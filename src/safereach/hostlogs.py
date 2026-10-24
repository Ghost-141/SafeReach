"""Runs ON THE HOST, over the operator's own SSH access: find log sources, apply log policy.

Sent as a script on stdin (``python3 -I - <mode> <base64 json>``), never installed, so it
is stdlib-only and written for the oldest Python 3 a shim host may have (3.7: no walrus,
no ``match``). Two modes:

``discover``
    Read-only. Reports where logs are, as facts — directory names, file names, sizes and
    timestamps, the systemd unit and command name of processes holding a log open, which
    units have an empty journal, which containers exist. It never opens a file for
    reading, never reads a process's command line or environment, and never runs ``pm2``
    (``pm2 jlist`` starts the PM2 daemon if it is not running). The client turns these
    facts into a checklist.

``apply``
    Writes ``log_sources`` and ``log_path_prefixes`` into the host's own policy file,
    keeping every other key, its mode and its owner. When the policy is the root-owned
    one (hardened enrolment), it also grants the diag group read access to each file
    source's directory with POSIX ACLs — default ACLs too, so files created by log
    rotation stay readable — and revokes grants for sources that were removed. Every
    grant is recorded in the policy so ``unenroll`` can take it back precisely.
"""

import base64
import contextlib
import fnmatch
import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import time

ROOT_POLICY = "/etc/safereach/config.json"
USER_POLICY = "~/.config/safereach-shim/config.json"

#: Exit code that tells the client to retry the same request under ``sudo -n``.
NEED_ROOT = 3

DEADLINE_S = 10.0
MAX_FDS_PER_PROCESS = 200
MAX_PROCESSES = 2000
MAX_NAMES_PER_DIR = 50
MAX_UNITS_PROBED = 20
APP_ROOTS = ("/opt/", "/srv/", "/home/", "/var/www/", "/app/", "/data/", "/root/")
_IGNORED_TREES = ("/proc/", "/sys/", "/dev/", "/run/", "/var/log/journal/", "/tmp/")
_LOG_SUFFIXES = (".log", ".out", ".err")


def _emit(obj):
    sys.stdout.write(json.dumps(obj, sort_keys=True))
    sys.stdout.write("\n")


def _run(argv, timeout=5):
    if shutil.which(argv[0]) is None:
        return None
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


# --------------------------------------------------------------------------------------
# discover
# --------------------------------------------------------------------------------------


def _looks_like_log(path):
    if not path.startswith("/") or path.endswith(" (deleted)"):
        return False
    if any(path.startswith(tree) for tree in _IGNORED_TREES):
        return False
    base = os.path.basename(path)
    parent = os.path.basename(os.path.dirname(path))
    return base.endswith(_LOG_SUFFIXES) or ".log." in base or parent in ("log", "logs")


def _unit_of(pid):
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            for line in fh:
                for part in reversed(line.strip().split("/")):
                    if part.endswith(".service"):
                        return part
    except OSError:
        pass
    return None


def _comm_of(pid):
    try:
        with open(f"/proc/{pid}/comm") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _user_of(pid):
    try:
        return pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except (OSError, KeyError):
        return None


def _scan_processes(deadline):
    """Open log files and app-rooted services, from /proc. fds and cwd only."""
    open_logs = []
    seen = set()
    app_units = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()][:MAX_PROCESSES]
    except OSError:
        return open_logs, []
    for pid in pids:
        if time.monotonic() > deadline:
            break
        unit = None
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            cwd = ""
        if cwd.startswith(APP_ROOTS):
            unit = _unit_of(pid)
            if unit and unit not in app_units:
                app_units[unit] = {"unit": unit, "comm": _comm_of(pid), "cwd": cwd}
        try:
            fds = os.listdir(f"/proc/{pid}/fd")[:MAX_FDS_PER_PROCESS]
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if target in seen or not _looks_like_log(target):
                continue
            seen.add(target)
            open_logs.append(
                {
                    "path": target,
                    "comm": _comm_of(pid),
                    "unit": unit or _unit_of(pid),
                    "user": _user_of(pid),
                }
            )
    return open_logs, list(app_units.values())


def _pm2_dirs():
    homes = ["/root"]
    with contextlib.suppress(OSError):
        homes += ["/home/" + h for h in sorted(os.listdir("/home"))]
    homes.append(os.path.expanduser("~"))
    out = []
    for home in homes:
        path = os.path.join(home, ".pm2", "logs") + "/"
        if path not in out and os.path.isdir(path):
            out.append(path)
    return out


def _dir_facts(path, deny):
    facts = {"exists": False}
    try:
        names = os.listdir(path)
    except OSError as exc:
        facts["exists"] = os.path.isdir(path)
        facts["error"] = exc.strerror
        return facts
    facts["exists"] = True
    files = []
    hazards = []
    total = 0
    for name in names:
        full = os.path.join(path, name)
        if any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(full, p) for p in deny):
            hazards.append(name)
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        total += st.st_size
        files.append((st.st_mtime, name))
    files.sort(reverse=True)
    facts.update(
        {
            "files": len(files),
            "bytes": total,
            "names": [n for _, n in files[:MAX_NAMES_PER_DIR]],
            "newest": files[0][1] if files else None,
            "newest_mtime": files[0][0] if files else None,
            "hazards": sorted(hazards)[:10],
            "readable": os.access(path, os.R_OK | os.X_OK)
            and (not files or os.access(os.path.join(path, files[0][1]), os.R_OK)),
        }
    )
    return facts


def _journal_empty(unit):
    out = _run(["journalctl", "-u", unit, "-n", "1", "-q", "--no-pager"], timeout=3)
    if out is None:
        return None
    return out.strip() == ""


def discover(params):
    # On a hardened host the agent reads as a different account than ours, and only
    # root can see every process's open files; ask to be re-run under sudo.
    if params.get("root_if_hardened") and os.path.exists(ROOT_POLICY) and os.geteuid() != 0:
        _emit({"ok": False, "need_root": True})
        return NEED_ROOT
    deadline = time.monotonic() + DEADLINE_S
    deny = params.get("deny") or []
    open_logs, app_units = _scan_processes(deadline)
    pm2 = _pm2_dirs()

    dirs = list(params.get("dirs") or [])
    for entry in open_logs:
        d = os.path.dirname(entry["path"]) + "/"
        if d not in dirs:
            dirs.append(d)
    for d in pm2:
        if d not in dirs:
            dirs.append(d)
    dir_facts = {}
    for d in dirs:
        if time.monotonic() > deadline:
            break
        dir_facts[d] = _dir_facts(d, deny)

    running = _run(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"]
    )
    running_units = sorted(line.split()[0] for line in (running or "").splitlines() if line.strip())
    probe = [u["unit"] for u in app_units]
    probe += [u for u in params.get("units") or [] if u in running_units and u not in probe]
    journal_empty = {}
    for unit in probe[:MAX_UNITS_PROBED]:
        if time.monotonic() > deadline:
            break
        journal_empty[unit] = _journal_empty(unit)

    names = _run(["docker", "ps", "--format", "{{.Names}}"])
    containers = sorted(n.strip() for n in (names or "").splitlines() if n.strip())

    _emit(
        {
            "user": pwd.getpwuid(os.geteuid()).pw_name,
            "root": os.geteuid() == 0,
            "now": time.time(),
            "dirs": dir_facts,
            "open_logs": open_logs,
            "pm2_dirs": pm2,
            "app_units": app_units,
            "running_units": running_units,
            "journal_empty": journal_empty,
            "containers": containers,
        }
    )
    return 0


# --------------------------------------------------------------------------------------
# apply
# --------------------------------------------------------------------------------------


def _setfacl(args, paths):
    """Run setfacl over ``paths`` in batches; return the number of failures."""
    failures = 0
    for i in range(0, len(paths), 200):
        proc = subprocess.run(
            ["setfacl", *args, *paths[i : i + 200]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        failures += proc.returncode != 0
    return failures


def _walk(top, limit=5000):
    dirs, files = [top], []
    for root, subdirs, names in os.walk(top):
        if root.count("/") - top.count("/") >= 4:
            subdirs[:] = []
        dirs += [os.path.join(root, d) for d in subdirs]
        files += [os.path.join(root, n) for n in names]
        if len(dirs) + len(files) > limit:
            break
    return dirs, [f for f in files if not os.path.islink(f)]


def _parents(path):
    out = []
    parent = os.path.dirname(path.rstrip("/"))
    while parent and parent != "/":
        out.append(parent + "/")
        parent = os.path.dirname(parent)
    return out


def _grant(group, directory, deny):
    """Read for the diag group on a log directory, minus anything on the protected list.

    The shim already refuses a `.env` that sits beside the logs; skipping it here means
    the account cannot read it at the OS level either. A protected file created LATER
    would inherit the default ACL — the shim's refusal is what covers that case.
    """
    dirs, files = _walk(directory)
    files = [
        f
        for f in files
        if not any(fnmatch.fnmatch(f, p) or fnmatch.fnmatch(os.path.basename(f), p) for p in deny)
    ]
    bad = _setfacl(["-m", f"g:{group}:rx,d:g:{group}:rx"], dirs)
    bad += _setfacl(["-m", f"g:{group}:r"], files)
    return bad


def _revoke(group, directory):
    if not os.path.isdir(directory):
        return 0
    dirs, files = _walk(directory)
    bad = _setfacl(["-x", f"g:{group},d:g:{group}"], dirs)
    bad += _setfacl(["-x", f"g:{group}"], files)
    return bad


def apply(params):
    path = ROOT_POLICY if os.path.exists(ROOT_POLICY) else os.path.expanduser(USER_POLICY)
    if path == ROOT_POLICY and os.geteuid() != 0:
        _emit({"ok": False, "need_root": True})
        return NEED_ROOT
    try:
        with open(path) as fh:
            cfg = json.load(fh)
        st = os.stat(path)
    except (OSError, ValueError) as exc:
        _emit({"ok": False, "error": f"cannot read {path}: {exc}"})
        return 1

    sources = params.get("log_sources") or {}
    cfg["log_sources"] = sources
    cfg["log_path_prefixes"] = list(params.get("log_path_prefixes") or [])
    wanted = sorted(
        {s["dir"] for s in sources.values() if isinstance(s, dict) and s.get("kind") == "file"}
    )

    acl = "not-applicable"
    granted, revoked = [], []
    if path == ROOT_POLICY:
        # The policy is installed root:<diag>, so its group IS the diag account's group.
        group = params.get("group")
        try:
            group = group or grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = None
        previous = list(cfg.get("granted_acls") or [])
        traverse_before = list(cfg.get("granted_traverse") or [])
        if not group or group == "root":
            acl = "no-diag-group"
        elif shutil.which("setfacl") is None:
            acl = "setfacl-missing"
        else:
            failures = 0
            for d in previous:
                if d not in wanted:
                    failures += _revoke(group, d)
                    revoked.append(d)
            for d in wanted:
                if os.path.isdir(d):
                    failures += _grant(group, d, params.get("deny") or [])
                    granted.append(d)
            # Parents need only search (x) to reach the leaf, and only where "other"
            # lacks it already. Recorded so they can be taken back when unneeded.
            needed = set()
            for d in granted:
                for parent in _parents(d):
                    try:
                        if not os.stat(parent).st_mode & stat.S_IXOTH:
                            needed.add(parent)
                    except OSError:
                        continue
            failures += _setfacl(["-m", f"g:{group}:x"], sorted(needed - set(traverse_before)))
            failures += _setfacl(["-x", f"g:{group}"], sorted(set(traverse_before) - needed))
            cfg["granted_traverse"] = sorted(needed)
            cfg["granted_acls"] = granted
            acl = "ok" if not failures else "partial"

    tmp = path + ".new"
    with open(tmp, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    if os.geteuid() == 0:
        os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)
    _emit({"ok": True, "policy": path, "acl": acl, "granted": granted, "revoked": revoked})
    return 0


def main(argv):
    if len(argv) != 3 or argv[1] not in ("discover", "apply"):
        sys.stderr.write("usage: hostlogs.py discover|apply BASE64-JSON\n")
        return 2
    params = json.loads(base64.b64decode(argv[2]).decode("utf-8"))
    if argv[1] == "discover":
        return discover(params)
    return apply(params)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
