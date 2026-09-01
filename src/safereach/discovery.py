"""Discover hosts you can already reach with your existing SSH keys.

The point is to remove the setup step entirely for the common case: if you can already
``ssh myserver``, the agent should be able to diagnose ``myserver`` without you writing
any configuration at all.

Two implementation choices worth knowing about:

* **Effective config comes from ``ssh -G``, not from parsing.** OpenSSH config has
  ``Include``, ``Match`` blocks, token expansion, per-host defaults and system-wide files
  underneath the user's. Reimplementing that resolution would be wrong in ways that only
  show up on somebody else's machine. ``ssh -G <alias>`` asks OpenSSH itself what it would
  do, which is correct by construction.

* **Only ``Host`` *names* are parsed here**, because ``ssh -G`` needs something to
  resolve and there is no "list all hosts" flag. That parse is deliberately simple, and
  anything it gets wrong shows up as a host that fails to probe rather than as a wrong
  connection.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "DiscoveredHost",
    "candidate_aliases",
    "resolve_alias",
    "probe_alias",
    "discover",
]

SSH_CONFIG = Path.home() / ".ssh" / "config"

_HOST_LINE = re.compile(r"^\s*Host\s+(.+?)\s*$", re.IGNORECASE)
_INCLUDE_LINE = re.compile(r"^\s*Include\s+(.+?)\s*$", re.IGNORECASE)

#: Patterns rather than names: `ssh -G` cannot resolve these into a single target.
_WILDCARD = re.compile(r"[*?!]")


@dataclass
class DiscoveredHost:
    alias: str
    hostname: str = ""
    user: str = ""
    port: int = 22
    identity_files: list[str] = field(default_factory=list)
    status: str = "unknown"  # ok | auth-failed | unknown-host-key | unreachable | error
    detail: str = ""

    @property
    def usable(self) -> bool:
        return self.status == "ok"


def _read_config_files(path: Path, seen: set[Path] | None = None) -> list[str]:
    """Read a config file and everything it Includes."""
    seen = seen if seen is not None else set()
    resolved = path.expanduser()
    if resolved in seen or not resolved.is_file():
        return []
    seen.add(resolved)

    lines: list[str] = []
    for line in resolved.read_text(encoding="utf-8", errors="replace").splitlines():
        include = _INCLUDE_LINE.match(line)
        if include:
            for pattern in include.group(1).split():
                target = Path(pattern).expanduser()
                if target.is_absolute():
                    bases = [Path(target.anchor)]
                    glob = str(target.relative_to(target.anchor))
                else:
                    # ssh_config(5): a relative Include in a user config resolves against
                    # ~/.ssh, not against the including file. The including file's own
                    # directory is tried as well so a config kept elsewhere still works;
                    # `seen` stops a file being read twice if both bases match.
                    bases = [Path.home() / ".ssh", resolved.parent]
                    glob = str(target)
                for base in bases:
                    for match in sorted(base.glob(glob)):
                        lines.extend(_read_config_files(match, seen))
            continue
        lines.append(line)
    return lines


def candidate_aliases(config_path: Path | None = None) -> list[str]:
    """Host aliases worth probing, in file order, de-duplicated.

    Wildcard patterns (``Host *``) are skipped: they configure defaults rather than name
    a machine, and ``ssh -G`` has nothing to resolve them to.
    """
    lines = _read_config_files(config_path or SSH_CONFIG)
    aliases: list[str] = []
    for line in lines:
        match = _HOST_LINE.match(line)
        if not match:
            continue
        for name in match.group(1).split():
            if _WILDCARD.search(name) or name in aliases:
                continue
            aliases.append(name)
    return aliases


def resolve_alias(alias: str) -> DiscoveredHost:
    """Ask OpenSSH what it would actually do for this alias."""
    host = DiscoveredHost(alias=alias)
    if not shutil.which("ssh"):
        host.status = "error"
        host.detail = "the ssh client is not installed"
        return host

    try:
        proc = subprocess.run(
            ["ssh", "-G", alias], capture_output=True, text=True, timeout=10, check=False
        )
    except subprocess.TimeoutExpired:
        host.status = "error"
        host.detail = "ssh -G timed out"
        return host

    if proc.returncode != 0:
        host.status = "error"
        host.detail = (proc.stderr or "ssh -G failed").strip().splitlines()[-1:][0]
        return host

    for line in proc.stdout.splitlines():
        key, _, value = line.partition(" ")
        key = key.lower()
        if key == "hostname":
            host.hostname = value
        elif key == "user":
            host.user = value
        elif key == "port":
            host.port = int(value) if value.isdigit() else 22
        elif key == "identityfile":
            host.identity_files.append(value)
    return host


def probe_alias(alias: str, timeout: int = 8) -> tuple[str, str]:
    """Try a real key-based connection. Returns ``(status, detail)``.

    ``BatchMode=yes`` is what makes this safe to run across a whole config: it disables
    every interactive prompt, so a host needing a password fails immediately instead of
    hanging the discovery loop waiting on a terminal that is not there.

    Host key checking is left at its configured setting. A host that would prompt to
    accept a new key is reported as such rather than silently trusted.
    """
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "LogLevel=ERROR",
        alias,
        "true",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5, check=False)
    except subprocess.TimeoutExpired:
        return "unreachable", f"no response within {timeout}s"

    if proc.returncode == 0:
        return "ok", "key-based authentication works"

    err = (proc.stderr or "").strip()
    low = err.lower()
    if "host key verification failed" in low or "no matching host key" in low:
        return "unknown-host-key", "host key is not in known_hosts — run ssh-keyscan first"
    if "permission denied" in low:
        return "auth-failed", "no usable key for this host (password auth is not supported)"
    if "could not resolve" in low or "name or service not known" in low:
        return "unreachable", "hostname does not resolve"
    if "connection refused" in low or "timed out" in low or "no route" in low:
        return "unreachable", err.splitlines()[-1] if err else "connection failed"
    return "error", (err.splitlines()[-1] if err else f"ssh exited {proc.returncode}")


def discover(
    config_path: Path | None = None,
    aliases: list[str] | None = None,
    probe: bool = True,
    timeout: int = 8,
) -> list[DiscoveredHost]:
    """Resolve and optionally probe every alias in the user's SSH config."""
    names = aliases if aliases is not None else candidate_aliases(config_path)
    found: list[DiscoveredHost] = []
    for alias in names:
        host = resolve_alias(alias)
        if host.status == "error":
            found.append(host)
            continue
        if probe:
            host.status, host.detail = probe_alias(alias, timeout=timeout)
        else:
            host.status = "unknown"
            host.detail = "not probed"
        found.append(host)
    return found
