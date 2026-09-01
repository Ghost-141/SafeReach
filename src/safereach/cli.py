"""Command-line interface.

``safereach`` with no subcommand runs the MCP server over stdio. Everything else is
setup and diagnostics for the tool itself.

**Stdout discipline:** in server mode stdout is the JSON-RPC channel, so nothing here may
print to it before or during ``run()``. All human output in this module goes through
:func:`say`, which writes to stderr. A single stray print corrupts the protocol and the
agent sees an opaque parse failure — it is the most common way a working MCP server looks
broken.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .config import (
    DEFAULT_CONFIG_PATH,
    HostConfig,
    Settings,
    load_command_spec,
    load_settings,
    resolve_data_file,
)
from .install import adapters as ad
from .ssh import SSHError, SSHPool
from .validator import Rejected, render, validate
from .versioning import fingerprint

OK = "ok"
WARN = "!!"
BAD = "XX"


def say(*parts: Any) -> None:
    """Human-facing output. Always stderr — stdout belongs to the protocol."""
    print(*parts, file=sys.stderr)


# --------------------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    dest = Path(args.path).expanduser() if args.path else DEFAULT_CONFIG_PATH
    if dest.exists() and not args.force:
        say(f"{WARN} {dest} already exists (use --force to overwrite)")
        return 1

    template = resolve_data_file("hosts.example.yaml").read_text(encoding="utf-8")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(template, encoding="utf-8")
    # Contains hostnames, usernames and key paths.
    dest.chmod(0o600)
    say(f"{OK} wrote {dest} (mode 0600)")
    say("   Edit it, then run: safereach doctor")
    return 0


# --------------------------------------------------------------------------------------
# install / uninstall
# --------------------------------------------------------------------------------------


def cmd_install(args: argparse.Namespace) -> int:
    detected = ad.detect_all()

    if args.list:
        say("Detected agents:")
        for adapter in ad.ADAPTERS.values():
            mark = OK if adapter in detected else "  "
            path = adapter.config_path()
            where = str(path) if path else f"via `{adapter.name}` CLI"
            say(f"  [{mark}] {adapter.label:<20} {where}")
        return 0

    if args.agents:
        unknown = [a for a in args.agents if a not in ad.ADAPTERS]
        if unknown:
            say(f"{BAD} unknown agent(s): {', '.join(unknown)}")
            say(f"   available: {', '.join(sorted(ad.ADAPTERS))}")
            return 2
        targets = [ad.ADAPTERS[a] for a in args.agents]
    elif args.all:
        targets = detected
    else:
        targets = detected
        if not targets:
            say(f"{WARN} no agents detected. Name one explicitly:")
            say(f"   safereach install {' | '.join(sorted(ad.ADAPTERS))}")
            return 1
        say("Registering with detected agents: " + ", ".join(a.label for a in targets))

    spec = ad.resolve_command(mode=args.launcher, version=None if args.unpinned else __version__)
    if args.config:
        spec = ad.ServerSpec(
            command=spec.command,
            args=[*spec.args, "--config", str(Path(args.config).expanduser())],
        )

    say(f"   server command: {spec.command} {' '.join(spec.args)}".rstrip())

    failures = 0
    for adapter in targets:
        try:
            result = ad.apply(adapter, spec, remove=args.remove)
        except Exception as exc:  # noqa: BLE001 - report and continue to other agents
            say(f"{BAD} {adapter.label}: {exc}")
            failures += 1
            continue
        mark = BAD if result.startswith(("failed", "timed out")) else OK
        if mark == BAD:
            failures += 1
        say(f"{mark} {adapter.label}: {result}")

    if not args.remove and failures == 0:
        say("\nRestart your agent to pick up the new server.")
    return 1 if failures else 0


# --------------------------------------------------------------------------------------
# discover
# --------------------------------------------------------------------------------------

DISCOVER_HEADER = """\
# Written by `safereach discover`.
#
# Each host resolves through your existing ~/.ssh/config — hostname, user, port and
# IdentityFile all come from OpenSSH itself, so anything you can already `ssh` to works
# here with no further setup.
#
# SECURITY MODE: client-only.
#   These hosts reuse your own SSH credentials, which means your own account and usually
#   your own privileges. There is no safereach-shim and no unprivileged diag user, so the
#   command allowlist running on THIS machine is the only thing standing between the
#   agent and that account. That is a reasonable trade for a lab box or a VPS you own.
#   It is weaker than the hardened path.
#
#   To harden a host — dedicated unprivileged account, plus a remote validator behind an
#   SSH forced command that the agent cannot reach or bypass:
#       safereach provision <alias> --admin-user <you>
#   then delete that host's `require_shim: false` line below.
"""


def cmd_discover(args: argparse.Namespace) -> int:
    from . import discovery

    aliases = args.hosts or None
    candidates = aliases if aliases is not None else discovery.candidate_aliases()

    if not candidates:
        say(f"{WARN} no Host entries found in ~/.ssh/config")
        say("   Add the servers you use to ~/.ssh/config, or name them explicitly:")
        say("     safereach discover myserver otherserver")
        return 1

    say(f"Probing {len(candidates)} host(s) from ~/.ssh/config …")
    if not args.no_probe:
        say("(using BatchMode, so nothing will prompt for a password)\n")

    found = discovery.discover(aliases=candidates, probe=not args.no_probe, timeout=args.timeout)

    usable = []
    for host in found:
        mark = {
            "ok": OK,
            "unknown": "  ",
            "auth-failed": WARN,
            "unknown-host-key": WARN,
            "unreachable": WARN,
            "error": BAD,
        }.get(host.status, BAD)
        where = f"{host.user}@{host.hostname}" if host.hostname else "?"
        say(f"{mark} {host.alias:<24} {where:<34} {host.detail}")
        if host.usable or args.no_probe:
            usable.append(host)

    if not usable:
        say(f"\n{WARN} nothing usable found.")
        say("   Hosts needing a password are skipped — this tool only uses key auth.")
        say("   For an unknown host key, run: ssh-keyscan -H <host> >> ~/.ssh/known_hosts")
        return 1

    default_allow = DEFAULT_ALLOW

    lines = [
        DISCOVER_HEADER,
        "defaults:",
        "  audit_log: ~/.local/state/safereach/audit.jsonl",
        "",
        "hosts:",
    ]
    for host in usable:
        lines += [
            f"  {host.alias}:",
            f"    ssh_config_host: {host.alias}",
            f'    description: "{host.user}@{host.hostname}"',
            "    require_shim: false        # client-only mode; see header",
            f"    allow: [{', '.join(default_allow)}]",
            "    curl_targets: [localhost, 127.0.0.1]",
            "",
        ]
    body = "\n".join(lines)

    dest = Path(args.out).expanduser() if args.out else DEFAULT_CONFIG_PATH
    if args.dry_run:
        say(f"\n--- would write {dest} ---")
        say(body)
        return 0
    if dest.exists() and not args.force:
        say(f"\n{WARN} {dest} exists. Re-run with --force to overwrite, or --dry-run to preview.")
        return 1

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body, encoding="utf-8")
    dest.chmod(0o600)

    say(f"\n{OK} wrote {dest} with {len(usable)} host(s)")
    say(f"{WARN} security mode: client-only — see the header of that file for what that means")
    say("\nNext:")
    say("   safereach doctor")
    say("   safereach install")
    return 0


# --------------------------------------------------------------------------------------
# enroll — the default path
# --------------------------------------------------------------------------------------

#: Privileged reads the shim may perform, selected by NAME.
#:
#: The agent sends "dmesg-recent" and nothing else — there is no argument surface here at
#: all. This is why `sudo` is not in commands.yaml: if the agent could pass arguments to
#: sudo, the allowlist would be decorative. Each entry is a fully-specified invocation.
#: Read-only commands permitted inside a container via `docker exec`. Kept narrow and
#: separate from the host allowlist: `deny_paths` still applies, so `cat /app/.env` is
#: refused in the container exactly as it is on the host.
EXEC_INNER_ALLOW = ["cat", "tail", "head", "ls", "stat", "ps", "df", "grep"]

ELEVATED_RECIPES: dict[str, list[str]] = {
    "dmesg-recent": [
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/dmesg",
        "--level=err,crit,alert,emerg",
        "--ctime",
    ],
    "dmesg-all": ["/usr/bin/sudo", "-n", "/usr/bin/dmesg", "--ctime"],
}


#: The default set written both into hosts.yaml and into each host's own policy file.
#: These must not drift: an empty `allow` on the remote is read as "allow nothing", so a
#: host enrolled before any hosts.yaml existed refused every command.
DEFAULT_ALLOW = [
    "journalctl",
    "systemctl",
    "dmesg",
    "df",
    "du",
    "free",
    "uptime",
    "ps",
    "ss",
    "ip",
    "tail",
    "head",
    "grep",
    "stat",
    "ls",
    "docker",
    "curl",
]


KEY_DIR = DEFAULT_CONFIG_PATH.parent / "keys"
KEY_PATH = KEY_DIR / "id_ed25519_safereach"

#: Marker comment on the authorized_keys entry. Used to find and replace our own line on
#: re-enrolment without touching anything else in the file.
KEY_COMMENT = "safereach-enrolled"

#: Paths the agent may never name, in any command, on any host. Enforced against every
#: argument token rather than only positionals — a path can arrive as a flag value too.
DEFAULT_DENY_PATHS = [
    "*.env",
    "*.env.*",
    ".env*",
    "*.envrc",
    "*/secrets/*",
    "*/.ssh/*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*credentials*",
    "*.kubeconfig",
    "*/.aws/*",
    "*/.docker/config.json",
]

#: Where enrolment looks for .env files to learn variable names from.
ENV_SCAN_ROOTS = ["/opt", "/srv", "/var/www", "/etc"]

ENV_KEY_SCRIPT = r"""set -eu
# Emit only the variable NAMES, never a value. `cut -d= -f1` truncates at the first '='
# so no part of any secret can reach stdout even if a name is malformed.
for root in {roots}; do
    [ -d "$root" ] || continue
    find "$root" -maxdepth 4 -type f \( -name '.env' -o -name '.env.*' -o -name '*.env' \) 2>/dev/null
done | head -50 | while read -r f; do
    grep -hoE '^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=' "$f" 2>/dev/null \
      | sed -E 's/^[[:space:]]*(export[[:space:]]+)?//; s/=$//'
done | sort -u | head -400
"""


ENV_VALUE_SCRIPT = r"""set -eu
# Emits HMAC digests of secret VALUES — never a value itself. The hashing happens here,
# as root on the host where the values already live, so the diag account ends up holding
# hashes of secrets it cannot read.
KEY="$1"
for root in {roots}; do
    [ -d "$root" ] || continue
    find "$root" -maxdepth 4 -type f \( -name '.env' -o -name '.env.*' -o -name '*.env' \) 2>/dev/null
done | head -50 | while read -r f; do
    sed -nE 's/^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=(.*)$/\2/p' "$f" 2>/dev/null
done | sed -E 's/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/' | sort -u | while IFS= read -r v; do
    [ -n "$v" ] || continue
    printf '%s' "$v" | openssl dgst -sha256 -hmac "$KEY" -r 2>/dev/null | cut -c1-32
done | sort -u | head -500
"""


def _discover_env_digests(alias: str, key: str) -> list[str]:
    """HMAC digests of the host's secret values. Values never leave the host.

    Requires `openssl`, which is present on any host running TLS. A host without it
    simply gets Layers 1 and 2 — the feature degrades rather than failing enrolment.
    """
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", alias, "sudo -n bash -s", "--", key],
        input=ENV_VALUE_SCRIPT.format(roots=" ".join(ENV_SCAN_ROOTS)),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return sorted({d.strip() for d in proc.stdout.split() if len(d.strip()) == 32})


def _discover_env_keys(alias: str) -> list[str]:
    """Learn which variable names this host treats as configuration.

    Names, never values. A name is not a secret, so it is safe to keep in the host's
    policy file and in the audit trail — but knowing the names is what lets the shim mask
    `SALT=`, `NEXTAUTH_SECRET=` or `SMTP_USER=` wherever they surface, including in logs
    and `systemctl show` output that the generic "looks like a password" patterns miss.
    """
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", alias, "sudo -n bash -s"],
        input=ENV_KEY_SCRIPT.format(roots=" ".join(ENV_SCAN_ROOTS)),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    keys = [k.strip() for k in proc.stdout.splitlines() if k.strip()]
    # Never mask these: they are not secrets and masking them makes output unreadable.
    boring = {"PATH", "HOME", "TZ", "LANG", "LC_ALL", "TERM", "SHELL", "PWD", "USER"}
    return sorted({k for k in keys if k not in boring})


HARDENED_SCRIPT = r"""set -eu
DIAG_USER="{diag_user}"

# --- account -----------------------------------------------------------------------
# A system account with no login shell of its own worth having, no sudo, and crucially
# NOT in the docker group — that group is equivalent to root on the host, which is the
# whole reason Docker is reached through a read-only proxy instead.
if ! id -u "$DIAG_USER" >/dev/null 2>&1; then
    useradd -r -m -s /bin/bash "$DIAG_USER"
    echo "CREATED_USER=1"
fi

# systemd-journal is the single highest-value grant: without it journalctl returns only
# this account's own entries, which is nothing. adm covers /var/log/syslog and friends.
for grp in systemd-journal adm; do
    getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$DIAG_USER"
done
# Belt and braces in case the account predates this script.
for grp in sudo docker wheel admin adm_root; do
    id -nG "$DIAG_USER" | tr ' ' '\n' | grep -qx "$grp" && gpasswd -d "$DIAG_USER" "$grp" >/dev/null 2>&1 || true
done
# adm is wanted; the loop above would have stripped it, so re-add.
getent group adm >/dev/null 2>&1 && usermod -aG adm "$DIAG_USER"

# --- shim, owned by root ------------------------------------------------------------
# In hardened mode the binary and its policy live outside the diag account entirely, so
# the account cannot rewrite what it is allowed to run even if it were compromised.
install -o root -g root -m 0755 /tmp/.safereach-shim.upload /usr/local/bin/safereach-shim
rm -f /tmp/.safereach-shim.upload
mkdir -p /etc/safereach
install -o root -g root -m 0644 /tmp/.safereach-shim.conf.upload /etc/safereach/config.json
rm -f /tmp/.safereach-shim.conf.upload

# --- forced-command key -------------------------------------------------------------
HOME_DIR=$(getent passwd "$DIAG_USER" | cut -d: -f6)
mkdir -p "$HOME_DIR/.ssh"
touch "$HOME_DIR/.ssh/authorized_keys"
grep -v '{marker}' "$HOME_DIR/.ssh/authorized_keys" > "$HOME_DIR/.ssh/.ak.new" 2>/dev/null || true
cat >> "$HOME_DIR/.ssh/.ak.new" <<'DIAGKEY'
{authkey}
DIAGKEY
mv "$HOME_DIR/.ssh/.ak.new" "$HOME_DIR/.ssh/authorized_keys"
chown -R "$DIAG_USER":"$DIAG_USER" "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"; chmod 600 "$HOME_DIR/.ssh/authorized_keys"

# --- sudoers: only the enabled recipes, exact match, no wildcards --------------------
rm -f /etc/sudoers.d/safereach
{sudoers_block}

# Audit log. The account whose commands are recorded must not be able to erase the
# record, so the file is made append-only: with +a even its owner can only add to it,
# and clearing the flag needs CAP_LINUX_IMMUTABLE, which diag does not have.
# Clear +a first: a previous enrolment set it, and append-only blocks chown/chmod too,
# which made re-enrolment fail on its own hardening.
chattr -a /var/log/safereach.jsonl 2>/dev/null || true
touch /var/log/safereach.jsonl
chown "$DIAG_USER":root /var/log/safereach.jsonl
chmod 0640 /var/log/safereach.jsonl
if chattr +a /var/log/safereach.jsonl 2>/dev/null; then
    echo "AUDIT=append-only"
else
    echo "AUDIT=writable"   # unsupported filesystem; the log is tamperable
fi

echo "HOME=$HOME_DIR"
echo "GROUPS=$(id -nG "$DIAG_USER")"
echo "SHIM=$(/usr/local/bin/safereach-shim --version)"
"""

DOCKER_PROXY_SCRIPT = r"""set -eu
# Read-only Docker API. The diag account is deliberately NOT in the docker group, so
# this proxy is its only route to container data — and the proxy refuses every mutating
# call at the API level, independent of our parser.
if ! command -v docker >/dev/null 2>&1; then echo "NO_DOCKER=1"; exit 0; fi
docker rm -f safereach-docker-proxy >/dev/null 2>&1 || true
docker run -d --name safereach-docker-proxy --restart unless-stopped \
    -p 127.0.0.1:{proxy_port}:2375 \
    -e CONTAINERS=1 -e IMAGES=1 -e NETWORKS=1 -e VOLUMES=1 -e INFO=1 -e VERSION=1 \
    -e POST={post} -e EXEC={exec_flag} -e BUILD=0 -e COMMIT=0 -e CONFIGS=0 -e SECRETS=0 \
    -e SERVICES=0 -e SWARM=0 -e SYSTEM=0 -e TASKS=0 -e NODES=0 -e PLUGINS=0 \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    tecnativa/docker-socket-proxy >/dev/null
sleep 2
echo "PROXY=$(docker inspect -f '{{{{.State.Status}}}}' safereach-docker-proxy)"
"""


ENROLL_SCRIPT = r"""set -eu
mkdir -p "$HOME/.local/bin" "$HOME/.config/safereach-shim" "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

command -v python3 >/dev/null 2>&1 || {{ echo "python3 not found on this host" >&2; exit 1; }}

install -m 0755 /tmp/.safereach-shim.upload "$HOME/.local/bin/safereach-shim"
rm -f /tmp/.safereach-shim.upload
install -m 0600 /tmp/.safereach-shim.conf.upload "$HOME/.config/safereach-shim/config.json"
rm -f /tmp/.safereach-shim.conf.upload

touch "$HOME/.ssh/authorized_keys"
# Replace only our own previous entry. Every other key in this file is left byte for
# byte alone — including the one being used to run this script.
grep -v '{marker}' "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/.ak.new" || true
cat >> "$HOME/.ssh/.ak.new" <<'DIAGKEY'
{authkey}
DIAGKEY
mv "$HOME/.ssh/.ak.new" "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"

echo "HOME=$HOME"
echo "SHIM=$("$HOME/.local/bin/safereach-shim" --version)"
"""


def _yaml_key(name: str) -> str:
    """An alias the agent can address. `user@host` is not usable as one."""
    return name.split("@")[-1]


def _ensure_local_key() -> Path:
    """A dedicated keypair for the agent, generated once and never reused elsewhere."""
    if KEY_PATH.is_file():
        return KEY_PATH
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.chmod(0o700)
    proc = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", KEY_COMMENT, "-f", str(KEY_PATH)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"ssh-keygen failed: {proc.stderr.strip()}")
    KEY_PATH.chmod(0o600)
    say(f"{OK} generated {KEY_PATH}")
    return KEY_PATH


def _enroll_one(
    alias: str,
    shim: Path,
    expected: str,
    settings: Settings | None,
    elevated: list[str] | None = None,
) -> dict | None:
    """Install the shim and a restricted key on one host, over existing SSH access."""
    elevated = elevated or []
    pub = Path(str(KEY_PATH) + ".pub").read_text(encoding="utf-8").strip()

    # `command=` is honoured from the user's own authorized_keys — no root anywhere in
    # this flow. That is the whole point: the forced command, which is the actual
    # security boundary, costs nothing to install.
    authkey = (
        'command="{shim}",no-pty,no-port-forwarding,no-agent-forwarding,'
        "no-X11-forwarding,no-user-rc {pub}"
    )

    # $HOME is not expanded inside command=, so the absolute path has to be resolved on
    # the host before the entry is written. One extra round trip, no guessing.
    probe = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", alias, "echo $HOME"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        say(f"{BAD} {alias}: cannot connect ({(probe.stderr or '').strip().splitlines()[-1:]})")
        return None
    remote_home = probe.stdout.strip()
    if not remote_home.startswith("/"):
        say(f"{BAD} {alias}: could not determine remote HOME")
        return None

    entry = authkey.format(shim=f"{remote_home}/.local/bin/safereach-shim", pub=pub)

    host_cfg = settings.hosts.get(alias) if settings else None
    conf = {
        "allow": sorted(host_cfg.allow) if host_cfg and host_cfg.allow else list(DEFAULT_ALLOW),
        "curl_targets": sorted(host_cfg.curl_targets) if host_cfg else ["localhost", "127.0.0.1"],
        "deny_paths": list(DEFAULT_DENY_PATHS),
        "secret_env_keys": _discover_env_keys(alias),
        "docker_host": host_cfg.docker_host if host_cfg else None,
        "command_timeout": 30,
        "max_output_bytes": 65536,
        "elevated": {name: ELEVATED_RECIPES[name] for name in elevated},
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write(json.dumps(conf, indent=2))
        conf_path = Path(fh.name)

    try:
        for src, dest in (
            (shim, "/tmp/.safereach-shim.upload"),
            (conf_path, "/tmp/.safereach-shim.conf.upload"),
        ):
            up = subprocess.run(
                ["scp", "-q", "-o", "BatchMode=yes", str(src), f"{alias}:{dest}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if up.returncode != 0:
                say(f"{BAD} {alias}: upload failed: {up.stderr.strip()}")
                return None

        script = ENROLL_SCRIPT.format(marker=KEY_COMMENT, authkey=entry)
        run = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", alias, "bash -s"],
            input=script,
            capture_output=True,
            text=True,
            check=False,
        )
        if run.returncode != 0:
            say(f"{BAD} {alias}: setup failed: {(run.stderr or run.stdout).strip()}")
            return None
    finally:
        conf_path.unlink(missing_ok=True)

    installed = ""
    for line in run.stdout.splitlines():
        if line.startswith("SHIM="):
            installed = line.split("=", 1)[1].strip()
    if installed != expected:
        say(f"{BAD} {alias}: installed shim reports {installed!r}, expected {expected!r}")
        return None

    from . import discovery

    resolved = discovery.resolve_alias(alias)

    # Verification must use ONLY the enrolled key.
    #
    # `-i key -o IdentitiesOnly=yes` is not enough: IdentitiesOnly restricts ssh to the
    # identities named on the command line *and in the config*, so a `Host` block with
    # its own IdentityFile still gets offered — and if that key is already authorised
    # (it is, that is how we reached this host) ssh authenticates with it instead and
    # hands back an unrestricted shell. The check then reports a failure against a key
    # it was never actually testing.
    #
    # `-F /dev/null` drops the config entirely, so ours is the only identity on offer.
    def restricted_ssh(command: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "ssh",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                f"UserKnownHostsFile={Path('~/.ssh/known_hosts').expanduser()}",
                "-o",
                "StrictHostKeyChecking=yes",
                "-i",
                str(KEY_PATH),
                "-p",
                str(resolved.port),
                f"{resolved.user}@{resolved.hostname}",
                command,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    verify = restricted_ssh("@ping")
    if verify.returncode != 0:
        say(f"{BAD} {alias}: enrolled key does not work: {(verify.stderr or '').strip()}")
        return None

    # The check that actually matters: if sshd is not enforcing `command=`, this
    # succeeds, and the host must not be recorded as enrolled.
    escape = restricted_ssh("rm -rf /tmp/.safereach-escape-probe")
    if escape.returncode == 0:
        say(f"{BAD} {alias}: SECURITY — the forced command is not being enforced. Not enrolling.")
        return None

    say(f"{OK} {alias}: shim {installed}, restricted key verified, escape refused")
    return {
        "alias": alias,
        "hostname": resolved.hostname,
        "user": resolved.user,
        "port": resolved.port,
        "description": f"{resolved.user}@{resolved.hostname}" if resolved.hostname else alias,
    }


def _sudoers_block(elevated: list[str]) -> str:
    """Exactly the enabled recipes, spelled out in full.

    Sudoers wildcard matching is easy to get subtly wrong, so every entry is a literal
    command line with no `*`. An account with `NOPASSWD: ALL` gives a shim bug the run of
    the machine; this gives it two specific reads.
    """
    if not elevated:
        return 'echo "SUDOERS=none"'
    lines = []
    for name in elevated:
        argv = ELEVATED_RECIPES[name]
        # drop the leading sudo -n; sudoers describes what may be run *via* sudo
        cmd = " ".join(a.replace(",", r"\,") for a in argv[2:])
        lines.append(f"{{DIAG}} ALL=(root) NOPASSWD: {cmd}")
    body = "\n".join(lines)
    return (
        f'printf \'%s\\n\' "{body}" | sed "s/{{DIAG}}/$DIAG_USER/" '
        "> /etc/sudoers.d/safereach\n"
        "chmod 0440 /etc/sudoers.d/safereach\n"
        "visudo -cf /etc/sudoers.d/safereach >/dev/null || "
        "{ rm -f /etc/sudoers.d/safereach; echo 'SUDOERS=invalid'; exit 1; }\n"
        'echo "SUDOERS=ok"'
    )


def _enroll_hardened(
    alias: str,
    shim: Path,
    expected: str,
    diag_user: str,
    elevated: list[str],
    proxy_port: int,
    settings: Settings | None,
    allow_exec: bool = False,
    exec_containers: list[str] | None = None,
) -> dict | None:
    """Create a dedicated unprivileged account and enrol against that, not your own.

    This is the mode where the account itself is a control rather than a backstop: no
    sudo beyond the named recipes, no docker group, and a shim the account cannot
    rewrite because it and its policy are root-owned.
    """
    from . import discovery

    resolved = discovery.resolve_alias(alias)
    pub = Path(str(KEY_PATH) + ".pub").read_text(encoding="utf-8").strip()

    say(f"   {alias}: creating unprivileged user {diag_user!r} (needs sudo on the host)")

    proxy_ok = False
    if allow_exec:
        say(
            f"{WARN} {alias}: --allow-exec requires POST on the docker proxy, which also "
            "permits container create/start at the API level.\n"
            "        The command allowlist remains the control; the proxy no longer is."
        )
    proxy = subprocess.run(
        # No -n here: the script itself is delivered on stdin.
        ["ssh", "-o", "BatchMode=yes", alias, "sudo -n bash -s"],
        input=DOCKER_PROXY_SCRIPT.format(
            proxy_port=proxy_port,
            post=1 if allow_exec else 0,
            exec_flag=1 if allow_exec else 0,
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    if "PROXY=running" in proxy.stdout:
        proxy_ok = True
        say(f"   {alias}: read-only docker proxy on 127.0.0.1:{proxy_port}")
    elif "NO_DOCKER=1" in proxy.stdout:
        say(f"   {alias}: no docker installed, skipping proxy")
    else:
        say(f"{WARN} {alias}: docker proxy not started ({(proxy.stderr or '').strip()[:80]})")

    env_keys = _discover_env_keys(alias)
    if env_keys:
        say(f"   {alias}: learned {len(env_keys)} config variable names to mask (names only)")

    # A per-host HMAC key. Digests from one host are meaningless on another, and the key
    # is generated fresh rather than derived from anything guessable.
    digest_key = secrets.token_hex(32)
    digests = _discover_env_digests(alias, digest_key)
    if digests:
        say(f"   {alias}: {len(digests)} secret value digests (values never left the host)")

    host_cfg = settings.hosts.get(alias) if settings else None
    conf = {
        "allow": sorted(host_cfg.allow) if host_cfg and host_cfg.allow else list(DEFAULT_ALLOW),
        "curl_targets": sorted(host_cfg.curl_targets) if host_cfg else ["localhost", "127.0.0.1"],
        "deny_paths": list(DEFAULT_DENY_PATHS),
        "secret_env_keys": env_keys,
        "digest_key": digest_key,
        "secret_digests": digests,
        "allow_exec": bool(allow_exec),
        "exec_containers": list(exec_containers or []),
        "exec_allow": sorted(EXEC_INNER_ALLOW),
        "docker_host": f"tcp://127.0.0.1:{proxy_port}" if proxy_ok else None,
        "env_allowlist": sorted(host_cfg.env_allowlist) if host_cfg else [],
        "command_timeout": 30,
        "max_output_bytes": 65536,
        "elevated": {name: ELEVATED_RECIPES[name] for name in elevated},
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write(json.dumps(conf, indent=2))
        conf_path = Path(fh.name)
    try:
        for src, dest in (
            (shim, "/tmp/.safereach-shim.upload"),
            (conf_path, "/tmp/.safereach-shim.conf.upload"),
        ):
            up = subprocess.run(
                ["scp", "-q", "-o", "BatchMode=yes", str(src), f"{alias}:{dest}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if up.returncode != 0:
                say(f"{BAD} {alias}: upload failed: {up.stderr.strip()}")
                return None

        authkey = (
            'command="/usr/local/bin/safereach-shim",no-pty,no-port-forwarding,'
            f"no-agent-forwarding,no-X11-forwarding,no-user-rc {pub}"
        )
        script = HARDENED_SCRIPT.format(
            diag_user=diag_user,
            marker=KEY_COMMENT,
            authkey=authkey,
            sudoers_block=_sudoers_block(elevated),
        )
        run = subprocess.run(
            # No -n here: the script itself is delivered on stdin.
            ["ssh", "-o", "BatchMode=yes", alias, "sudo -n bash -s"],
            input=script,
            capture_output=True,
            text=True,
            check=False,
        )
        if run.returncode != 0:
            say(f"{BAD} {alias}: hardened setup failed: {(run.stderr or run.stdout).strip()[:300]}")
            return None
    finally:
        conf_path.unlink(missing_ok=True)

    info = dict(line.split("=", 1) for line in run.stdout.splitlines() if "=" in line)
    if info.get("SHIM") != expected:
        say(f"{BAD} {alias}: installed shim {info.get('SHIM')!r} != expected {expected!r}")
        return None

    def restricted(cmd: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "ssh",
                "-n",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                f"UserKnownHostsFile={Path('~/.ssh/known_hosts').expanduser()}",
                "-o",
                "StrictHostKeyChecking=yes",
                "-i",
                str(KEY_PATH),
                "-p",
                str(resolved.port),
                f"{diag_user}@{resolved.hostname}",
                cmd,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    if restricted("@ping").returncode != 0:
        say(f"{BAD} {alias}: enrolled key does not work as {diag_user}")
        return None
    if restricted("rm -rf /tmp/.safereach-escape-probe").returncode == 0:
        say(f"{BAD} {alias}: SECURITY — forced command not enforced. Not enrolling.")
        return None

    say(
        f"{OK} {alias}: user {diag_user}, groups [{info.get('GROUPS', '?')}], "
        f"sudoers {info.get('SUDOERS', '?')}, shim {info.get('SHIM')}"
    )
    return {
        "alias": alias,
        "hostname": resolved.hostname,
        "user": diag_user,
        "port": resolved.port,
        "description": f"{diag_user}@{resolved.hostname} (hardened)",
        "docker_host": conf["docker_host"],
        "hardened": True,
    }


def cmd_enroll(args: argparse.Namespace) -> int:
    from . import discovery

    try:
        settings: Settings | None = load_settings(args.config)
    except (FileNotFoundError, ValueError):
        settings = None

    if args.hosts:
        aliases = args.hosts
    elif args.all:
        aliases = [h.alias for h in discovery.discover(probe=True) if h.usable]
        if not aliases:
            say(f"{WARN} no reachable hosts found in ~/.ssh/config")
            return 1
    else:
        say(f"{BAD} name a host, or pass --all to enroll every reachable host")
        return 2

    if args.hardened:
        say("Hardened enrolment. Uses sudo on the host to create a dedicated account.")
        say(f"Each host gets: unprivileged user {args.diag_user!r} (no sudo, not in the")
        say("docker group), a root-owned shim it cannot rewrite, a read-only docker")
        say("proxy, and a forced-command key.\n")
    else:
        say("Enrolling over your existing SSH access. No sudo, no new system user.")
        say("Each host gets: the shim in ~/.local/bin, and one restricted key entry.")
        say("Your existing authorized_keys entries are not touched.\n")

    try:
        _ensure_local_key()
        shim, expected = _build_shim()
    except RuntimeError as exc:
        say(f"{BAD} {exc}")
        return 1

    if args.hardened:
        enrolled = [
            r
            for alias in aliases
            if (
                r := _enroll_hardened(
                    alias,
                    shim,
                    expected,
                    args.diag_user,
                    args.elevated,
                    args.proxy_port,
                    settings,
                    args.allow_exec,
                    args.exec_container,
                )
            )
        ]
    else:
        enrolled = [
            r
            for alias in aliases
            if (r := _enroll_one(alias, shim, expected, settings, args.elevated))
        ]
    if not enrolled:
        say(f"\n{BAD} nothing was enrolled")
        return 1

    default_allow = DEFAULT_ALLOW
    lines = [
        "# Written by `safereach enroll`.",
        "#",
        "# Each host runs safereach-shim behind an SSH forced command, so the key below can",
        "# invoke nothing else — the allowlist is enforced ON THE HOST, not just here.",
        "#",
        "# Note these hosts authenticate as your own account, so a shim bug would carry",
        "# your privileges. For a dedicated unprivileged account as well:",
        "#     safereach provision <alias> --admin-user <you>",
        "",
        "defaults:",
        "  audit_log: ~/.local/state/safereach/audit.jsonl",
        "",
        "hosts:",
    ]
    config_aliases = set(discovery.candidate_aliases())
    for host in enrolled:
        alias = host["alias"]
        # Only delegate to ~/.ssh/config for aliases that are actually Host entries
        # there — that path preserves ProxyJump and friends. Anything else (a bare
        # hostname, or `user@host`) is written explicitly, because asyncssh takes the
        # connect target literally and would try to resolve "user@host" as a DNS name.
        # A hardened host connects as the *diag* account, so it must never resolve
        # through ~/.ssh/config — that would silently reconnect as your own user and
        # bypass the unprivileged account entirely.
        if host.get("hardened"):
            key_name = _yaml_key(host["hostname"] or alias)
            connection = [
                f"    hostname: {host['hostname'] or alias}",
                f"    user: {host['user']}",
                f"    port: {host['port']}",
            ]
            if host.get("docker_host"):
                connection.append(f"    docker_host: {host['docker_host']}")
        elif alias in config_aliases:
            key_name = _yaml_key(alias)
            connection = [f"    ssh_config_host: {alias}"]
        else:
            key_name = _yaml_key(host["hostname"] or alias)
            connection = [
                f"    hostname: {host['hostname'] or alias}",
                f"    user: {host['user']}",
                f"    port: {host['port']}",
            ]
        lines += [
            f"  {key_name}:",
            *connection,
            f"    key: {KEY_PATH}",
            f'    description: "{host["description"]}"',
            f"    allow: [{', '.join(default_allow)}]",
            "    curl_targets: [localhost, 127.0.0.1]",
            *([f"    elevated: [{', '.join(args.elevated)}]"] if args.elevated else []),
            "",
        ]

    dest = Path(args.out).expanduser() if args.out else DEFAULT_CONFIG_PATH
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines), encoding="utf-8")
    dest.chmod(0o600)

    say(f"\n{OK} enrolled {len(enrolled)} host(s); wrote {dest}")
    say("\nNext:  safereach install")
    return 0


# --------------------------------------------------------------------------------------
# validate (offline allowlist check)
# --------------------------------------------------------------------------------------


def cmd_validate(args: argparse.Namespace) -> int:
    """Check a command against the allowlist without connecting to anything.

    Useful when extending commands.yaml: it shows the exact string that would go over the
    wire, including force-injected flags.
    """
    spec = load_command_spec()
    ctx: dict[str, Any] = {"curl_targets": args.curl_targets or []}
    allow = None

    if args.host:
        settings = load_settings(args.config)
        host = settings.host(args.host)
        allow = host.allow or None
        ctx["curl_targets"] = list(host.curl_targets)

    try:
        result = validate(args.command, spec, allow=allow, ctx=ctx)
    except Rejected as rej:
        say(rej.render())
        return 1
    say(f"{OK} accepted")
    say(f"   would execute: {render(result.argv)}")
    if result.injected:
        say(f"   force-injected: {' '.join(result.injected)}")
    return 0


# --------------------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------------------


async def _probe_hosts(
    settings: Settings, expected: str, fix: bool = False
) -> list[tuple[str, str, str]]:
    pool = SSHPool(settings.defaults)
    rows: list[tuple[str, str, str]] = []
    try:

        async def one(host: HostConfig) -> tuple[str, str, str]:
            try:
                version = await pool.shim_version(host)
            except SSHError as exc:
                return (BAD, host.alias, str(exc))
            if version is None:
                return (WARN, host.alias, f"reachable, no shim — run `enroll {host.alias}`")
            if version != expected:
                # Drift is the realistic failure mode, and since enrolment needs no root
                # the fix costs nothing. `doctor --fix` re-pushes rather than telling you
                # to run yet another command.
                if fix:
                    if _push_shim(host.alias):
                        return (OK, host.alias, f"shim was stale; re-pushed {expected}")
                    return (BAD, host.alias, f"shim {version} is stale and re-push failed")
                return (
                    BAD,
                    host.alias,
                    f"shim {version} != expected {expected} — run `doctor --fix`",
                )
            return (OK, host.alias, f"reachable, shim {version}")

        rows = list(await asyncio.gather(*(one(h) for h in settings.hosts.values())))
    finally:
        await pool.close()
    return rows


def _push_shim(alias: str) -> bool:
    """Re-install the shim on one enrolled host. No root needed, so this is safe to
    do automatically as part of `doctor --fix`."""
    try:
        shim, _expected = _build_shim()
    except RuntimeError:
        return False
    up = subprocess.run(
        ["scp", "-q", "-o", "BatchMode=yes", str(shim), f"{alias}:/tmp/.safereach-shim.upload"],
        capture_output=True,
        text=True,
        check=False,
    )
    if up.returncode != 0:
        return False
    inst = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            alias,
            'install -m 0755 /tmp/.safereach-shim.upload "$HOME/.local/bin/safereach-shim" '
            "&& rm -f /tmp/.safereach-shim.upload",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return inst.returncode == 0


def cmd_doctor(args: argparse.Namespace) -> int:
    problems = 0

    try:
        settings = load_settings(args.config)
    except (FileNotFoundError, ValueError) as exc:
        say(f"{BAD} config: {exc}")
        return 1
    say(f"{OK} config: {settings.source_path} ({len(settings.hosts)} host(s))")

    # Mode. The file holds hostnames, usernames and key paths.
    if settings.source_path:
        mode = stat.S_IMODE(settings.source_path.stat().st_mode)
        if mode & 0o077:
            say(
                f"{WARN} config is mode {mode:04o}; tighten with `chmod 600 {settings.source_path}`"
            )
            problems += 1

    try:
        spec = load_command_spec()
        expected = fingerprint(spec)
        say(f"{OK} command spec: {len(spec)} binaries, fingerprint {expected}")
    except Exception as exc:  # noqa: BLE001
        say(f"{BAD} command spec: {exc}")
        return 1

    # Keys and known_hosts, checked locally before any network work.
    for alias, host in settings.hosts.items():
        key = host.expanded_key()
        if not key.is_file():
            say(f"{BAD} {alias}: key {key} not found")
            problems += 1
            continue
        mode = stat.S_IMODE(key.stat().st_mode)
        if mode & 0o077:
            say(f"{WARN} {alias}: key {key} is mode {mode:04o}; ssh may refuse it")
            problems += 1
        kh = host.expanded_known_hosts(settings.defaults)
        if not kh.is_file():
            say(f"{BAD} {alias}: known_hosts {kh} not found — host keys cannot be verified")
            problems += 1

    # Agent registrations.
    for adapter in ad.detect_all():
        path = adapter.config_path()
        if path and path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8") or "{}")
                registered = ad.SERVER_KEY in (data.get(adapter.root_key) or {})
            except Exception:  # noqa: BLE001
                registered = False
            say(
                f"{OK if registered else '  '} {adapter.label}: "
                f"{'registered' if registered else 'not registered'}"
            )

    if args.offline:
        say("\n(skipping connectivity checks: --offline)")
        return 1 if problems else 0

    if not settings.hosts:
        return 1 if problems else 0

    say("\nConnectivity:")
    for mark, alias, detail in asyncio.run(_probe_hosts(settings, expected, fix=args.fix)):
        say(f"{mark} {alias}: {detail}")
        if mark != OK:
            problems += 1

    say("")
    say(f"{OK} no problems found" if not problems else f"{WARN} {problems} problem(s) above")
    return 1 if problems else 0


# --------------------------------------------------------------------------------------
# provision / shim-update
# --------------------------------------------------------------------------------------

REMOTE_SETUP = r"""set -eu
DIAG_USER="{user}"
SHIM=/usr/local/bin/safereach-shim
CONF_DIR=/etc/safereach

if ! id -u "$DIAG_USER" >/dev/null 2>&1; then
  useradd -r -m -s /bin/bash "$DIAG_USER"
  echo "created user $DIAG_USER"
fi

# These two groups are what make the host legible at all. Without systemd-journal,
# journalctl returns only this user's own entries, which is effectively nothing; adm
# covers /var/log/syslog, auth.log and nginx logs. The docker group is deliberately NOT
# added — it is root-equivalent, which is why DOCKER_HOST points at a read-only proxy.
for grp in systemd-journal adm; do
  if getent group "$grp" >/dev/null 2>&1; then
    usermod -aG "$grp" "$DIAG_USER"
  fi
done

install -m 0755 /tmp/safereach-shim.upload "$SHIM"
rm -f /tmp/safereach-shim.upload
mkdir -p "$CONF_DIR"
install -m 0644 /tmp/safereach-shim.conf.upload "$CONF_DIR/config.json"
rm -f /tmp/safereach-shim.conf.upload

HOME_DIR=$(getent passwd "$DIAG_USER" | cut -d: -f6)
mkdir -p "$HOME_DIR/.ssh"
touch "$HOME_DIR/.ssh/authorized_keys"
# Replace any previous entry for this key rather than appending a duplicate.
grep -v 'safereach-shim' "$HOME_DIR/.ssh/authorized_keys" > "$HOME_DIR/.ssh/authorized_keys.new" || true
cat >> "$HOME_DIR/.ssh/authorized_keys.new" <<'AUTHKEY'
{authkey}
AUTHKEY
mv "$HOME_DIR/.ssh/authorized_keys.new" "$HOME_DIR/.ssh/authorized_keys"
chown -R "$DIAG_USER":"$DIAG_USER" "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"

touch /var/log/safereach.jsonl
chown "$DIAG_USER" /var/log/safereach.jsonl
chmod 0640 /var/log/safereach.jsonl

echo "shim version: $($SHIM --version)"
echo "groups: $(id -nG "$DIAG_USER")"
"""

AUTHKEY_OPTS = (
    'command="/usr/local/bin/safereach-shim",no-port-forwarding,no-agent-forwarding,'
    "no-pty,no-X11-forwarding,no-user-rc"
)


def _build_shim() -> tuple[Path, str]:
    """Build the shim into a temp file and return its path and fingerprint."""
    repo_build = Path(__file__).resolve().parents[2] / "shim" / "build.py"
    spec = load_command_spec()
    expected = fingerprint(spec)

    if repo_build.is_file():
        out = Path(tempfile.mkdtemp(prefix="safereach-shim-")) / "safereach-shim"
        proc = subprocess.run(
            [sys.executable, str(repo_build), "--out", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"shim build failed: {proc.stderr.strip()}")
        return out, expected

    packaged = Path(__file__).parent / "data" / "safereach-shim"
    if packaged.is_file():
        return packaged, expected
    raise RuntimeError("cannot locate shim/build.py or a packaged safereach-shim")


def _shim_config(host: HostConfig, settings: Settings) -> dict[str, Any]:
    """The host's own policy file.

    Deliberately host-local: what this server believes about a host is irrelevant to what
    the host permits. A compromised server cannot widen a host's allowlist by sending a
    different config, because it never sends one.
    """
    return {
        "allow": sorted(host.allow),
        "curl_targets": sorted(host.curl_targets),
        "docker_host": host.docker_host,
        "command_timeout": host.timeout(settings.defaults),
        "max_output_bytes": host.max_bytes(settings.defaults),
        "elevated": {
            "dmesg-recent": [
                "/usr/bin/sudo",
                "-n",
                "/bin/dmesg",
                "--level=err,crit,alert,emerg",
                "--ctime",
            ]
        }
        if "dmesg-recent" in host.elevated
        else {},
    }


def _ssh_base(args: argparse.Namespace, host: HostConfig, settings: Settings) -> list[str]:
    port = host.ssh_port(settings.defaults)
    return ["ssh", "-p", str(port), f"{args.admin_user}@{host.hostname}"]


def cmd_provision(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    try:
        host = settings.host(args.host)
    except KeyError as exc:
        say(f"{BAD} {exc}")
        return 2

    pub = Path(str(host.expanded_key()) + ".pub")
    if not pub.is_file():
        say(f"{BAD} public key {pub} not found (expected alongside the private key)")
        return 1

    authkey = f"{AUTHKEY_OPTS} {pub.read_text(encoding='utf-8').strip()}"
    script = REMOTE_SETUP.format(user=host.user, authkey=authkey)
    conf = json.dumps(_shim_config(host, settings), indent=2)

    say(f"About to provision {host.alias} ({host.hostname}) as admin user {args.admin_user!r}:")
    say(f"  - create unprivileged user {host.user!r}, add to systemd-journal and adm")
    say("  - install /usr/local/bin/safereach-shim")
    say("  - write /etc/safereach/config.json")
    say("  - pin the diag key to a forced command in authorized_keys")
    say("")
    if args.dry_run:
        say("--- remote script ---")
        say(script)
        say("--- /etc/safereach/config.json ---")
        say(conf)
        return 0
    if not args.yes:
        say("This modifies a remote host. Re-run with --yes to proceed (or --dry-run to inspect).")
        return 1

    try:
        shim_path, expected = _build_shim()
    except RuntimeError as exc:
        say(f"{BAD} {exc}")
        return 1

    port = str(host.ssh_port(settings.defaults))
    target = f"{args.admin_user}@{host.hostname}"

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write(conf)
        conf_path = Path(fh.name)

    try:
        for src, dest in (
            (shim_path, "/tmp/safereach-shim.upload"),
            (conf_path, "/tmp/safereach-shim.conf.upload"),
        ):
            proc = subprocess.run(
                ["scp", "-P", port, str(src), f"{target}:{dest}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                say(f"{BAD} scp failed: {proc.stderr.strip()}")
                return 1

        proc = subprocess.run(
            [*_ssh_base(args, host, settings), "sudo", "-n", "bash", "-s"],
            input=script,
            capture_output=True,
            text=True,
            check=False,
        )
        say(proc.stdout.strip())
        if proc.returncode != 0:
            say(f"{BAD} remote setup failed: {proc.stderr.strip()}")
            return 1
    finally:
        conf_path.unlink(missing_ok=True)

    say(f"\n{OK} provisioned {host.alias} (expected fingerprint {expected})")
    say("   Verify with: safereach doctor")
    return 0


def cmd_shim_update(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    if args.all:
        hosts = list(settings.hosts.values())
    elif args.host:
        try:
            hosts = [settings.host(args.host)]
        except KeyError as exc:
            say(f"{BAD} {exc}")
            return 2
    else:
        say(f"{BAD} name a host or pass --all")
        return 2

    try:
        shim_path, expected = _build_shim()
    except RuntimeError as exc:
        say(f"{BAD} {exc}")
        return 1
    say(f"built shim, fingerprint {expected}")

    failures = 0
    for host in hosts:
        port = str(host.ssh_port(settings.defaults))
        target = f"{args.admin_user}@{host.hostname}"
        up = subprocess.run(
            ["scp", "-P", port, str(shim_path), f"{target}:/tmp/safereach-shim.upload"],
            capture_output=True,
            text=True,
            check=False,
        )
        if up.returncode != 0:
            say(f"{BAD} {host.alias}: scp failed: {up.stderr.strip()}")
            failures += 1
            continue
        inst = subprocess.run(
            [
                "ssh",
                "-p",
                port,
                target,
                "sudo",
                "-n",
                "install",
                "-m",
                "0755",
                "/tmp/safereach-shim.upload",
                "/usr/local/bin/safereach-shim",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if inst.returncode != 0:
            say(f"{BAD} {host.alias}: install failed: {inst.stderr.strip()}")
            failures += 1
            continue
        say(f"{OK} {host.alias}: updated to {expected}")

    return 1 if failures else 0


# --------------------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safereach",
        description="Read-only remote diagnostics over SSH, as an MCP server. "
        "With no subcommand, runs the MCP server over stdio.",
    )
    parser.add_argument("--config", help="path to hosts.yaml")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="scaffold hosts.yaml")
    p.add_argument("--path")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("install", help="register this server with your agents")
    p.add_argument("agents", nargs="*", help=f"one or more of: {', '.join(sorted(ad.ADAPTERS))}")
    p.add_argument("--all", action="store_true", help="every detected agent")
    p.add_argument("--list", action="store_true", help="show detected agents and exit")
    p.add_argument(
        "--launcher",
        choices=["auto", "uvx", "script"],
        default="auto",
        help="how agents start the server: uvx (portable, default when available) "
        "or the installed console script",
    )
    p.add_argument(
        "--unpinned",
        action="store_true",
        help="register `uvx safereach` without a version pin (not recommended)",
    )
    p.set_defaults(func=cmd_install, remove=False)

    p = sub.add_parser("uninstall", help="remove this server's registration")
    p.add_argument("agents", nargs="*")
    p.add_argument("--all", action="store_true")
    p.add_argument("--list", action="store_true")
    p.add_argument("--launcher", choices=["auto", "uvx", "script"], default="auto")
    p.add_argument("--unpinned", action="store_true")
    p.set_defaults(func=cmd_install, remove=True)

    p = sub.add_parser(
        "enroll",
        help="set up hosts over your existing SSH access (no sudo) — the recommended path",
    )
    p.add_argument("hosts", nargs="*", help="aliases to enroll")
    p.add_argument("--all", action="store_true", help="every reachable host in ~/.ssh/config")
    p.add_argument("--out", help="where to write hosts.yaml")
    p.add_argument(
        "--elevated",
        action="append",
        default=[],
        choices=sorted(ELEVATED_RECIPES),
        help="enable a named privileged read (repeatable); requires passwordless sudo on the host",
    )
    p.add_argument(
        "--hardened",
        action="store_true",
        help="create a dedicated unprivileged user with read-only docker (needs sudo on the host)",
    )
    p.add_argument("--diag-user", default="diag", help="account name for --hardened")
    p.add_argument(
        "--proxy-port", type=int, default=2375, help="localhost port for the docker proxy"
    )
    p.add_argument(
        "--allow-exec",
        action="store_true",
        help="permit read-only commands INSIDE containers via docker exec "
        "(requires POST on the docker proxy — see the README)",
    )
    p.add_argument(
        "--exec-container",
        action="append",
        default=[],
        metavar="NAME",
        help="restrict --allow-exec to this container (repeatable; default: any)",
    )
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser(
        "discover", help="find servers you can already reach with your existing SSH keys"
    )
    p.add_argument(
        "hosts", nargs="*", help="specific aliases to check (default: all in ~/.ssh/config)"
    )
    p.add_argument("--out", help="where to write hosts.yaml")
    p.add_argument("--force", action="store_true", help="overwrite an existing hosts.yaml")
    p.add_argument("--dry-run", action="store_true", help="print the config instead of writing it")
    p.add_argument("--no-probe", action="store_true", help="skip the live connection check")
    p.add_argument("--timeout", type=int, default=8)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("validate", help="check a command against the allowlist, offline")
    p.add_argument("command")
    p.add_argument("--host", help="apply this host's allow list and curl targets")
    p.add_argument("--curl-targets", nargs="*", default=None)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("doctor", help="verify config, keys, connectivity and shim versions")
    p.add_argument("--offline", action="store_true", help="skip network checks")
    p.add_argument("--fix", action="store_true", help="re-push the shim to any drifted host")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser(
        "provision", help="set up a remote host (user, groups, shim, authorized_keys)"
    )
    p.add_argument("host")
    p.add_argument(
        "--admin-user",
        default=os.environ.get("USER", "root"),
        help="the account with sudo on the target (NOT the diag user)",
    )
    p.add_argument("--yes", action="store_true", help="proceed without confirmation")
    p.add_argument("--dry-run", action="store_true", help="print what would run")
    p.set_defaults(func=cmd_provision)

    p = sub.add_parser("shim-update", help="rebuild and redeploy the shim")
    p.add_argument("host", nargs="?")
    p.add_argument("--all", action="store_true")
    p.add_argument("--admin-user", default=os.environ.get("USER", "root"))
    p.set_defaults(func=cmd_shim_update)

    return parser


def _is_server_invocation(args: list[str]) -> bool:
    """True when the arguments are only ones the stdio server understands.

    No arguments at all is the common case — that is how an agent launches it.
    """
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--config" and i + 1 < len(args):
            i += 2
            continue
        if arg.startswith("--config="):
            i += 1
            continue
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv

    # Server mode is the no-subcommand default, and it has to be decided before argparse
    # so that a bare `safereach --config X` is not answered with a usage message on
    # stdout — which would corrupt the JSON-RPC stream.
    #
    # The test is "does this invocation consist only of server arguments", not "is a
    # subcommand absent". Anything else — including `--help` and `--version` — belongs to
    # argparse. Getting this backwards meant `--help` started the server and died looking
    # for hosts.yaml.
    if _is_server_invocation(args_list):
        from .server import run

        run()
        return 0

    parser = build_parser()
    args = parser.parse_args(args_list)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return 2
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        say(f"{BAD} {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
