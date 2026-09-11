"""Start, reach and tear down the disposable production host.

Everything that touches a real server in the suite goes through here, so the container
is the only thing ever enrolled, provisioned, or probed. Usable on its own::

    python -m tests.e2e.rig up      # build + start, print how to ssh in
    python -m tests.e2e.rig down    # stop and remove, including the docker volume

The container runs ``--privileged``: systemd needs it, and so does the Docker daemon
nested inside (the proxy the hardened enrolment starts has to run on THAT daemon, or the
unix socket it binds would land on this machine instead of the "host").
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = "safereach-e2e-host"
CONTAINER = "safereach-e2e-host"
VOLUME = "safereach-e2e-docker"
CONTAINERD_VOLUME = "safereach-e2e-containerd"
PORT = int(os.environ.get("SAFEREACH_E2E_PORT", "2222"))
ADMIN = "ops"
ALIAS = "e2e-prod"


def _run(*cmd: str, check: bool = True, **kw: object) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(list(cmd), capture_output=True, text=True, check=False, **kw)  # type: ignore[arg-type]
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc


def docker_available() -> bool:
    return (
        shutil.which("docker") is not None and _run("docker", "info", check=False).returncode == 0
    )


@dataclass
class Host:
    """A running host and the throwaway HOME that knows how to reach it."""

    home: Path
    admin_key: Path
    port: int = PORT
    alias: str = ALIAS

    @property
    def env(self) -> dict[str, str]:
        """Environment for `safereach` subprocesses: nothing from the real HOME leaks in."""
        return {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "PATH": os.environ["PATH"],
            "SSH_AUTH_SOCK": "",  # no agent: the enrolled key must stand on its own
            # OpenSSH reads ~/.ssh/config from the passwd home, not $HOME; point it here.
            "SAFEREACH_SSH_CONFIG": str(self.home / ".ssh" / "config"),
            "NO_COLOR": "1",
            "PYTHONUNBUFFERED": "1",
        }

    def exec(self, *cmd: str, user: str = "root", check: bool = True) -> str:
        """Run a command inside the container as root (or another user), for assertions."""
        proc = _run("docker", "exec", "-u", user, CONTAINER, *cmd, check=check)
        return proc.stdout

    def ssh(
        self, *cmd: str, user: str = ADMIN, key: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        """A real ssh session, using only the given key."""
        return _run(
            "ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"UserKnownHostsFile={self.home / '.ssh' / 'known_hosts'}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-i",
            str(key or self.admin_key),
            "-p",
            str(self.port),
            "-o",
            "ConnectTimeout=15",
            f"{user}@127.0.0.1",
            *cmd,
            check=False,
            timeout=120,  # a hung session must fail the test, not the run
        )

    def safereach(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return _run(sys.executable, "-m", "safereach", *args, env=self.env, check=check)


def build() -> None:
    _run("docker", "build", "-q", "-t", IMAGE, str(HERE))


def up(home: Path) -> Host:
    """Build if needed, start the host, and prepare a HOME that can ssh to it as admin."""
    if _run("docker", "image", "inspect", IMAGE, check=False).returncode != 0:
        build()
    down()
    _run(
        "docker",
        "run",
        "-d",
        "--name",
        CONTAINER,
        "--privileged",
        "--cgroupns=private",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        # No /sys/fs/cgroup bind mount: on cgroup v2 Docker gives a private namespace its
        # own writable cgroup2 mount, and bind-mounting the host's over it kills systemd.
        "-v",
        f"{VOLUME}:/var/lib/docker",
        "-v",
        f"{CONTAINERD_VOLUME}:/var/lib/containerd",
        "-p",
        f"127.0.0.1:{PORT}:22",
        IMAGE,
    )

    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    ssh_dir.chmod(0o700)
    admin_key = ssh_dir / "id_ed25519_ops"
    _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "e2e-admin", "-f", str(admin_key))

    _wait_for(
        "sshd",
        lambda: (
            _run(
                "docker", "exec", CONTAINER, "systemctl", "is-active", "ssh", check=False
            ).stdout.strip()
            == "active"
        ),
    )
    _wait_for(
        "dockerd",
        lambda: _run("docker", "exec", CONTAINER, "docker", "info", check=False).returncode == 0,
    )
    _wait_for(
        "app",
        lambda: (
            _run(
                "docker", "exec", CONTAINER, "systemctl", "is-active", "app", check=False
            ).stdout.strip()
            == "active"
        ),
    )

    pub = Path(str(admin_key) + ".pub").read_text(encoding="utf-8")
    _run(
        "docker",
        "exec",
        "-i",
        CONTAINER,
        "bash",
        "-c",
        f"install -o {ADMIN} -g {ADMIN} -m 0600 /dev/stdin /home/{ADMIN}/.ssh/authorized_keys",
        input=pub,
    )

    # known_hosts, the way an operator would populate it: scan, never trust-on-first-use.
    scan = _run("ssh-keyscan", "-p", str(PORT), "127.0.0.1")
    (ssh_dir / "known_hosts").write_text(scan.stdout, encoding="utf-8")

    # An ssh_config Host entry: `enroll` reaches hosts by alias through OpenSSH itself.
    (ssh_dir / "config").write_text(
        textwrap.dedent(
            f"""\
            # One block for the alias `enroll` uses and the admin@hostname form that
            # `shim-update` and `provision` use; Host matches the name typed, not HostName.
            Host {ALIAS} 127.0.0.1
                HostName 127.0.0.1
                Port {PORT}
                User {ADMIN}
                IdentityFile {admin_key}
                IdentitiesOnly yes
                UserKnownHostsFile {ssh_dir / "known_hosts"}
                StrictHostKeyChecking yes
            """
        ),
        encoding="utf-8",
    )
    (ssh_dir / "config").chmod(0o600)

    host = Host(home=home, admin_key=admin_key)
    _wait_for("ssh as admin", lambda: host.ssh("true").returncode == 0)
    return host


def down() -> None:
    _run("docker", "rm", "-f", CONTAINER, check=False)


def destroy() -> None:
    down()
    _run("docker", "volume", "rm", "-f", VOLUME, CONTAINERD_VOLUME, check=False)


def _wait_for(what: str, ready: Callable[[], bool], timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ready():
            return
        time.sleep(1.0)
    logs = _run("docker", "logs", "--tail", "40", CONTAINER, check=False)
    raise RuntimeError(
        f"{what} did not become ready within {timeout:.0f}s\n{logs.stdout}\n{logs.stderr}"
    )


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in {"up", "down", "destroy", "build"}:
        print(__doc__)
        return 2
    if argv[0] == "build":
        build()
        print(f"built {IMAGE}")
    elif argv[0] == "up":
        home = Path(os.environ.get("SAFEREACH_E2E_HOME", "/tmp/safereach-e2e-home"))
        home.mkdir(parents=True, exist_ok=True)
        host = up(home)
        print(f"up: ssh -F {home / '.ssh' / 'config'} {ALIAS}   (HOME={home} for safereach)")
        print(f"    HOME={home} XDG_CONFIG_HOME={home}/.config safereach enroll {ALIAS} --hardened")
        _ = host
    elif argv[0] == "down":
        down()
        print("down")
    else:
        destroy()
        print("destroyed (container and docker volume)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
