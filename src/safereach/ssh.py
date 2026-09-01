"""SSH transport: a pooled asyncssh client with strict host key checking.

Nothing in this module decides what may run — that is entirely :mod:`validator`. This
layer's job is to get an already-validated string to the host safely, bound its cost, and
turn asyncssh's exceptions into messages that are useful to an agent without leaking
infrastructure detail back to it.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh

from .config import Defaults, HostConfig

__all__ = ["SSHPool", "ExecResult", "SSHError"]

#: Bound concurrent channels per host so a fan-out cannot exhaust MaxSessions.
_MAX_CHANNELS_PER_HOST = 4


class SSHError(Exception):
    """A transport-level failure, already scrubbed for agent consumption."""


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    duration_ms: int


class SSHPool:
    """Reuses one connection per host alias.

    Connection reuse is the actual performance lever here. Every call would otherwise pay
    a full handshake — 100-300 ms — which dwarfs the runtime of the diagnostic commands
    themselves. Held in the server's lifespan context and closed on shutdown.
    """

    def __init__(self, defaults: Defaults) -> None:
        self._defaults = defaults
        self._conns: dict[str, asyncssh.SSHClientConnection] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}

    def _lock(self, alias: str) -> asyncio.Lock:
        return self._locks.setdefault(alias, asyncio.Lock())

    def _sem(self, alias: str) -> asyncio.Semaphore:
        return self._sems.setdefault(alias, asyncio.Semaphore(_MAX_CHANNELS_PER_HOST))

    async def close(self) -> None:
        for conn in list(self._conns.values()):
            conn.close()
        for conn in list(self._conns.values()):
            with contextlib.suppress(Exception):  # shutdown is best-effort
                await conn.wait_closed()
        self._conns.clear()

    def _auth_options(self, host: HostConfig) -> dict[str, Any]:
        """Where the credentials come from.

        Two modes. With ``ssh_config_host`` set, asyncssh reads the user's own
        ``~/.ssh/config`` and applies whatever IdentityFile, User, Port and ProxyJump it
        finds — the same resolution ``ssh <alias>`` would do, so a host the user can
        already reach works with no extra configuration. Otherwise the key is explicit.

        ``agent_path`` is left at its default when ``use_agent`` is set, which lets
        asyncssh pick up ``SSH_AUTH_SOCK``. That is agent *use*, not agent *forwarding*:
        the socket is read locally to sign a challenge and is never exposed to the remote
        host.
        """
        options: dict[str, Any] = {}

        key_path = host.expanded_key()
        if key_path is not None and not key_path.is_file():
            raise SSHError(
                f"SSH key for host {host.alias!r} is missing or unreadable. "
                "Check the 'key' entry in hosts.yaml."
            )

        if host.uses_ssh_config:
            config_path = Path("~/.ssh/config").expanduser()
            if not config_path.is_file():
                raise SSHError(
                    f"host {host.alias!r} is configured to resolve through ~/.ssh/config, "
                    "but that file does not exist."
                )
            options["config"] = [str(config_path)]
            # `enroll` writes both: hostname, port and ProxyJump still come from the
            # user's own SSH config (so a host behind a bastion keeps working), while the
            # key is the dedicated enrolled one rather than whatever IdentityFile the
            # config names. An explicit client_keys overrides the config's identities.
            if key_path is not None:
                options["client_keys"] = [str(key_path)]
        else:
            if key_path is not None:
                options["client_keys"] = [str(key_path)]
            options["username"] = host.user
            options["port"] = host.ssh_port(self._defaults)

        if not host.use_agent:
            options["agent_path"] = None
        return options

    async def _connect(self, host: HostConfig) -> asyncssh.SSHClientConnection:
        auth = self._auth_options(host)
        target = host.ssh_config_host if host.uses_ssh_config else host.hostname

        known_hosts = host.expanded_known_hosts(self._defaults)
        if not known_hosts.is_file():
            raise SSHError(
                f"known_hosts file for {host.alias!r} does not exist. "
                "Host key checking cannot be skipped — populate it with "
                f"`ssh-keyscan -p {host.ssh_port(self._defaults)} "
                f"{host.hostname or host.ssh_config_host} >> {known_hosts}`."
            )

        try:
            return await asyncssh.connect(
                target,
                # Never None. asyncssh reads None as "accept any host key", which
                # silently accepts a man-in-the-middle.
                known_hosts=str(known_hosts),
                connect_timeout=host.connect_secs(self._defaults),
                login_timeout=host.connect_secs(self._defaults),
                keepalive_interval=30,
                **auth,
            )
        except asyncssh.HostKeyNotVerifiable as exc:
            raise SSHError(
                f"host key for {host.alias!r} is not in known_hosts, or has changed. "
                "This is refused rather than trusted on first use. If the host was "
                "legitimately rebuilt, remove the stale entry and re-scan it."
            ) from exc
        except asyncssh.PermissionDenied as exc:
            # Deliberately vague: the agent does not need the key path or username.
            raise SSHError(
                f"authentication was refused by host {host.alias!r}. "
                "Verify the diag key is installed in that host's authorized_keys."
            ) from exc
        except (TimeoutError, OSError, asyncssh.Error) as exc:
            raise SSHError(
                f"could not connect to host {host.alias!r}: {type(exc).__name__}"
            ) from exc

    async def _get(self, host: HostConfig) -> asyncssh.SSHClientConnection:
        async with self._lock(host.alias):
            conn = self._conns.get(host.alias)
            if conn is not None and not conn.is_closed():
                return conn
            conn = await self._connect(host)
            self._conns[host.alias] = conn
            return conn

    async def _drop(self, alias: str) -> None:
        async with self._lock(alias):
            conn = self._conns.pop(alias, None)
        if conn is not None:
            conn.close()

    async def run(self, host: HostConfig, command: str) -> ExecResult:
        """Execute one already-validated command string.

        The string goes to sshd, which — with the forced command installed — hands it to
        ``safereach-shim`` as ``$SSH_ORIGINAL_COMMAND`` rather than executing it. The same call
        works on a host without the shim, which is what makes incremental rollout
        possible.
        """
        timeout = host.timeout(self._defaults)
        max_bytes = host.max_bytes(self._defaults)

        async with self._sem(host.alias):
            started = time.monotonic()
            try:
                conn = await self._get(host)
                result = await conn.run(
                    command,
                    check=False,
                    timeout=timeout,
                    # No PTY: blocks interactive pagers and curses UIs outright, rather
                    # than relying on --no-pager reaching every tool.
                    request_pty=False,
                )
            except TimeoutError as exc:
                raise SSHError(
                    f"command exceeded the {timeout}s timeout on {host.alias!r} and was terminated"
                ) from exc
            except asyncssh.ChannelOpenError as exc:
                await self._drop(host.alias)
                raise SSHError(
                    f"could not open a session on {host.alias!r} (too many channels?)"
                ) from exc
            except (OSError, asyncssh.Error) as exc:
                # A dropped connection is usually transient. Evict so the next call
                # reconnects rather than reusing a dead handle.
                await self._drop(host.alias)
                raise SSHError(
                    f"connection to {host.alias!r} failed: {type(exc).__name__}"
                ) from exc

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = _as_text(result.stdout)
        stderr = _as_text(result.stderr)
        truncated = len(stdout) > max_bytes or len(stderr) > max_bytes

        return ExecResult(
            exit_code=result.exit_status if result.exit_status is not None else -1,
            stdout=stdout[:max_bytes],
            stderr=stderr[:max_bytes],
            truncated=truncated,
            duration_ms=duration_ms,
        )

    async def shim_version(self, host: HostConfig) -> str | None:
        """Ask the host's shim for its version stamp.

        Returns ``None`` when no shim is installed — which is a legitimate state during
        rollout, not an error. The caller decides whether to allow it.
        """
        try:
            result = await self.run(host, "@version")
        except SSHError:
            raise
        if result.exit_code != 0:
            return None
        version = result.stdout.strip()
        return version or None


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
