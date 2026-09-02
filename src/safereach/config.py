"""Configuration loading and validation.

This is the server-side half of the line: pydantic and PyYAML live here, never in
``validator.py``, which has to stay stdlib-only so it can be inlined into the shim.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import naming

__all__ = [
    "HostConfig",
    "Defaults",
    "Settings",
    "load_settings",
    "load_command_spec",
    "default_config_path",
    "resolve_data_file",
]

DEFAULT_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "safereach"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "hosts.yaml"


def default_config_path() -> Path:
    return DEFAULT_CONFIG_PATH


def resolve_data_file(name: str) -> Path:
    """Find a packaged data file, whether installed or running from a source checkout."""
    packaged = Path(__file__).parent / "data" / name
    if packaged.is_file():
        return packaged
    repo = Path(__file__).resolve().parents[2] / "config" / name
    if repo.is_file():
        return repo
    raise FileNotFoundError(f"could not locate {name}; looked in {packaged} and {repo}")


class Defaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port: int = 22
    connect_timeout: int = 10
    command_timeout: int = 30
    max_output_bytes: int = 65536
    known_hosts: str = "~/.ssh/known_hosts"
    audit_log: str = "~/.local/state/safereach/audit.jsonl"

    #: Refuse to run against a host with no safereach-shim installed. Safe by default: a host
    #: without the shim has only client-side validation, which is a UX layer rather than
    #: a control. Set false only for a deliberate incremental rollout, and expect
    #: `doctor` to keep pointing it out.
    require_shim: bool = True


class HostConfig(BaseModel):
    """One managed host.

    Everything the agent must not see lives here: hostname, user, key path, port. The
    agent addresses hosts by alias and the server resolves them, which is what prevents
    it aiming this at a machine it was not granted.
    """

    model_config = ConfigDict(extra="forbid")

    alias: str = ""
    description: str = ""

    #: Stable identity, assigned at enrolment and never changed. The alias answers
    #: "what do I call this today"; this answers "is this the same machine as last
    #: month", so renaming a host does not sever its audit history.
    id: str | None = None

    #: --- Mode A: delegate to ~/.ssh/config -------------------------------------
    #: Set this to an alias you can already `ssh` to, and hostname/user/key/port all
    #: come from OpenSSH's own resolution. This is what `discover` writes, and it is the
    #: zero-setup path: if `ssh myserver` works today, the agent can use `myserver`.
    ssh_config_host: str | None = None

    #: --- Mode B: explicit ------------------------------------------------------
    #: Used by `provision`ed hosts, where the connection details are ours rather than
    #: inherited from the user's own SSH setup.
    hostname: str | None = None
    user: str | None = None
    key: str | None = None
    port: int | None = None

    #: Allow the local ssh-agent to supply keys. Necessary for passphrase-protected keys,
    #: which is the common case for an existing personal key. This is agent *use*, not
    #: agent *forwarding* — nothing is exposed to the remote host.
    use_agent: bool = True

    #: Per-host override of defaults.require_shim. `discover` sets this false explicitly
    #: on each host it writes, so that running without the shim is a visible per-host
    #: marking rather than a silently loosened global.
    require_shim: bool | None = None

    #: Intersected with the global command spec — a host can only narrow, never widen.
    allow: list[str] = Field(default_factory=list)

    connect_timeout: int | None = None
    command_timeout: int | None = None
    max_output_bytes: int | None = None
    known_hosts: str | None = None

    docker_host: str | None = None
    env_allowlist: list[str] = Field(default_factory=list)

    #: Empty means curl reaches nothing. Default-deny: an internal host with an open
    #: curl is an outbound exfiltration channel.
    curl_targets: list[str] = Field(default_factory=list)
    curl_insecure: bool = False

    elevated: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _assign_stable_id(self) -> HostConfig:
        """Derive the id when the config does not carry one.

        Deriving rather than storing means every existing install gains audit continuity
        with no migration step, and the value cannot drift from the machine it names —
        the same hostname and port always produce the same id.
        """
        if not self.id:
            target = self.hostname or self.ssh_config_host or self.alias
            if target:
                object.__setattr__(self, "id", naming.host_id(target, self.port or 22))
        return self

    @model_validator(mode="after")
    def _require_one_connection_mode(self) -> HostConfig:
        if self.ssh_config_host:
            return self
        missing = [f for f in ("hostname", "user") if not getattr(self, f)]
        if missing:
            raise ValueError(
                f"host {self.alias or '?'} needs either 'ssh_config_host' (resolve via "
                f"~/.ssh/config) or explicit {', '.join(missing)}"
            )
        if not self.key and not self.use_agent:
            raise ValueError(
                f"host {self.alias or '?'} has no 'key' and use_agent is false, "
                "so there is no way to authenticate"
            )
        return self

    @property
    def uses_ssh_config(self) -> bool:
        return bool(self.ssh_config_host)

    def security_mode(self, shim_present: bool) -> str:
        """How much is actually standing between the agent and this host.

        Surfaced to the user rather than inferred, because the difference is large:
        `hardened` has an unprivileged account and a remote validator the agent cannot
        reach; `client-only` has neither, so the parser on this machine is the whole
        control.
        """
        if shim_present:
            return "hardened"
        return "client-only"

    @field_validator("known_hosts")
    @classmethod
    def _reject_disabled_host_keys(cls, v: str | None) -> str | None:
        # asyncssh treats known_hosts=None as "accept any host key", which silently
        # accepts a man-in-the-middle. There is no legitimate reason to configure that,
        # so the spelling that would request it is refused outright.
        if v is not None and str(v).strip().lower() in {"none", "null", "false", ""}:
            raise ValueError(
                "known_hosts must point at a real file; disabling host key checking "
                "is not supported"
            )
        return v

    def expanded_key(self) -> Path | None:
        return Path(self.key).expanduser() if self.key else None

    def expanded_known_hosts(self, defaults: Defaults) -> Path:
        return Path(self.known_hosts or defaults.known_hosts).expanduser()

    def timeout(self, defaults: Defaults) -> int:
        return self.command_timeout or defaults.command_timeout

    def connect_secs(self, defaults: Defaults) -> int:
        return self.connect_timeout or defaults.connect_timeout

    def max_bytes(self, defaults: Defaults) -> int:
        return self.max_output_bytes or defaults.max_output_bytes

    def ssh_port(self, defaults: Defaults) -> int:
        return self.port or defaults.port

    def shim_required(self, defaults: Defaults) -> bool:
        return defaults.require_shim if self.require_shim is None else self.require_shim

    def public_view(self) -> dict[str, Any]:
        """What the agent is allowed to know about this host."""
        return {
            "alias": self.alias,
            "description": self.description,
            "allowed_commands": sorted(self.allow),
            "elevated_recipes": sorted(self.elevated),
            "curl_targets": sorted(self.curl_targets),
        }


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: Defaults = Field(default_factory=Defaults)
    hosts: dict[str, HostConfig] = Field(default_factory=dict)
    source_path: Path | None = None

    def host(self, alias: str) -> HostConfig:
        try:
            return self.hosts[alias]
        except KeyError:
            known = ", ".join(sorted(self.hosts)) or "(none configured)"
            raise KeyError(f"unknown host {alias!r}; configured hosts: {known}") from None

    def audit_path(self) -> Path:
        return Path(self.defaults.audit_log).expanduser()


def load_command_spec(path: Path | None = None) -> dict[str, Any]:
    """Load ``commands.yaml`` into the plain dict the validator expects."""
    target = path or resolve_data_file("commands.yaml")
    with Path(target).open(encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    if not isinstance(spec, dict):
        raise ValueError(f"{target}: command spec must be a mapping")
    return spec


def load_settings(path: Path | None = None) -> Settings:
    """Resolve and load ``hosts.yaml``.

    Precedence: explicit path, then ``$SAFEREACH_CONFIG``, then the XDG default, then
    ``./hosts.yaml``.
    """
    target = _resolve_config_path(path)
    with target.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"{target}: config root must be a mapping")

    hosts_raw = raw.get("hosts") or {}
    if not isinstance(hosts_raw, dict):
        raise ValueError(f"{target}: 'hosts' must be a mapping of alias -> config")

    hosts: dict[str, HostConfig] = {}
    for alias, body in hosts_raw.items():
        if not isinstance(body, dict):
            raise ValueError(f"{target}: host {alias!r} must be a mapping")
        hosts[alias] = HostConfig(alias=alias, **body)

    return Settings(
        defaults=Defaults(**(raw.get("defaults") or {})),
        hosts=hosts,
        source_path=target,
    )


def _resolve_config_path(path: Path | None) -> Path:
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path).expanduser())
    env = os.environ.get("SAFEREACH_CONFIG")
    if env:
        candidates.append(Path(env).expanduser())
    candidates.append(DEFAULT_CONFIG_PATH)
    candidates.append(Path.cwd() / "hosts.yaml")

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        "no hosts.yaml found. Looked in: "
        + ", ".join(str(c) for c in candidates)
        + "\nRun `safereach init` to create one."
    )
