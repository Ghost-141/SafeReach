"""SSH-config discovery, and the zero-setup host mode it produces."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from safereach import discovery
from safereach.config import HostConfig, load_settings

CONFIG = """\
Host *
    ServerAliveInterval 60

Host web-01
    HostName 10.0.1.5
    User deploy
    IdentityFile ~/.ssh/id_ed25519

Host db-01 db-primary
    HostName 10.0.1.9
    User postgres

Host bastion-*
    ProxyJump none

Host  spaced-out
    HostName example.internal
"""


def _write_config(tmp_path: Path, body: str = CONFIG) -> Path:
    path = tmp_path / "config"
    path.write_text(body, encoding="utf-8")
    return path


def test_candidate_aliases_skips_patterns(tmp_path: Path) -> None:
    """`Host *` and `Host bastion-*` configure defaults; they do not name a machine."""
    aliases = discovery.candidate_aliases(_write_config(tmp_path))
    assert aliases == ["web-01", "db-01", "db-primary", "spaced-out"]
    assert "*" not in aliases
    assert "bastion-*" not in aliases


def test_multiple_names_on_one_host_line(tmp_path: Path) -> None:
    aliases = discovery.candidate_aliases(_write_config(tmp_path))
    assert "db-01" in aliases and "db-primary" in aliases


def test_duplicates_collapse(tmp_path: Path) -> None:
    body = "Host a\n  HostName x\nHost a\n  HostName y\n"
    assert discovery.candidate_aliases(_write_config(tmp_path, body)) == ["a"]


def test_missing_config_is_not_an_error(tmp_path: Path) -> None:
    assert discovery.candidate_aliases(tmp_path / "does-not-exist") == []


def test_include_directive_is_followed(tmp_path: Path) -> None:
    """Include is exactly the kind of thing a hand-rolled parser gets wrong."""
    extra = tmp_path / "work.conf"
    extra.write_text("Host workbox\n  HostName work.internal\n", encoding="utf-8")
    main = _write_config(tmp_path, f"Include {extra}\n\nHost home\n  HostName home.lan\n")

    aliases = discovery.candidate_aliases(main)
    assert "workbox" in aliases
    assert "home" in aliases


def test_include_glob_is_expanded(tmp_path: Path) -> None:
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "a.conf").write_text("Host alpha\n", encoding="utf-8")
    (tmp_path / "conf.d" / "b.conf").write_text("Host beta\n", encoding="utf-8")
    main = _write_config(tmp_path, "Include conf.d/*.conf\n")

    aliases = discovery.candidate_aliases(main)
    assert {"alpha", "beta"} <= set(aliases)


def test_include_cycle_terminates(tmp_path: Path) -> None:
    a = tmp_path / "a.conf"
    b = tmp_path / "b.conf"
    a.write_text(f"Include {b}\nHost from-a\n", encoding="utf-8")
    b.write_text(f"Include {a}\nHost from-b\n", encoding="utf-8")

    aliases = discovery.candidate_aliases(a)
    assert {"from-a", "from-b"} <= set(aliases)


def test_resolve_uses_ssh_itself() -> None:
    """`ssh -G` is the source of truth; we never reimplement OpenSSH's resolution."""
    host = discovery.resolve_alias("example.invalid")
    assert host.alias == "example.invalid"
    if host.status != "error":
        assert host.hostname == "example.invalid"
        assert host.user
        assert host.port


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("Permission denied (publickey).", "auth-failed"),
        ("Host key verification failed.", "unknown-host-key"),
        ("ssh: Could not resolve hostname x", "unreachable"),
        ("connect to host x port 22: Connection refused", "unreachable"),
    ],
)
def test_probe_classifies_failures(
    monkeypatch: pytest.MonkeyPatch, stderr: str, expected: str
) -> None:
    """The distinction matters: each failure has a different remedy."""

    class FakeProc:
        returncode = 255

    def fake_run(*_a: object, **_kw: object) -> object:
        proc = FakeProc()
        proc.stderr = stderr  # type: ignore[attr-defined]
        return proc

    monkeypatch.setattr(discovery.subprocess, "run", fake_run)
    status, _detail = discovery.probe_alias("whatever")
    assert status == expected


# --------------------------------------------------------------------------------------
# The config mode discovery produces
# --------------------------------------------------------------------------------------


def test_ssh_config_host_needs_nothing_else() -> None:
    """The whole point: an alias you can already ssh to needs no other configuration."""
    host = HostConfig(alias="web-01", ssh_config_host="web-01")
    assert host.uses_ssh_config
    assert host.hostname is None
    assert host.expanded_key() is None


def test_explicit_mode_still_requires_connection_details() -> None:
    with pytest.raises(ValidationError, match="ssh_config_host"):
        HostConfig(alias="broken", description="no way to connect")


def test_no_key_and_no_agent_is_refused() -> None:
    with pytest.raises(ValidationError, match="no way to authenticate"):
        HostConfig(alias="x", hostname="h", user="u", use_agent=False)


def test_per_host_shim_override(tmp_path: Path) -> None:
    """`discover` marks each host individually rather than loosening the global default."""
    path = tmp_path / "hosts.yaml"
    path.write_text(
        "hosts:\n"
        "  lab:\n"
        "    ssh_config_host: lab\n"
        "    require_shim: false\n"
        "  prod:\n"
        "    ssh_config_host: prod\n",
        encoding="utf-8",
    )
    settings = load_settings(path)

    assert settings.defaults.require_shim is True
    assert settings.host("lab").shim_required(settings.defaults) is False
    assert settings.host("prod").shim_required(settings.defaults) is True


def test_security_mode_is_reported_not_assumed() -> None:
    host = HostConfig(alias="lab", ssh_config_host="lab", require_shim=False)
    assert host.security_mode(shim_present=False) == "client-only"
    assert host.security_mode(shim_present=True) == "hardened"
