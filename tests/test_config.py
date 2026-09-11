"""Config loading, and the safety properties encoded in the schema."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from safereach.config import HostConfig, load_command_spec, load_settings
from safereach.versioning import fingerprint

MINIMAL = """\
defaults:
  known_hosts: ~/.ssh/known_hosts
hosts:
  web-01:
    hostname: 10.0.1.5
    user: diag
    key: ~/.ssh/id_ed25519_diag
    description: prod web
    allow: [df, journalctl]
    curl_targets: [localhost]
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "hosts.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_loads_minimal_config(tmp_path: Path) -> None:
    settings = load_settings(_write(tmp_path, MINIMAL))
    host = settings.host("web-01")
    assert host.alias == "web-01"
    assert host.hostname == "10.0.1.5"
    assert host.allow == ["df", "journalctl"]


def test_unknown_host_lists_the_known_ones(tmp_path: Path) -> None:
    settings = load_settings(_write(tmp_path, MINIMAL))
    with pytest.raises(KeyError, match="web-01"):
        settings.host("nope")


def test_typos_are_rejected_not_ignored(tmp_path: Path) -> None:
    """extra='forbid' — a silently ignored `allowed:` would quietly widen access."""
    body = MINIMAL.replace("allow: [df, journalctl]", "allowe: [df, journalctl]")
    with pytest.raises(ValidationError):
        load_settings(_write(tmp_path, body))


@pytest.mark.parametrize("value", ["none", "null", "false", "", "None", "NULL"])
def test_disabling_host_key_checking_is_refused(value: str) -> None:
    """asyncssh reads known_hosts=None as 'trust anything'. There is no valid use."""
    with pytest.raises(ValidationError, match="known_hosts"):
        HostConfig(hostname="h", user="u", key="~/.ssh/k", known_hosts=value)


def test_public_view_hides_infrastructure(tmp_path: Path) -> None:
    """The agent must never learn hostnames, usernames, ports or key paths."""
    settings = load_settings(_write(tmp_path, MINIMAL))
    view = settings.host("web-01").public_view()

    rendered = repr(view)
    assert "10.0.1.5" not in rendered
    assert "diag" not in rendered
    assert "id_ed25519" not in rendered
    assert view["alias"] == "web-01"
    assert view["description"] == "prod web"
    assert view["allowed_commands"] == ["df", "journalctl"]


def test_defaults_are_safe(tmp_path: Path) -> None:
    settings = load_settings(_write(tmp_path, MINIMAL))
    host = settings.host("web-01")
    # Both capabilities are off unless a host grants them.
    assert host.docker_host is None
    assert host.elevated == []
    assert host.env_allowlist == []
    # And a host with no shim is refused rather than silently downgraded.
    assert settings.defaults.require_shim is True


def test_curl_targets_default_empty(tmp_path: Path) -> None:
    body = MINIMAL.replace("    curl_targets: [localhost]\n", "")
    settings = load_settings(_write(tmp_path, body))
    assert settings.host("web-01").curl_targets == []


def test_env_var_config_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write(tmp_path, MINIMAL)
    monkeypatch.setenv("SAFEREACH_CONFIG", str(path))
    assert load_settings().source_path == path


def test_missing_config_names_where_it_looked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SAFEREACH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("safereach.config.DEFAULT_CONFIG_PATH", tmp_path / "absent.yaml")
    with pytest.raises(FileNotFoundError, match="safereach init"):
        load_settings()


def test_command_spec_loads_and_fingerprints_stably() -> None:
    spec = load_command_spec()
    assert "journalctl" in spec and "docker" in spec and "curl" in spec
    assert fingerprint(spec) == fingerprint(spec)
    assert len(fingerprint(spec)) == 12


def test_fingerprint_changes_when_spec_changes() -> None:
    """This is what makes a drifted host detectable."""
    spec = load_command_spec()
    before = fingerprint(spec)
    mutated = {**spec, "newtool": {"description": "x", "positionals": {"max": 0}}}
    assert fingerprint(mutated) != before


def test_version_is_derived_not_duplicated() -> None:
    """__version__ must come from package metadata, not a literal.

    A hard-coded copy drifts: 0.1.1 shipped reporting 0.1.0, and since `install` pins
    agents to __version__, it would have wired every agent to the previous release.
    """
    import tomllib
    from pathlib import Path

    from safereach import __version__

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]

    assert __version__ == declared, (
        f"__version__ is {__version__!r} but pyproject.toml says {declared!r}.\n\n"
        "If you just bumped the version, the installed metadata is stale — run\n"
        "    uv pip install -e '.[dev]'\n"
        "and re-run. In CI the install always follows the checkout, so a failure there\n"
        "means the two really have drifted, and the package would report and pin the\n"
        "wrong version."
    )


def test_agent_registration_pins_the_running_version() -> None:
    """`install` writes `uvx safereach@<version>`; it must be the version in use."""
    from safereach import __version__
    from safereach.install.adapters import resolve_command

    spec = resolve_command(mode="uvx", version=__version__)
    assert spec.args == [f"safereach@{__version__}"]


# --------------------------------------------------------------------------------------
# defaults.production — the weaker modes become a startup error
# --------------------------------------------------------------------------------------

HARDENED = """\
defaults:
  production: true
hosts:
  web-01:
    hostname: 10.0.1.5
    user: diag
    key: ~/.ssh/id_ed25519_diag
    allow: [df]
"""


def test_production_accepts_a_hardened_explicit_host(tmp_path: Path) -> None:
    settings = load_settings(_write(tmp_path, HARDENED))
    assert settings.defaults.production is True
    assert settings.host("web-01").shim_required(settings.defaults)


def test_production_refuses_client_only_mode(tmp_path: Path) -> None:
    body = HARDENED.replace("    allow: [df]\n", "    allow: [df]\n    require_shim: false\n")
    with pytest.raises(ValueError, match="require_shim is false"):
        load_settings(_write(tmp_path, body))


def test_production_refuses_a_global_require_shim_false(tmp_path: Path) -> None:
    body = HARDENED.replace("  production: true\n", "  production: true\n  require_shim: false\n")
    with pytest.raises(ValueError, match="require_shim is false"):
        load_settings(_write(tmp_path, body))


def test_production_refuses_ssh_config_hosts(tmp_path: Path) -> None:
    """A ~/.ssh/config host connects as the operator's own account."""
    body = HARDENED.replace(
        "    hostname: 10.0.1.5\n    user: diag\n    key: ~/.ssh/id_ed25519_diag\n",
        "    ssh_config_host: web-01\n",
    )
    with pytest.raises(ValueError, match="ssh/config"):
        load_settings(_write(tmp_path, body))


def test_production_is_off_by_default_so_discover_configs_still_load(tmp_path: Path) -> None:
    body = MINIMAL + "  lab:\n    ssh_config_host: lab\n    require_shim: false\n"
    settings = load_settings(_write(tmp_path, body))
    assert settings.defaults.production is False
    assert "lab" in settings.hosts
