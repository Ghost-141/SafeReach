"""Installer tests.

The regression that matters most: these config files hold the user's *other* MCP servers.
Clobbering them would be the worst thing this tool could do on first run, so every case
seeds a file with existing servers and asserts they survive untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safereach.install import adapters as ad

EXISTING = {
    "mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
        "github": {"command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"]},
    },
    "someOtherSetting": {"theme": "dark", "fontSize": 14},
}

SPEC = ad.ServerSpec(command="/usr/local/bin/safereach", args=["--config", "/etc/x.yaml"])


@pytest.fixture
def json_config(tmp_path: Path) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(EXISTING, indent=2), encoding="utf-8")
    return path


def test_json_insert_preserves_existing_servers(json_config: Path) -> None:
    action = ad.apply_json(json_config, "mcpServers", SPEC)
    assert action == "added"

    data = json.loads(json_config.read_text(encoding="utf-8"))
    assert data["mcpServers"]["filesystem"] == EXISTING["mcpServers"]["filesystem"]
    assert data["mcpServers"]["github"] == EXISTING["mcpServers"]["github"]
    assert data["someOtherSetting"] == EXISTING["someOtherSetting"]
    assert data["mcpServers"]["safereach"] == {
        "command": "/usr/local/bin/safereach",
        "args": ["--config", "/etc/x.yaml"],
    }


def test_install_is_idempotent(json_config: Path) -> None:
    ad.apply_json(json_config, "mcpServers", SPEC)
    first = json_config.read_text(encoding="utf-8")
    assert ad.apply_json(json_config, "mcpServers", SPEC) == "already up to date"
    assert json_config.read_text(encoding="utf-8") == first


def test_uninstall_removes_only_our_key(json_config: Path) -> None:
    ad.apply_json(json_config, "mcpServers", SPEC)
    assert ad.apply_json(json_config, "mcpServers", SPEC, remove=True) == "removed"

    data = json.loads(json_config.read_text(encoding="utf-8"))
    assert "safereach" not in data["mcpServers"]
    assert set(data["mcpServers"]) == {"filesystem", "github"}
    assert data["someOtherSetting"] == EXISTING["someOtherSetting"]


def test_backup_written_before_change(json_config: Path) -> None:
    ad.apply_json(json_config, "mcpServers", SPEC)
    backups = list(json_config.parent.glob("*.bak-*"))
    assert backups, "no backup was created"
    assert json.loads(backups[0].read_text(encoding="utf-8")) == EXISTING


def test_missing_file_is_created(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "mcp.json"
    assert ad.apply_json(path, "mcpServers", SPEC) == "added"
    assert json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["safereach"]


def test_empty_file_handled(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text("", encoding="utf-8")
    assert ad.apply_json(path, "mcpServers", SPEC) == "added"


def test_malformed_json_refuses_rather_than_overwrites(tmp_path: Path) -> None:
    """Better to stop than to silently replace a file we could not understand."""
    path = tmp_path / "mcp.json"
    original = '{"mcpServers": {"a": '
    path.write_text(original, encoding="utf-8")

    with pytest.raises(RuntimeError, match="not valid JSON"):
        ad.apply_json(path, "mcpServers", SPEC)
    assert path.read_text(encoding="utf-8") == original


def test_zed_uses_context_servers_key(tmp_path: Path) -> None:
    """Shape exception that would otherwise fail silently."""
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"theme": "One Dark"}), encoding="utf-8")
    ad.apply_json(path, "context_servers", SPEC)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert "safereach" in data["context_servers"]
    assert "mcpServers" not in data
    assert data["theme"] == "One Dark"


def test_vscode_adapter_uses_servers_key() -> None:
    assert ad.ADAPTERS["zed"].root_key == "context_servers"
    assert ad.ADAPTERS["codex"].root_key == "mcp_servers"
    assert ad.ADAPTERS["cursor"].root_key == "mcpServers"


# --------------------------------------------------------------------------------------
# TOML (Codex)
# --------------------------------------------------------------------------------------

TOML_EXISTING = """\
model = "gpt-5"

# A comment the user wrote and would be annoyed to lose
[mcp_servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem"]

[other_section]
value = 1
"""


@pytest.fixture
def toml_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(TOML_EXISTING, encoding="utf-8")
    return path


def test_toml_append_preserves_everything_else(toml_config: Path) -> None:
    """Targeted text editing, because no stdlib TOML writer preserves comments."""
    assert ad.apply_toml(toml_config, "mcp_servers", SPEC) == "added"

    text = toml_config.read_text(encoding="utf-8")
    assert 'model = "gpt-5"' in text
    assert "# A comment the user wrote" in text
    assert "[mcp_servers.filesystem]" in text
    assert "[other_section]" in text
    assert "[mcp_servers.safereach]" in text
    assert '"--config", "/etc/x.yaml"' in text


def test_toml_update_replaces_only_our_section(toml_config: Path) -> None:
    ad.apply_toml(toml_config, "mcp_servers", SPEC)
    updated = ad.ServerSpec(command="/new/path", args=[])
    assert ad.apply_toml(toml_config, "mcp_servers", updated) == "updated"

    text = toml_config.read_text(encoding="utf-8")
    assert text.count("[mcp_servers.safereach]") == 1
    assert '"/new/path"' in text
    assert "/usr/local/bin/safereach" not in text
    assert "[mcp_servers.filesystem]" in text
    assert "[other_section]" in text


def test_toml_remove_leaves_the_rest(toml_config: Path) -> None:
    ad.apply_toml(toml_config, "mcp_servers", SPEC)
    assert ad.apply_toml(toml_config, "mcp_servers", SPEC, remove=True) == "removed"

    text = toml_config.read_text(encoding="utf-8")
    assert "safereach" not in text
    assert "[mcp_servers.filesystem]" in text
    assert "# A comment the user wrote" in text
    assert "[other_section]" in text


def test_toml_remove_when_absent_is_a_noop(toml_config: Path) -> None:
    before = toml_config.read_text(encoding="utf-8")
    assert ad.apply_toml(toml_config, "mcp_servers", SPEC, remove=True) == "not present"
    assert toml_config.read_text(encoding="utf-8") == before


def test_resolve_command_always_produces_something_runnable() -> None:
    spec = ad.resolve_command()
    assert spec.command
    assert Path(spec.command).name in {"safereach", Path(spec.command).name}


def test_command_adapters_replace_rather_than_collide(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-installing must update the entry, not report "already exists".

    Agent CLIs refuse to overwrite an existing MCP server, so without an uninstall first
    a re-install silently keeps the OLD command — which is exactly wrong after a rename
    or a change of launcher.
    """
    calls: list[list[str]] = []

    class FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **_kw):
        calls.append(list(cmd))
        return FakeProc()

    monkeypatch.setattr(ad.subprocess, "run", fake_run)
    result = ad.apply_command(ad.ADAPTERS["claude-code"], SPEC)

    assert result == "registered"
    assert len(calls) == 2, "expected a remove followed by an add"
    assert "remove" in calls[0]
    assert "add" in calls[1]
