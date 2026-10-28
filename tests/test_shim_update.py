"""Updating the shim on an already-enrolled host — the 0.5.0 upgrade that left hosts stale.

0.5.0 changed the shim fingerprint, so every host had to be updated, and the agent then
refused all of them. The documented paths did not work on plain hosts resolved through
~/.ssh/config: `shim-update` connected to `user@None` and only knew the hardened
/usr/local/bin location, `doctor --fix` assumed the hosts.yaml key was an ssh alias, and
the MCP server cached the stale answer so a fixed host stayed refused until restart.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from safereach import cli, server
from safereach.config import HostConfig, Settings

NEW = "newfingerprint"
OLD = "1c88f2640482"


@pytest.fixture
def plain_host() -> HostConfig:
    # Exactly the shape `enroll` writes for a host in ~/.ssh/config: no hostname at all.
    return HostConfig(alias="synapse-main", ssh_config_host="synapse-main", key="/tmp/k")


@pytest.fixture
def settings(plain_host: HostConfig) -> Settings:
    return Settings(hosts={"synapse-main": plain_host})


@pytest.fixture
def shim(tmp_path: Path) -> Path:
    path = tmp_path / "safereach-shim"
    path.write_bytes(b"#!/usr/bin/env python3\n# new shim\n")
    return path


def _args(**kw: object) -> argparse.Namespace:
    return argparse.Namespace(**{"via": None, "admin_user": "ops", **kw})


class FakeSSH:
    """Stands in for subprocess.run; records what would have gone to the host."""

    def __init__(self, stdout: str = "UPDATED= user\n", code: int = 0) -> None:
        self.calls: list[tuple[list[str], bytes | None]] = []
        self.stdout, self.code = stdout, code

    def __call__(self, argv: list[str], **kw: object) -> subprocess.CompletedProcess:
        self.calls.append((list(argv), kw.get("input")))  # type: ignore[arg-type]
        return subprocess.CompletedProcess(argv, self.code, self.stdout.encode(), b"boom")


def test_plain_ssh_config_host_is_reached_by_its_alias_not_user_at_none(
    monkeypatch: pytest.MonkeyPatch, plain_host: HostConfig, settings: Settings, shim: Path
) -> None:
    fake = FakeSSH()
    monkeypatch.setattr(cli.subprocess, "run", fake)
    monkeypatch.setattr(cli, "_probe_one", lambda *a: _done((NEW, 0)))

    ok, detail = cli._update_shim(plain_host, settings, _args(), shim, NEW)

    assert ok, detail
    argv, sent = fake.calls[0]
    assert "synapse-main" in argv
    assert not any("None" in a for a in argv)
    assert sent == shim.read_bytes()
    assert "$HOME/.local/bin/safereach-shim" in argv[-1]
    assert "verified with the enrolled key" in detail


def test_update_is_not_reported_until_the_enrolled_key_agrees(
    monkeypatch: pytest.MonkeyPatch, plain_host: HostConfig, settings: Settings, shim: Path
) -> None:
    monkeypatch.setattr(cli.subprocess, "run", FakeSSH(stdout="UPDATED= root\nROOT_NEEDS_SUDO=1\n"))
    monkeypatch.setattr(cli, "_probe_one", lambda *a: _done((OLD, 0)))

    ok, detail = cli._update_shim(plain_host, settings, _args(), shim, NEW)

    assert not ok
    assert OLD in detail and NEW in detail


def test_host_with_no_shim_is_told_to_enrol(
    monkeypatch: pytest.MonkeyPatch, plain_host: HostConfig, settings: Settings, shim: Path
) -> None:
    monkeypatch.setattr(cli.subprocess, "run", FakeSSH(stdout="UPDATED=\n"))
    ok, detail = cli._update_shim(plain_host, settings, _args(), shim, NEW)
    assert not ok and "enroll synapse-main" in detail


def test_unreachable_admin_route_is_reported(
    monkeypatch: pytest.MonkeyPatch, plain_host: HostConfig, settings: Settings, shim: Path
) -> None:
    monkeypatch.setattr(cli.subprocess, "run", FakeSSH(stdout="", code=255))
    ok, detail = cli._update_shim(plain_host, settings, _args(), shim, NEW)
    assert not ok and "administrator" in detail


def test_via_overrides_the_route(
    monkeypatch: pytest.MonkeyPatch, plain_host: HostConfig, settings: Settings, shim: Path
) -> None:
    fake = FakeSSH()
    monkeypatch.setattr(cli.subprocess, "run", fake)
    monkeypatch.setattr(cli, "_probe_one", lambda *a: _done((NEW, 0)))
    cli._update_shim(plain_host, settings, _args(via="admin-box"), shim, NEW)
    assert "admin-box" in fake.calls[0][0]


def test_update_script_replaces_the_plain_shim_for_real(tmp_path: Path) -> None:
    """Run the remote script itself, as the host would, against a fake home."""
    if Path("/usr/local/bin/safereach-shim").exists():
        pytest.skip("this machine has a root-owned shim; the script would try to update it")
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    old = home / ".local" / "bin" / "safereach-shim"
    old.write_text("old shim\n")
    proc = subprocess.run(
        ["bash", "-c", cli.SHIM_UPDATE_SCRIPT],
        input=b"new shim\n",
        capture_output=True,
        env={"HOME": str(home), "PATH": os.environ["PATH"]},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert old.read_text() == "new shim\n"
    assert os.access(old, os.X_OK)
    assert "UPDATED= user" in proc.stdout.decode()


def test_shim_update_command_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, shim: Path
) -> None:
    config = tmp_path / "hosts.yaml"
    config.write_text(
        "hosts:\n  synapse-main:\n    ssh_config_host: synapse-main\n    key: /tmp/k\n"
    )
    monkeypatch.setattr(cli, "_build_shim", lambda: (shim, NEW))
    monkeypatch.setattr(cli.subprocess, "run", FakeSSH())
    monkeypatch.setattr(cli, "_probe_one", lambda *a: _done((NEW, 0)))
    args = cli.build_parser().parse_args(["--config", str(config), "shim-update", "--all"])
    assert args.func(args) == 0


def test_doctor_fix_repairs_only_stale_hosts(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, shim: Path
) -> None:
    other = HostConfig(alias="db-1", ssh_config_host="db-1", key="/tmp/k")
    settings.hosts["db-1"] = other
    rows = [
        (cli.BAD, "synapse-main", f"shim {OLD} != expected {NEW} — run `doctor --fix`"),
        (cli.OK, "db-1", f"reachable, shim {NEW}"),
    ]
    monkeypatch.setattr(cli, "_build_shim", lambda: (shim, NEW))
    updated: list[str] = []

    def fake_update(host, settings_, args, path, expected):  # noqa: ANN001, ANN202
        updated.append(host.alias)
        return True, f"updated to {expected}"

    monkeypatch.setattr(cli, "_update_shim", fake_update)
    fixed = cli._fix_stale(rows, settings, _args(), NEW)
    assert updated == ["synapse-main"]
    assert fixed[0][0] == cli.OK and fixed[1] == rows[1]


def test_server_forgets_a_stale_shim_so_a_fixed_host_works_without_restart(
    plain_host: HostConfig, settings: Settings
) -> None:
    answers = iter([(OLD, 0), (NEW, 0)])

    async def shim_probe(_host: HostConfig) -> tuple[str, int]:
        return next(answers)

    app = SimpleNamespace(
        shim_versions={},
        expected_fingerprint=NEW,
        settings=settings,
        pool=SimpleNamespace(shim_probe=shim_probe),
    )
    with pytest.raises(ToolError, match="shim-update synapse-main"):
        asyncio.run(server._ensure_shim(app, plain_host))
    assert "synapse-main" not in app.shim_versions
    asyncio.run(server._ensure_shim(app, plain_host))  # the host was fixed meanwhile
    assert app.shim_versions["synapse-main"] == NEW


async def _coro(value: object) -> object:
    return value


def _done(value: object) -> object:
    """A coroutine for code that passes `_probe_one(...)` to asyncio.run."""
    return _coro(value)
