"""Per-agent MCP registration.

Every agent wants the same information — a command and its arguments — in a slightly
different place and under a slightly different key. So this is one canonical server spec
plus a thin adapter per agent, and adding an agent is a table entry rather than code.

Two shape exceptions are easy to get wrong and fail silently: VS Code uses ``servers``
rather than ``mcpServers``, and Zed uses ``context_servers``.

The rule that matters most here: these files hold the user's *other* MCP servers.
Clobbering them would be the worst thing this tool could do on first run, so every write
merges into existing content, backs the file up first, and is idempotent.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["ADAPTERS", "Adapter", "ServerSpec", "detect_all"]

SERVER_KEY = "safereach"


@dataclass(frozen=True)
class ServerSpec:
    """The canonical registration, rendered per agent."""

    command: str = "safereach"
    args: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"command": self.command}
        if self.args:
            out["args"] = list(self.args)
        return out


@dataclass(frozen=True)
class Adapter:
    name: str
    label: str
    kind: str  # "json" | "toml" | "command"
    root_key: str = "mcpServers"
    path_factory: Callable[[], Path | None] | None = None
    probe: Callable[[], bool] | None = None
    install_cmd: Callable[[ServerSpec], list[str]] | None = None
    uninstall_cmd: Callable[[], list[str]] | None = None

    def config_path(self) -> Path | None:
        return self.path_factory() if self.path_factory else None

    def detected(self) -> bool:
        if self.probe is not None:
            return self.probe()
        path = self.config_path()
        # A present parent directory is the signal: the agent is installed even if it
        # has never written a config yet.
        return bool(path and (path.exists() or path.parent.is_dir()))


# --------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------


def _home() -> Path:
    return Path.home()


def _xdg_config() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", _home() / ".config"))


def _claude_desktop_path() -> Path:
    system = platform.system()
    if system == "Darwin":
        return _home() / "Library/Application Support/Claude/claude_desktop_config.json"
    if system == "Windows":
        base = os.environ.get("APPDATA", str(_home() / "AppData/Roaming"))
        return Path(base) / "Claude/claude_desktop_config.json"
    return _xdg_config() / "Claude/claude_desktop_config.json"


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


# --------------------------------------------------------------------------------------
# The table
# --------------------------------------------------------------------------------------

ADAPTERS: dict[str, Adapter] = {
    "claude-code": Adapter(
        name="claude-code",
        label="Claude Code",
        kind="command",
        probe=lambda: _has("claude"),
        install_cmd=lambda spec: [
            "claude",
            "mcp",
            "add",
            SERVER_KEY,
            "--scope",
            "user",
            "--",
            spec.command,
            *spec.args,
        ],
        uninstall_cmd=lambda: ["claude", "mcp", "remove", SERVER_KEY, "--scope", "user"],
    ),
    "claude-desktop": Adapter(
        name="claude-desktop",
        label="Claude Desktop",
        kind="json",
        root_key="mcpServers",
        path_factory=_claude_desktop_path,
    ),
    "codex": Adapter(
        name="codex",
        label="Codex CLI",
        kind="toml",
        root_key="mcp_servers",
        path_factory=lambda: _home() / ".codex" / "config.toml",
    ),
    "cursor": Adapter(
        name="cursor",
        label="Cursor",
        kind="json",
        root_key="mcpServers",
        path_factory=lambda: _home() / ".cursor" / "mcp.json",
    ),
    "windsurf": Adapter(
        name="windsurf",
        label="Windsurf",
        kind="json",
        root_key="mcpServers",
        path_factory=lambda: _home() / ".codeium" / "windsurf" / "mcp_config.json",
    ),
    "vscode": Adapter(
        name="vscode",
        label="VS Code / Copilot",
        kind="command",
        probe=lambda: _has("code"),
        install_cmd=lambda spec: [
            "code",
            "--add-mcp",
            json.dumps({"name": SERVER_KEY, **spec.as_dict()}),
        ],
    ),
    "zed": Adapter(
        name="zed",
        label="Zed",
        kind="json",
        root_key="context_servers",  # not mcpServers
        path_factory=lambda: _xdg_config() / "zed" / "settings.json",
    ),
    "gemini": Adapter(
        name="gemini",
        label="Gemini CLI",
        kind="json",
        root_key="mcpServers",
        path_factory=lambda: _home() / ".gemini" / "settings.json",
    ),
}


def detect_all() -> list[Adapter]:
    return [a for a in ADAPTERS.values() if a.detected()]


# --------------------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------------------


def backup(path: Path) -> Path | None:
    if not path.is_file():
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = path.with_suffix(path.suffix + f".bak-{stamp}")
    shutil.copy2(path, dest)
    return dest


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{path} is not valid JSON ({exc}). Refusing to overwrite it — "
            "fix or move the file and re-run."
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{path}: expected a JSON object at the top level")
    return data


def apply_json(path: Path, root_key: str, spec: ServerSpec, remove: bool = False) -> str:
    data = _load_json(path)
    servers = data.get(root_key)
    if servers is None:
        servers = {}
    if not isinstance(servers, dict):
        raise RuntimeError(f"{path}: '{root_key}' exists but is not an object")

    if remove:
        if SERVER_KEY not in servers:
            return "not present"
        servers.pop(SERVER_KEY)
        action = "removed"
    else:
        entry = spec.as_dict()
        if servers.get(SERVER_KEY) == entry:
            return "already up to date"
        action = "updated" if SERVER_KEY in servers else "added"
        servers[SERVER_KEY] = entry

    data[root_key] = servers
    backup(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return action


_TOML_SECTION_RE_TEMPLATE = r"^\[{key}\.{name}\]\n(?:(?!^\[).*\n?)*"


def apply_toml(path: Path, root_key: str, spec: ServerSpec, remove: bool = False) -> str:
    """Edit only our own section, leaving the rest of the file byte-for-byte intact.

    Round-tripping TOML through a parser and serialiser would discard the user's comments
    and formatting, and there is no comment-preserving TOML writer in the standard
    library. Targeted text replacement of a single section avoids the problem entirely.
    """
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    pattern = re.compile(
        _TOML_SECTION_RE_TEMPLATE.format(key=re.escape(root_key), name=re.escape(SERVER_KEY)),
        re.MULTILINE,
    )

    if remove:
        new_text, n = pattern.subn("", text)
        if not n:
            return "not present"
        backup(path)
        path.write_text(new_text, encoding="utf-8")
        return "removed"

    args_toml = ", ".join(json.dumps(a) for a in spec.args)
    section = (
        f"[{root_key}.{SERVER_KEY}]\ncommand = {json.dumps(spec.command)}\nargs = [{args_toml}]\n"
    )

    if pattern.search(text):
        new_text, _ = pattern.subn(section, text, count=1)
        action = "updated"
    else:
        sep = "" if not text or text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
        new_text = text + sep + section
        action = "added"

    if new_text == text:
        return "already up to date"

    backup(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_text, encoding="utf-8")
    return action


def apply_command(adapter: Adapter, spec: ServerSpec, remove: bool = False) -> str:
    builder = adapter.uninstall_cmd if remove else adapter.install_cmd
    if builder is None:
        return "unsupported"

    if not remove and adapter.uninstall_cmd is not None:
        # These CLIs refuse to overwrite an existing entry, so a re-install reports
        # "already exists" and silently keeps the OLD command — which is wrong after a
        # rename or a launcher change. The JSON adapters update in place; this gives the
        # command adapters the same behaviour.
        subprocess.run(
            adapter.uninstall_cmd(),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    cmd = builder() if remove else builder(spec)  # type: ignore[operator]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except FileNotFoundError:
        return f"skipped ({cmd[0]} not found)"
    except subprocess.TimeoutExpired:
        return "timed out"
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return f"failed: {detail[-1] if detail else proc.returncode}"
    return "removed" if remove else "registered"


def apply(adapter: Adapter, spec: ServerSpec, remove: bool = False) -> str:
    if adapter.kind == "command":
        return apply_command(adapter, spec, remove)
    path = adapter.config_path()
    if path is None:
        return "unsupported"
    if adapter.kind == "json":
        return apply_json(path, adapter.root_key, spec, remove)
    if adapter.kind == "toml":
        return apply_toml(path, adapter.root_key, spec, remove)
    raise ValueError(f"unknown adapter kind {adapter.kind!r}")


PACKAGE = "safereach"


def resolve_command(mode: str = "auto", version: str | None = None) -> ServerSpec:
    """How the agent should launch the server.

    ``uvx`` is the default because it is the one form that works identically for every
    agent — Claude Code, Codex, Cursor, Windsurf, Zed, Gemini — without depending on a
    venv path that only exists on the machine where it was created. A registration
    pointing at ``/home/you/proj/.venv/bin/...`` breaks the moment anything moves.

    **The version is always pinned.** Bare ``uvx safereach`` refetches from PyPI on
    every launch, which for a tool holding production SSH keys is a standing
    supply-chain exposure on the component whose whole job is being a security boundary.
    Pinning keeps the convenience without the exposure; upgrades stay deliberate.
    """
    if mode == "uvx" or (mode == "auto" and shutil.which("uvx")):
        pinned = f"{PACKAGE}@{version}" if version else PACKAGE
        return ServerSpec(command="uvx", args=[pinned])
    found = shutil.which("safereach")
    if found:
        return ServerSpec(command=found)
    return ServerSpec(command=sys.executable, args=["-m", "safereach"])
