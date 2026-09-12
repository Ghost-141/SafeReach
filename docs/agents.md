# Connecting agents

`safereach install` registers the MCP server with the coding agents on this machine so
each of them can reach your enrolled hosts. The README's
[Connecting your agents](../README.md#connecting-your-agents) has the short version.

## Supported agents, and how each is found

| Agent | Detected by | Registered by |
|---|---|---|
| Claude Code | `claude` on `PATH` | `claude mcp add safereach --scope user -- <command>` |
| Claude Desktop | its config file or directory | entry under `mcpServers` in `claude_desktop_config.json` (Linux `~/.config/Claude/`, macOS `~/Library/Application Support/Claude/`, Windows `%APPDATA%\Claude\`) |
| Codex CLI | `~/.codex/` | entry under `mcp_servers` in `~/.codex/config.toml` |
| Cursor | `~/.cursor/` | entry under `mcpServers` in `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/` | entry under `mcpServers` in `~/.codeium/windsurf/mcp_config.json` |
| VS Code / Copilot | `code` on `PATH` | `code --add-mcp '{...}'` |
| Zed | `~/.config/zed/` | entry under `context_servers` in `settings.json` — not `mcpServers` |
| Gemini CLI | `~/.gemini/` | entry under `mcpServers` in `~/.gemini/settings.json` |

Detection is deliberately generous: a present config *directory* counts, so an agent you
installed but have not yet configured is still picked up. It is also deliberately local:
it looks in your home directory and your `PATH`, so an agent installed for another user
is invisible.

## What gets written

The same registration everywhere, rendered per agent:

```json
{ "command": "uvx", "args": ["safereach@0.3.0"] }
```

For file-based agents the entry is **merged** into the existing config: the file is read,
a timestamped backup is written next to it, safereach's entry is added or replaced under
that agent's key, and everything else in the file — your other MCP servers, your other
settings — is written back unchanged. Two agents have shapes that are easy to get wrong
and fail silently, VS Code's `servers` and Zed's `context_servers`, which is why each has
its own adapter rather than a shared template.

Re-running `install` is idempotent. `safereach uninstall` removes only safereach's entry
and leaves the rest of the file alone.

## Options

```bash
safereach install --list                # detect and show, change nothing
safereach install                       # every detected agent
safereach install codex zed             # only these, detected or not
safereach install --launcher script     # the installed console script instead of uvx
safereach --config ~/ops/hosts.yaml install   # register with a specific hosts.yaml
safereach install --unpinned            # register bare `uvx safereach` — not recommended
```

**The pin.** `install` registers `uvx safereach@<the version that is running>`. Bare
`uvx safereach` would refetch the newest release from PyPI on every launch, which for a
tool holding production SSH keys is a standing supply-chain exposure on the one component
whose job is to be a security boundary. Upgrades are therefore deliberate: install the
new version, run `install` again, and the agents move. See
[Upgrading](../README.md#upgrading).

**Launchers.** `--launcher auto` (the default) picks `uvx` when it is on `PATH`, because
it is the one form that works identically in every agent and does not depend on a
virtualenv path that only exists on the machine that created it. `--launcher script`
registers the `safereach` console script instead — the one on `PATH` from a
`uv tool install` or `pipx` install, or failing that `python -m safereach` from the
current interpreter, which is what a source checkout needs. `--launcher uvx` forces
`uvx` even when `auto` would not have chosen it.

## When an agent is not listed

Name it anyway: `safereach install cursor` writes the entry whether or not the directory
exists. If the agent keeps its config somewhere this tool does not know, the JSON above is
all it needs — put it under the agent's MCP servers key by hand, and it will launch the
same pinned command.
