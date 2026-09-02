"""The MCP server: seven tools over a validated SSH transport.

Two SDK behaviours shape everything here, both changed in ``mcp`` v2:

* **Only :class:`ToolError` messages reach the model.** Every other exception is
  sanitised to an opaque ``-32603``. So every rejection has to be raised as a
  ``ToolError`` carrying its reason and a legal alternative, or the agent gets a blank
  failure and cannot self-correct. Conversely, raw ``asyncssh`` exceptions must never
  escape — they can carry hostnames and key paths.
* **Input schemas are advertised but not enforced by the SDK.** Argument validation is
  this module's job, not the framework's.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field, create_model

from .audit import AuditLog
from .config import HostConfig, Settings, load_command_spec, load_settings
from .redact import redact_docker_inspect, redact_text
from .ssh import ExecResult, SSHError, SSHPool
from .validator import Rejected, render, spec_summary, validate
from .versioning import fingerprint

log = logging.getLogger("safereach")

# Stdout is the JSON-RPC channel. A single stray print corrupts the protocol and the
# agent sees an opaque parse failure, so all diagnostics go to stderr — set up here
# rather than in main() so importing this module can never install a stdout handler.
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


# --------------------------------------------------------------------------------------
# Result models — the SDK derives tool output schemas from these
# --------------------------------------------------------------------------------------


class CommandResult(BaseModel):
    host: str
    command: str = Field(description="The reassembled string actually executed")
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    duration_ms: int


class HostResult(BaseModel):
    """One host's outcome inside a fan-out. Errors are values here, not exceptions —
    one unreachable host must not discard the results from every other host."""

    host: str
    ok: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    truncated: bool = False
    duration_ms: int | None = None


class HostStatus(BaseModel):
    host: str
    status: str = Field(description="ok | unreachable | shim-stale | shim-missing")
    detail: str = ""
    shim_version: str | None = None


# --------------------------------------------------------------------------------------
# Lifespan
# --------------------------------------------------------------------------------------


@dataclass
class AppContext:
    settings: Settings
    spec: dict[str, Any]
    pool: SSHPool
    audit: AuditLog
    expected_fingerprint: str
    #: alias -> verified shim version, populated lazily on first use per host.
    shim_versions: dict[str, str | None]
    #: The host the user picked when asked. Remembered for the session so a multi-step
    #: investigation does not re-prompt on every single command.
    selected_host: str | None = None


@asynccontextmanager
async def app_lifespan(_server: MCPServer) -> AsyncIterator[AppContext]:
    settings = load_settings(_config_override())
    spec = load_command_spec()
    pool = SSHPool(settings.defaults)
    ctx = AppContext(
        settings=settings,
        spec=spec,
        pool=pool,
        audit=AuditLog(settings.audit_path()),
        expected_fingerprint=fingerprint(spec),
        shim_versions={},
    )
    log.info(
        "loaded %d host(s) from %s; spec fingerprint %s",
        len(settings.hosts),
        settings.source_path,
        ctx.expected_fingerprint,
    )
    try:
        yield ctx
    finally:
        await pool.close()


def _config_override() -> Path | None:
    """Support `safereach --config PATH` without argparse fighting the SDK."""
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg == "--config" and i + 1 < len(argv):
            return Path(argv[i + 1]).expanduser()
        if arg.startswith("--config="):
            return Path(arg.split("=", 1)[1]).expanduser()
    return None


mcp = MCPServer("safereach", lifespan=app_lifespan)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _host(app: AppContext, alias: str) -> HostConfig:
    try:
        return app.settings.host(alias)
    except KeyError as exc:
        raise ToolError(str(exc)) from exc


def _host_ctx(host: HostConfig) -> dict[str, Any]:
    return {"curl_targets": list(host.curl_targets)}


async def _resolve_host(app: AppContext, ctx: Context[AppContext], host: str | None) -> HostConfig:
    """Work out which server to act on, asking the user when it is genuinely ambiguous.

    The order matters for how this feels to use. An explicit alias always wins. A single
    configured host needs no question. Otherwise the user is asked once and the answer is
    remembered for the session — asking before every command would make a ten-command
    investigation unbearable.
    """
    if host:
        return _host(app, host)

    aliases = list(app.settings.hosts)
    if not aliases:
        raise ToolError(
            "No hosts are configured. Run `safereach discover` to pick up the servers "
            "in your ~/.ssh/config, then restart this server."
        )
    if len(aliases) == 1:
        return app.settings.hosts[aliases[0]]
    if app.selected_host in app.settings.hosts:
        return app.settings.hosts[app.selected_host]

    chosen = await _ask_which_host(app, ctx, aliases)
    app.selected_host = chosen
    return app.settings.hosts[chosen]


async def _ask_which_host(app: AppContext, ctx: Context[AppContext], aliases: list[str]) -> str:
    """Put the choice to the user through the client's elicitation UI.

    Elicitation is a client capability, and not every client implements it. When it is
    unavailable the fallback is deliberately *not* to guess a host — it is to raise a
    ToolError naming the options, so the agent asks in conversation instead. Either way a
    human chooses; only the mechanism differs.
    """
    labels = {alias: (app.settings.hosts[alias].description or alias) for alias in aliases}
    choice_model = create_model(
        "HostChoice",
        host=(
            Literal[tuple(aliases)],  # type: ignore[valid-type]
            Field(description="Which server to run the diagnostic on"),
        ),
    )
    listing = "\n".join(f"  • {a} — {labels[a]}" for a in aliases)

    try:
        result = await ctx.elicit(
            message=f"Which server should I diagnose?\n{listing}",
            schema=choice_model,
        )
    except Exception as exc:  # noqa: BLE001 - client may not support elicitation at all
        log.info("elicitation unavailable (%s); asking via ToolError", type(exc).__name__)
        raise ToolError(
            "Which server should I use? Ask the user to choose one of these, then call "
            f"this tool again with `host` set:\n{listing}"
        ) from exc

    if result.action != "accept" or result.data is None:
        raise ToolError(
            "No server was selected, so nothing was run. Ask the user which host to use."
        )
    return str(result.data.host)


def _validate_or_raise(app: AppContext, host: HostConfig, command: str) -> list[str]:
    try:
        result = validate(command, app.spec, allow=host.allow or None, ctx=_host_ctx(host))
    except Rejected as rej:
        app.audit.rejected(host=host.alias, host_id=host.id, requested=command, reason=rej.reason)
        # ToolError is the only exception class whose message the model can read.
        raise ToolError(rej.render()) from rej

    if not host.curl_insecure and "-k" in result.argv:
        raise ToolError(
            "Rejected: -k/--insecure disables TLS verification and is not enabled "
            f"for host {host.alias!r}.\n"
            "Set curl_insecure: true for that host in hosts.yaml if this is intended."
        )
    return result.argv


async def _ensure_shim(app: AppContext, host: HostConfig) -> None:
    """Verify the host's shim matches this server's spec before running anything.

    A stale shim is refused rather than warned about. The whole point of the stamp is
    that a host quietly running an older, looser allowlist is indistinguishable from a
    correctly configured one unless something checks.
    """
    if host.alias in app.shim_versions:
        version = app.shim_versions[host.alias]
    else:
        try:
            version = await app.pool.shim_version(host)
        except SSHError as exc:
            raise ToolError(str(exc)) from exc
        app.shim_versions[host.alias] = version

    if version is None:
        if host.shim_required(app.settings.defaults):
            raise ToolError(
                f"Host {host.alias!r} has no safereach-shim installed, so only client-side "
                "validation would apply — which is a usability layer, not a control.\n"
                f"Provision it with: safereach provision {host.alias}\n"
                "Or set defaults.require_shim: false in hosts.yaml to accept this "
                "during an incremental rollout."
            )
        return

    if version != app.expected_fingerprint:
        raise ToolError(
            f"Host {host.alias!r} is running safereach-shim {version}, but this server "
            f"expects {app.expected_fingerprint}. The host's allowlist and this "
            "server's no longer agree, so commands are refused.\n"
            f"Redeploy with: safereach shim-update {host.alias}"
        )


def _postprocess(host: HostConfig, argv: list[str], result: ExecResult) -> ExecResult:
    """Redact output before it reaches the agent (and therefore the transcript)."""
    stdout = result.stdout
    is_inspect = argv[:2] in (["docker", "inspect"],) or argv[:3] in (
        ["docker", "container", "inspect"],
        ["docker", "image", "inspect"],
        ["docker", "network", "inspect"],
    )
    if is_inspect or argv[:3] == ["docker", "compose", "config"]:
        stdout = redact_docker_inspect(stdout, host.env_allowlist)

    return ExecResult(
        exit_code=result.exit_code,
        stdout=redact_text(stdout),
        stderr=redact_text(result.stderr),
        truncated=result.truncated,
        duration_ms=result.duration_ms,
    )


async def _execute(app: AppContext, host: HostConfig, command: str) -> CommandResult:
    argv = _validate_or_raise(app, host, command)
    await _ensure_shim(app, host)
    wire = render(argv)

    # Structured argv when the host runs a shim: the token list goes over the wire as
    # JSON, so the remote side never re-tokenises a string and the two validators cannot
    # disagree about quoting. A host without a shim gets the shell-quoted form, which is
    # all a plain sshd can execute.
    if app.shim_versions.get(host.alias):
        payload = "@run " + json.dumps(argv, separators=(",", ":"))
    else:
        payload = wire

    try:
        raw = await app.pool.run(host, payload)
    except SSHError as exc:
        app.audit.error(host=host.alias, host_id=host.id, requested=command, error=str(exc))
        raise ToolError(str(exc)) from exc

    result = _postprocess(host, argv, raw)
    app.audit.allowed(
        host=host.alias,
        host_id=host.id,
        requested=command,
        executed=wire,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        bytes_out=len(raw.stdout),
        truncated=result.truncated,
    )
    return CommandResult(
        host=host.alias,
        command=wire,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        truncated=result.truncated,
        duration_ms=result.duration_ms,
    )


# --------------------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------------------


@mcp.tool()
def list_hosts(ctx: Context[AppContext]) -> dict[str, Any]:
    """List the servers available for diagnosis.

    Returns each host's alias, description, what it permits, and how hardened it is.
    Hostnames, usernames, ports and key paths are deliberately not included — address
    servers by alias.

    `selected` is the server chosen for this session; when it is null and more than one
    server exists, the user will be asked the first time a command is run.
    """
    app = ctx.request_context.lifespan_context
    hosts = []
    for cfg in app.settings.hosts.values():
        view = cfg.public_view()
        known = app.shim_versions.get(cfg.alias)
        view["security"] = (
            cfg.security_mode(shim_present=bool(known))
            if cfg.alias in app.shim_versions
            else "unverified"
        )
        hosts.append(view)
    return {
        "hosts": hosts,
        "selected": app.selected_host,
        "note": (
            "Omit `host` on run_command to use the selected server, or to have the user "
            "asked if none is selected yet."
        ),
    }


@mcp.tool()
def select_host(ctx: Context[AppContext], host: str) -> str:
    """Choose which server subsequent commands run against for the rest of this session.

    Use this when the user names a server in conversation, so they are not asked again.
    Passing `host` explicitly to `run_command` still overrides this for a single call.
    """
    app = ctx.request_context.lifespan_context
    cfg = _host(app, host)
    app.selected_host = cfg.alias
    return f"Selected {cfg.alias}" + (f" — {cfg.description}" if cfg.description else "")


@mcp.tool()
def describe_commands(ctx: Context[AppContext], host: str | None = None) -> dict[str, Any]:
    """Describe exactly which commands may be run, and with which flags.

    Call this before composing a command. Commands are validated against a strict
    allowlist: unknown binaries, unknown flags, pipes, redirects, subshells and command
    chaining are all refused. Reading this first avoids guessing.

    Pass a host alias to see that host's subset.
    """
    app = ctx.request_context.lifespan_context
    allow: list[str] | None = None
    elevated: list[str] = []
    target = (
        host
        or app.selected_host
        or (next(iter(app.settings.hosts)) if len(app.settings.hosts) == 1 else None)
    )
    if target is not None:
        cfg = _host(app, target)
        allow = cfg.allow or None
        elevated = sorted(cfg.elevated)

    return {
        "commands": spec_summary(app.spec, allow),
        "elevated_recipes": elevated,
        "rules": [
            "One command per call. No pipes, redirects, subshells or ';' chaining.",
            "Only allowlisted binaries, and only their listed flags.",
            "File paths are restricted to the locations shown per command.",
            "Everything is read-only; nothing here can change state.",
            "Use a command's own filtering flags instead of piping to grep, "
            "e.g. `journalctl -u nginx -n 200 --grep error`.",
        ],
    }


@mcp.tool()
async def run_command(
    ctx: Context[AppContext], command: str, host: str | None = None
) -> CommandResult:
    """Run one read-only diagnostic command on a server.

    `command` must be a single command permitted by `describe_commands` — it is validated
    here and again on the remote host before it runs. A rejection explains why and usually
    suggests the legal form.

    `host` is optional. Leave it out and the user will be asked which server to use (or,
    if only one is configured, it is used directly). Pass an alias from `list_hosts` to
    target a specific one.
    """
    app = ctx.request_context.lifespan_context
    return await _execute(app, await _resolve_host(app, ctx, host), command)


@mcp.tool()
async def run_on_hosts(
    ctx: Context[AppContext], hosts: list[str], command: str
) -> list[HostResult]:
    """Run the same command across several hosts concurrently.

    Use this to tell a single-host problem from a fleet-wide one — "is /var full
    everywhere, or just here". A failure on one host is reported in that host's entry
    rather than aborting the others.
    """
    app = ctx.request_context.lifespan_context
    if not hosts:
        raise ToolError("`hosts` must not be empty; call `list_hosts` first.")
    if len(hosts) > 32:
        raise ToolError(f"too many hosts in one call ({len(hosts)} > 32)")

    resolved = [_host(app, alias) for alias in hosts]

    async def one(cfg: HostConfig) -> HostResult:
        try:
            res = await _execute(app, cfg, command)
        except ToolError as exc:
            return HostResult(host=cfg.alias, ok=False, error=str(exc))
        return HostResult(
            host=cfg.alias,
            ok=True,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            truncated=res.truncated,
            duration_ms=res.duration_ms,
        )

    return list(await asyncio.gather(*(one(cfg) for cfg in resolved)))


@mcp.tool()
async def run_elevated(
    ctx: Context[AppContext], recipe: str, host: str | None = None
) -> CommandResult:
    """Run one named privileged diagnostic recipe (e.g. `dmesg-recent`).

    Takes a recipe *name*, never a command line — there is no argument surface. Available
    recipes are listed by `describe_commands` and are defined on the host itself.
    """
    app = ctx.request_context.lifespan_context
    cfg = await _resolve_host(app, ctx, host)

    if recipe not in cfg.elevated:
        available = ", ".join(sorted(cfg.elevated)) or "(none configured)"
        raise ToolError(
            f"{recipe!r} is not an elevated recipe on host {cfg.alias!r}. Available: {available}"
        )
    if not recipe.replace("-", "").replace("_", "").isalnum():
        raise ToolError(f"invalid recipe name {recipe!r}")

    await _ensure_shim(app, cfg)
    wire = f"@elevated {recipe}"
    try:
        raw = await app.pool.run(cfg, wire)
    except SSHError as exc:
        app.audit.error(host=cfg.alias, host_id=cfg.id, requested=wire, error=str(exc))
        raise ToolError(str(exc)) from exc

    app.audit.allowed(
        host=cfg.alias,
        host_id=cfg.id,
        requested=wire,
        executed=wire,
        exit_code=raw.exit_code,
        duration_ms=raw.duration_ms,
        bytes_out=len(raw.stdout),
        truncated=raw.truncated,
    )
    return CommandResult(
        host=cfg.alias,
        command=wire,
        exit_code=raw.exit_code,
        stdout=redact_text(raw.stdout),
        stderr=redact_text(raw.stderr),
        truncated=raw.truncated,
        duration_ms=raw.duration_ms,
    )


@mcp.tool()
async def run_in_container(
    ctx: Context[AppContext], container: str, command: str, host: str | None = None
) -> CommandResult:
    """Run one read-only command INSIDE a container, for logs an app writes to a file.

    Use this when a container's logs are not on stdout — a framework writing to
    `/app/storage/logs/laravel.log`, say — and `docker logs` therefore shows nothing
    useful for a code-level error.

    `command` is validated against a read-only in-container allowlist: `cat`, `tail`,
    `head`, `ls`, `stat`, `ps`, `df`, `grep`. There is no shell, and `.env` files and
    other secret paths are refused inside the container exactly as on the host. Prefer
    `run_command` with `docker logs` when the app logs to stdout — it is cheaper and
    always available.
    """
    app = ctx.request_context.lifespan_context
    cfg = await _resolve_host(app, ctx, host)
    await _ensure_shim(app, cfg)

    if not container or len(container) > 128:
        raise ToolError("invalid container name")

    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ToolError(f"could not parse command: {exc}") from exc
    if not argv:
        raise ToolError("empty command")

    wire = "@exec " + json.dumps({"container": container, "argv": argv}, separators=(",", ":"))
    try:
        raw = await app.pool.run(cfg, wire)
    except SSHError as exc:
        app.audit.error(host=cfg.alias, host_id=cfg.id, requested=wire, error=str(exc))
        raise ToolError(str(exc)) from exc

    if raw.exit_code == 92:
        app.audit.rejected(
            host=cfg.alias, host_id=cfg.id, requested=wire, reason=raw.stderr.strip()
        )
        raise ToolError(raw.stderr.strip() or "refused by the host")

    app.audit.allowed(
        host=cfg.alias,
        host_id=cfg.id,
        requested=f"exec {container}: {command}",
        executed=wire,
        exit_code=raw.exit_code,
        duration_ms=raw.duration_ms,
        bytes_out=len(raw.stdout),
        truncated=raw.truncated,
    )
    return CommandResult(
        host=cfg.alias,
        command=f"docker exec {container} {render(argv)}",
        exit_code=raw.exit_code,
        stdout=redact_text(raw.stdout),
        stderr=redact_text(raw.stderr),
        truncated=raw.truncated,
        duration_ms=raw.duration_ms,
    )


@mcp.tool()
async def check_connectivity(ctx: Context[AppContext], host: str | None = None) -> list[HostStatus]:
    """Check reachability, authentication and shim version for one or all hosts.

    Use this to tell "the host is down" apart from "my command was wrong". Also reports
    hosts whose remote allowlist has drifted out of sync with this server.
    """
    app = ctx.request_context.lifespan_context
    targets = [_host(app, host)] if host else list(app.settings.hosts.values())

    async def one(cfg: HostConfig) -> HostStatus:
        try:
            version = await app.pool.shim_version(cfg)
        except SSHError as exc:
            return HostStatus(host=cfg.alias, status="unreachable", detail=str(exc))

        app.shim_versions[cfg.alias] = version
        if version is None:
            return HostStatus(
                host=cfg.alias,
                status="shim-missing",
                detail=f"reachable, but no safereach-shim; run `safereach provision {cfg.alias}`",
            )
        if version != app.expected_fingerprint:
            return HostStatus(
                host=cfg.alias,
                status="shim-stale",
                shim_version=version,
                detail=f"expected {app.expected_fingerprint}; run `safereach shim-update {cfg.alias}`",
            )
        return HostStatus(host=cfg.alias, status="ok", shim_version=version, detail="reachable")

    return list(await asyncio.gather(*(one(cfg) for cfg in targets)))


def run() -> None:
    """Entry point for stdio transport."""
    mcp.run()


if __name__ == "__main__":
    run()
