"""Command allowlist validator — the security boundary of this project.

This module is deliberately **stdlib-only**. It is inlined verbatim into the remote
``safereach-shim`` by ``shim/build.py``, and the shim has to run on hosts where installing
third-party packages is not acceptable. Do not import pydantic, yaml, or anything else
that is not in the standard library here.

The spec it validates against is a plain ``dict`` — parsed from YAML by ``config.py`` on
the server side, and from embedded JSON by the shim. Keeping the parsing out of this
module is what allows the same code to run on both sides.

Design invariants, in order of importance:

1.  **Default-deny everywhere.** Unknown binary, unknown subcommand, unknown flag, and
    unmatched positional are all rejections. Nothing falls through to execution.
2.  **The accepted argv is re-quoted before it is sent.** The caller's original string is
    never executed. ``shlex.quote`` on every token makes shell metacharacters inert, so a
    token containing ``;`` becomes a literal argument rather than a command separator.
3.  **Round-trip stability.** For any accepted command,
    ``shlex.split(render(argv)) == argv``. This is asserted as a property test and is the
    structural guarantee that the remote shell cannot see a token boundary we did not
    intend.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "MUTATING_VERBS",
    "Rejected",
    "ValidationResult",
    "validate",
    "validate_argv",
    "render",
    "spec_summary",
]

# --------------------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------------------

MAX_COMMAND_LEN = 4096
MAX_TOKENS = 64
MAX_TOKEN_LEN = 512

#: Control characters are rejected before tokenising. Newline injection is the classic
#: way past a naive single-line check, so this runs on the raw string.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

#: Tokens that look like shell operators. ``shlex`` does not split on these — it glues
#: them onto adjacent tokens — so this is a belt-and-braces check that produces a much
#: better error message than "unknown flag '-h;'".
#:
#: Note that ``{`` and ``}`` are deliberately absent: ``docker inspect --format
#: '{{.State.Status}}'`` and ``curl -w '%{http_code}'`` both need them, and brace
#: expansion is inert once the token is re-quoted. Security here comes from the
#: re-quoting in :func:`render`, not from this pattern — this exists to turn a confusing
#: "unknown flag '-h;'" into a message that explains the actual problem.
_SHELL_META_RE = re.compile(r"[;&|<>`$()]|\\\n")

_NUMERIC_RE = re.compile(r"^-?\d+$")

#: Verbs that change state, in any tool or ecosystem.
#:
#: Some binaries put the verb in a POSITIONAL rather than a subcommand — `ip route del
#: default` deletes a route, and `deny_subcommands` never sees it. A spec sets
#: ``positionals: {deny_mutating: true}`` and every one of these is refused there.
#:
#: This lives in the validator, not in a test, so the runtime check and the spec linter
#: cannot drift apart. Maintaining the same list twice is how the gap appeared.
MUTATING_VERBS = frozenset(
    {
        "add",
        "append",
        "apply",
        "attach",
        "autoscale",
        "build",
        "change",
        "chgrp",
        "chmod",
        "chown",
        "clear",
        "commit",
        "cordon",
        "cp",
        "create",
        "del",
        "delete",
        "destroy",
        "disable",
        "down",
        "drain",
        "drop",
        "edit",
        "enable",
        "evict",
        "exec",
        "export",
        "flush",
        "halt",
        "import",
        "init",
        "install",
        "isolate",
        "kill",
        "load",
        "login",
        "logout",
        "mask",
        "migrate",
        "mv",
        "patch",
        "poweroff",
        "prepend",
        "prune",
        "pull",
        "purge",
        "push",
        "reboot",
        "reload",
        "remove",
        "replace",
        "reset",
        "restart",
        "restore",
        "revert",
        "rm",
        "rmi",
        "rollback",
        "rollout",
        "run",
        "save",
        "scale",
        "seed",
        "set",
        "shutdown",
        "start",
        "stop",
        "taint",
        "terminate",
        "truncate",
        "uncordon",
        "uninstall",
        "unmask",
        "unset",
        "up",
        "update",
        "upgrade",
        "vacuum",
        "write",
    }
)


# --------------------------------------------------------------------------------------
# Rejection
# --------------------------------------------------------------------------------------


class Rejected(Exception):
    """A command failed validation.

    Carries a ``suggestion`` wherever a legal alternative exists. This matters more than
    it looks: an agent that is told *why* it was refused and what the legal form is will
    self-correct in one turn, where a bare "denied" makes it flail.
    """

    def __init__(self, reason: str, suggestion: str | None = None) -> None:
        self.reason = reason
        self.suggestion = suggestion
        super().__init__(reason)

    def render(self) -> str:
        if self.suggestion:
            return f"Rejected: {self.reason}\nTry instead:\n  {self.suggestion}"
        return f"Rejected: {self.reason}"


@dataclass(frozen=True)
class ValidationResult:
    """An accepted command."""

    argv: list[str]
    binary: str
    subcommand: tuple[str, ...] = ()
    injected: tuple[str, ...] = field(default=())

    @property
    def command(self) -> str:
        """The exact string to send over the wire."""
        return render(self.argv)


def render(argv: list[str]) -> str:
    """Re-quote an argv into a single shell-safe string.

    This is the step that makes metacharacters inert. Never send anything else.
    """
    return " ".join(shlex.quote(tok) for tok in argv)


# --------------------------------------------------------------------------------------
# Spec normalisation
#
# YAML is forgiving in ways that matter here. ``value: none`` parses as the *string*
# "none" rather than null (only ``null``, ``~`` and empty are null in YAML), and a flag
# may be written either as ``"-x": {value: none}`` or the shorthand ``"-x": none``. Both
# spellings mean "takes no value", so both are normalised to the same shape once, here,
# rather than being special-cased at every use site.
# --------------------------------------------------------------------------------------


def _is_novalue(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.lower() in {"none", "null", "false"})


def _norm_flag(raw: Any) -> dict[str, Any]:
    if _is_novalue(raw):
        return {"value": None, "repeatable": False, "alias": None}
    if not isinstance(raw, dict):
        raise ValueError(f"malformed flag spec: {raw!r}")
    value = raw.get("value")
    return {
        "value": None if _is_novalue(value) else value,
        "repeatable": bool(raw.get("repeatable", False)),
        "alias": raw.get("alias"),
    }


def _flag_table(raw_flags: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Build a lookup mapping every spelling of a flag to one canonical spec."""
    table: dict[str, dict[str, Any]] = {}
    for name, raw in (raw_flags or {}).items():
        norm = _norm_flag(raw)
        norm["canonical"] = name
        table[name] = norm
        alias = norm.get("alias")
        if alias:
            table[alias] = norm
    return table


# --------------------------------------------------------------------------------------
# Value validation
# --------------------------------------------------------------------------------------


def _check_value(vspec: Any, value: str, flag: str, ctx: dict[str, Any]) -> None:
    if len(value) > MAX_TOKEN_LEN:
        raise Rejected(f"value for {flag} is too long ({len(value)} chars)")

    # curl reads ``@file`` in several option values, which turns a header or write-out
    # format into an arbitrary file read. Rejecting a leading '@' across the board is
    # cheaper and safer than tracking which options honour it.
    if ctx.get("reject_at_values") and value.startswith("@"):
        raise Rejected(
            f"value for {flag} starts with '@', which reads from a local file",
            "pass the value inline instead of with '@'",
        )

    if not isinstance(vspec, dict):
        raise Rejected(f"{flag} does not accept a value")

    kind = vspec.get("type")

    if kind == "int":
        if not _NUMERIC_RE.match(value):
            raise Rejected(f"{flag} expects an integer, got {value!r}")
        n = int(value)
        lo, hi = vspec.get("min"), vspec.get("max")
        if lo is not None and n < lo:
            raise Rejected(f"{flag} must be at least {lo} (got {n})")
        if hi is not None and n > hi:
            raise Rejected(
                f"{flag} must be at most {hi} (got {n})",
                f"use {flag} {hi} — the cap keeps output within the agent's context",
            )
        return

    if kind == "enum":
        choices = vspec.get("choices") or []
        if value not in choices:
            raise Rejected(f"{flag} must be one of: {', '.join(map(str, choices))} (got {value!r})")
        return

    if kind == "regex":
        pattern = vspec.get("pattern")
        if not pattern or not re.fullmatch(pattern, value):
            raise Rejected(f"value {value!r} is not permitted for {flag}")
        return

    raise Rejected(f"{flag} has an unsupported value type in the spec")


def _denied_path(token: str, patterns: list[str]) -> str | None:
    """Match a token against the host's protected-path globs.

    Both the raw token and its basename are tested, so a pattern of ``*.env`` catches
    ``/opt/app/.env`` and a bare ``.env`` alike.
    """
    if not patterns or not token:
        return None
    base = token.rsplit("/", 1)[-1]
    for pattern in patterns:
        if fnmatch.fnmatch(token, pattern) or fnmatch.fnmatch(base, pattern):
            return pattern
    return None


def _denied_positional(value: str, deny: dict[str, Any]) -> str | None:
    """Match a denied positional, tolerating the forms a resource name can take.

    `kubectl get secret`, `secrets`, `secret/db-creds` and `secrets.v1.core` all name the
    same thing, so the value is normalised to its first path- and dot-separated component
    before comparison. Denying only the bare word would leave three trivial spellings
    open.
    """
    head = value.lower().split("/")[0].split(".")[0]
    for name, reason in deny.items():
        if head == str(name).lower():
            return str(reason)
    return None


def _check_positional(value: str, pspec: dict[str, Any], ctx: dict[str, Any]) -> None:
    if len(value) > MAX_TOKEN_LEN:
        raise Rejected(f"argument is too long ({len(value)} chars)")

    if pspec.get("deny_mutating") and value.lower() in MUTATING_VERBS:
        raise Rejected(
            f"{value!r} is a state-changing verb and is never permitted",
            "this tool is read-only; use an inspection subcommand instead",
        )

    deny = pspec.get("deny")
    if deny:
        reason = _denied_positional(value, deny)
        if reason:
            raise Rejected(
                f"{value!r} is never permitted here — {reason}",
                "call `describe_commands` to see what may be inspected",
            )

    if ctx.get("reject_at_values") and value.startswith("@"):
        raise Rejected("arguments starting with '@' read from a local file")

    pattern = pspec.get("pattern")
    if pattern and not re.fullmatch(pattern, value):
        raise Rejected(f"argument {value!r} is not permitted here")

    prefixes = pspec.get("path_prefixes")
    if prefixes:
        # Reject traversal before the prefix check, so ``/var/log/../../etc/shadow``
        # cannot satisfy the prefix and then climb out of it.
        if ".." in value.split("/"):
            raise Rejected(
                f"path {value!r} contains '..'",
                "use an absolute path with no parent-directory segments",
            )
        if not any(value.startswith(p) for p in prefixes):
            raise Rejected(
                f"path {value!r} is outside the permitted locations",
                f"permitted prefixes: {', '.join(prefixes)}",
            )

    allow_key = pspec.get("host_allowlist_from")
    if allow_key:
        _check_url_host(value, ctx.get(allow_key) or [])


def _check_url_host(url: str, allowed: list[str]) -> None:
    """Pin a URL's target host to this host's allowlist.

    Without this, ``curl`` on an internal box is an outbound exfiltration channel. The
    scheme is pinned separately by the force-injected ``--proto =http,https``.
    """
    try:
        parts = urlsplit(url)
    except ValueError as exc:  # pragma: no cover - urlsplit is very permissive
        raise Rejected(f"could not parse URL {url!r}: {exc}") from exc

    if parts.scheme not in {"http", "https"}:
        raise Rejected(
            f"URL scheme {parts.scheme or '(none)'!r} is not permitted",
            "only http:// and https:// targets are allowed",
        )
    host = parts.hostname
    if not host:
        raise Rejected(f"URL {url!r} has no host")
    if not allowed:
        raise Rejected(
            "this host has no permitted curl targets configured",
            "add the target to 'curl_targets' for this host in hosts.yaml",
        )
    if host not in allowed:
        raise Rejected(
            f"{host!r} is not a permitted curl target for this host",
            f"permitted targets: {', '.join(allowed)}",
        )


# --------------------------------------------------------------------------------------
# Subcommand path matching
# --------------------------------------------------------------------------------------


def _match_subcommand_path(
    tokens: list[str], bspec: dict[str, Any], binary: str
) -> tuple[tuple[str, ...], dict[str, Any], int]:
    """Resolve a possibly multi-token subcommand path (``docker container ls``).

    Returns the matched path, the spec that applies to it, and how many tokens it ate.
    Longest match wins, so ``container ls`` beats a bare ``container`` if both exist.
    """
    paths = bspec.get("subcommand_paths")
    flat = bspec.get("subcommands")

    if not paths and not flat:
        return (), bspec, 0

    leading = [t for t in _take_while_positional(tokens)]

    if flat:
        if not leading:
            raise Rejected(
                f"{binary} requires a subcommand",
                f"one of: {', '.join(sorted(flat))}",
            )
        sub = leading[0]
        _reject_denied_subcommand(sub, bspec, binary)
        if sub not in flat:
            raise Rejected(
                f"{binary} {sub!r} is not permitted",
                f"permitted subcommands: {', '.join(sorted(flat))}",
            )
        return (sub,), bspec, 1

    # Nested paths. Try longest first.
    entries = [_norm_path_entry(e) for e in paths]
    if leading:
        _reject_denied_subcommand(leading[0], bspec, binary)

    for length in range(min(len(leading), 3), 0, -1):
        candidate = tuple(leading[:length])
        for entry in entries:
            if entry["path"] == candidate:
                merged = dict(bspec)
                for key in ("flags", "positionals", "force", "required_flags"):
                    if key in entry:
                        merged[key] = entry[key]
                return candidate, merged, length

    available = sorted(" ".join(e["path"]) for e in entries)
    got = " ".join(leading[:2]) if leading else "(none)"
    raise Rejected(
        f"{binary} {got} is not a permitted subcommand",
        f"permitted: {', '.join(available[:12])}" + (" …" if len(available) > 12 else ""),
    )


def _norm_path_entry(entry: Any) -> dict[str, Any]:
    if isinstance(entry, dict) and "path" in entry:
        out = dict(entry)
        out["path"] = tuple(entry["path"])
        return out
    if isinstance(entry, list):
        return {"path": tuple(entry)}
    raise ValueError(f"malformed subcommand_paths entry: {entry!r}")


def _reject_denied_subcommand(sub: str, bspec: dict[str, Any], binary: str) -> None:
    denied = bspec.get("deny_subcommands") or {}
    if sub in denied:
        raise Rejected(
            f"{binary} {sub} is never permitted — {denied[sub]}",
            f"see `describe_commands` for what {binary} may do",
        )


def _take_while_positional(tokens: list[str]) -> list[str]:
    out: list[str] = []
    for tok in tokens:
        if tok.startswith("-"):
            break
        out.append(tok)
    return out


# --------------------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------------------


def validate(
    command: str,
    spec: dict[str, Any],
    *,
    allow: list[str] | set[str] | None = None,
    ctx: dict[str, Any] | None = None,
) -> ValidationResult:
    """Validate ``command`` against ``spec``; return safe argv or raise :class:`Rejected`.

    :param command:  the raw command string as requested.
    :param spec:     the parsed ``commands.yaml`` mapping.
    :param allow:    per-host binary allowlist, intersected with ``spec``. ``None`` means
                     no host-level narrowing (used by tests and by the shim's own spec).
    :param ctx:      per-host context — currently ``curl_targets``.
    """
    ctx = dict(ctx or {})

    # 1. Size.
    if not command or not command.strip():
        raise Rejected("empty command")
    if len(command) > MAX_COMMAND_LEN:
        raise Rejected(f"command is too long ({len(command)} > {MAX_COMMAND_LEN} chars)")

    # 2. Control characters, on the raw string, before tokenising.
    m = _CONTROL_RE.search(command)
    if m:
        raise Rejected(
            f"command contains a control character (0x{ord(m.group()):02x})",
            "send a single-line command with no embedded newlines",
        )

    # 3. Shell operators. shlex would silently glue these onto a neighbouring token, so
    #    catching them here is purely for the error message — step 8 makes them inert
    #    regardless.
    meta = _SHELL_META_RE.search(command)
    if meta:
        raise Rejected(
            f"shell metacharacter {meta.group()!r} is not permitted "
            "(no pipes, redirects, subshells or command chaining)",
            "run one command at a time and use the tool's own filtering flags, "
            "e.g. `journalctl -u nginx -n 200 --grep error`",
        )

    # 4. Tokenise, then hand the token list to the real validator.
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise Rejected(f"could not parse command: {exc}", "check for unbalanced quotes") from exc

    return validate_argv(argv, spec, allow=allow, ctx=ctx)


def validate_argv(
    argv: list[str],
    spec: dict[str, Any],
    *,
    allow: list[str] | set[str] | None = None,
    ctx: dict[str, Any] | None = None,
) -> ValidationResult:
    """Validate an already-split argv. **This is the actual security decision.**

    Everything above is a string front-end for callers that have a command line rather
    than a token list. The wire protocol carries the token list itself, so the remote
    shim calls straight into here and never tokenises attacker-influenced text at all.

    That matters because tokenisation was the one step where the two sides could
    legitimately disagree — a quoting edge case parsed one way locally and another way
    remotely. Removing the remote tokeniser removes the divergence rather than testing
    for it. It also means the shim can be handed a hand-crafted argv over SSH (bypassing
    our client entirely) and still refuse it on the same rules.
    """
    ctx = dict(ctx or {})

    if not argv:
        raise Rejected("empty command")
    if len(argv) > MAX_TOKENS:
        raise Rejected(f"too many arguments ({len(argv)} > {MAX_TOKENS})")

    deny_paths = ctx.get("deny_paths") or []

    for token in argv:
        if not isinstance(token, str):
            raise Rejected("every argument must be a string")
        # Checked against every token, not only positionals: a path can arrive as a flag
        # value too. This is a hard stop that survives the allowlist being loosened later
        # — if someone adds `cat` one day, .env stays unreachable.
        denied = _denied_path(token, deny_paths)
        if denied:
            raise Rejected(
                f"{token!r} is on this host's protected-path list ({denied})",
                "secrets are deliberately unreadable; ask the operator for the value",
            )
        if len(token) > MAX_TOKEN_LEN:
            raise Rejected(f"argument is too long ({len(token)} chars)")
        found = _CONTROL_RE.search(token)
        if found:
            raise Rejected(f"argument contains a control character (0x{ord(found.group()):02x})")

    # 5. Binary.
    binary = argv[0]
    if "/" in binary:
        raise Rejected(
            f"binary must be a bare name, not a path ({binary!r})",
            f"use `{binary.rsplit('/', 1)[-1]}` without a directory",
        )
    if binary not in spec:
        raise Rejected(
            f"{binary!r} is not an allowlisted command",
            "call `describe_commands` to see what is available",
        )
    if allow is not None and binary not in set(allow):
        raise Rejected(
            f"{binary!r} is not permitted on this host",
            "call `list_hosts` to see what each host allows",
        )

    bspec = dict(spec[binary])
    ctx["reject_at_values"] = bool(bspec.get("reject_at_values"))

    rest = argv[1:]

    # 6. Subcommand path.
    subpath, eff, eaten = _match_subcommand_path(rest, bspec, binary)
    rest = rest[eaten:]

    # 7. Flags and positionals.
    accepted, seen = _parse_args(rest, eff, binary, ctx)

    # 7b. Required flags — LAYER 0, structural removal.
    #
    # Some subcommands are safe only in a narrowed form. Bare `systemctl show` dumps
    # every property including Environment=; `docker compose config` renders every
    # resolved secret. Neither has a flag that suppresses the sensitive part, so the
    # narrowing flag is made mandatory instead of the output being scrubbed afterwards.
    required = list(eff.get("required_flags") or [])
    if subpath:
        required += list((bspec.get("required_flags_for") or {}).get(subpath[0]) or [])
    flags_table = _flag_table(eff.get("flags"))
    for flag in required:
        canonical = flags_table.get(flag, {}).get("canonical", flag)
        if canonical not in seen:
            raise Rejected(
                f"{binary} {' '.join(subpath)} requires {flag}".strip(),
                f"the unrestricted form exposes configuration values; add {flag}",
            )

    # 8. Force-injected arguments.
    force = eff.get("force") or eff.get("force_flags") or eff.get("force_args") or []
    injected = _inject_force(force, _flag_table(eff.get("flags")), seen)

    out = [binary, *subpath, *accepted, *injected]
    return ValidationResult(argv=out, binary=binary, subcommand=subpath, injected=tuple(injected))


def _inject_force(force: list[Any], flags: dict[str, dict[str, Any]], seen: set[str]) -> list[str]:
    """Append forced arguments the caller did not already supply.

    Two things make this fiddlier than a set difference, and both were live bugs:

    * A forced entry may be a flag *and its value* (``["--tail", "500"]``). Testing tokens
      individually appends a stray ``500`` when ``--tail 200`` was already given.
    * Dedup must be alias-aware. ``--silent`` and ``-s`` are the same flag, so a caller
      who passed ``-s`` must not also get ``--silent``.

    Resolving through the canonical name from the flag table fixes both.
    """
    out: list[str] = []
    i = 0
    while i < len(force):
        tok = str(force[i])
        spec_for_flag = flags.get(tok)
        canonical = spec_for_flag["canonical"] if spec_for_flag else tok

        # Consume an accompanying value if the next entry is not itself a flag.
        value: str | None = None
        takes_value = spec_for_flag is None or spec_for_flag["value"] is not None
        if takes_value and i + 1 < len(force):
            nxt = str(force[i + 1])
            if not nxt.startswith("-"):
                value = nxt
                i += 1

        if canonical not in seen:
            out.append(tok)
            if value is not None:
                out.append(value)
            seen.add(canonical)
        i += 1
    return out


def _parse_args(
    tokens: list[str], eff: dict[str, Any], binary: str, ctx: dict[str, Any]
) -> tuple[list[str], set[str]]:
    flags = _flag_table(eff.get("flags"))
    denied = eff.get("deny_flags") or {}
    pspec = eff.get("positionals") or {"max": 0}
    short_forbidden = str(eff.get("short_flags", "")).lower() == "forbidden"

    out: list[str] = []
    positionals: list[str] = []
    seen: set[str] = set()
    end_of_flags = False
    i = 0

    while i < len(tokens):
        tok = tokens[i]

        # Tokens are emitted in the order they arrived. Hoisting all flags ahead of all
        # positionals would be semantically equivalent but would break idempotency:
        # re-validating an already-rendered command would produce a different argv, and
        # a force-injected flag would migrate on every pass.
        if end_of_flags or not tok.startswith("-") or tok == "-":
            positionals.append(tok)
            out.append(tok)
            i += 1
            continue

        if tok == "--":
            end_of_flags = True
            out.append(tok)
            i += 1
            continue

        name, inline = (tok.split("=", 1) + [None])[:2] if "=" in tok else (tok, None)

        # Explicit denials first — they carry a reason worth showing.
        if name in denied:
            raise Rejected(
                f"{name} is never permitted for {binary} — {denied[name]}",
                f"see `describe_commands` for the permitted {binary} flags",
            )

        if short_forbidden and not name.startswith("--"):
            long_forms = sorted(f for f in flags if f.startswith("--"))
            raise Rejected(
                f"{binary} accepts long flags only ({name!r} given)",
                f"use the long form — available: {', '.join(long_forms[:10])}"
                if long_forms
                else None,
            )

        spec_for_flag = flags.get(name)

        if spec_for_flag is None and not name.startswith("--") and len(name) > 2:
            # Two different meanings share this shape. `-n5` is a value attached to a
            # single flag; `-tln` is a cluster of independent no-value flags. Which one
            # applies is decided by whether the leading flag takes a value, so the
            # attached case must be tested first — otherwise `-n5` is misread as a
            # cluster and rejected because `-n` requires a value.
            head = flags.get(name[:2])
            if head is not None and head["value"] is not None:
                spec_for_flag = head
                inline = name[2:]
                name = name[:2]
            else:
                cluster = _expand_cluster(name, flags, binary)
                for single in cluster:
                    canon = flags[single]["canonical"]
                    if canon in seen and not flags[single]["repeatable"]:
                        raise Rejected(f"{single} given more than once")
                    seen.add(canon)
                    out.append(single)
                i += 1
                continue

        if spec_for_flag is None:
            known = sorted(set(f for f in flags))
            raise Rejected(
                f"{name!r} is not a permitted flag for {binary}",
                f"permitted flags: {', '.join(known[:12])}" if known else None,
            )

        canonical = spec_for_flag["canonical"]
        if canonical in seen and not spec_for_flag["repeatable"]:
            raise Rejected(f"{name} given more than once")
        seen.add(canonical)

        vspec = spec_for_flag["value"]

        if vspec is None:
            if inline is not None:
                raise Rejected(f"{name} does not take a value")
            out.append(name)
            i += 1
            continue

        # Flag expects a value: inline (--k=v), attached (-n200), or the next token.
        if inline is not None:
            value = inline
            consumed = 1
        elif i + 1 < len(tokens):
            value = tokens[i + 1]
            consumed = 2
            # A value that is itself an unconsumed flag means the caller dropped an
            # argument; silently eating the next flag would be worse than refusing.
            if value.startswith("-") and len(value) > 1 and not _NUMERIC_RE.match(value):
                raise Rejected(
                    f"{name} expects a value but was followed by {value!r}",
                    f"supply a value directly after {name}",
                )
        else:
            raise Rejected(f"{name} expects a value but none was given")

        _check_value(vspec, value, name, ctx)
        out.extend([name, value])
        i += consumed

    _check_positionals(positionals, pspec, binary, ctx)
    return out, seen


def _check_positionals(
    values: list[str], pspec: dict[str, Any], binary: str, ctx: dict[str, Any]
) -> None:
    """Validate positionals, allowing different rules per position.

    Some binaries mix argument kinds: ``grep PATTERN FILE...`` takes free text first and
    paths afterwards. A single flat rule has to be loose enough for the pattern, which
    then lets ``grep root /etc/shadow`` through. ``specs`` pins the leading positions and
    ``rest`` covers the remainder, so the file arguments can be prefix-constrained while
    the pattern stays free.
    """
    max_pos = pspec.get("max", 0)
    if len(values) > max_pos:
        raise Rejected(f"{binary} accepts at most {max_pos} argument(s), got {len(values)}")

    per_index = pspec.get("specs") or []
    rest = pspec.get("rest")

    for idx, value in enumerate(values):
        if idx < len(per_index):
            rule = per_index[idx]
        elif rest is not None:
            rule = rest
        else:
            rule = pspec
        _check_positional(value, rule, ctx)


def _expand_cluster(token: str, flags: dict[str, dict[str, Any]], binary: str) -> list[str]:
    letters = [f"-{ch}" for ch in token[1:]]
    for single in letters:
        spec_for_flag = flags.get(single)
        if spec_for_flag is None:
            raise Rejected(
                f"{token!r} is not a permitted flag for {binary}",
                f"{single} is not recognised",
            )
        if spec_for_flag["value"] is not None:
            raise Rejected(
                f"{single} takes a value and cannot be combined into {token!r}",
                f"write {single} separately with its value",
            )
    return letters


# --------------------------------------------------------------------------------------
# Introspection — what `describe_commands` renders
# --------------------------------------------------------------------------------------


def spec_summary(spec: dict[str, Any], allow: list[str] | None = None) -> dict[str, Any]:
    """Render the allowlist in a form an agent can read and act on."""
    out: dict[str, Any] = {}
    for binary, bspec in sorted(spec.items()):
        if allow is not None and binary not in allow:
            continue
        entry: dict[str, Any] = {}
        if bspec.get("description"):
            entry["description"] = bspec["description"]

        if bspec.get("subcommands"):
            entry["subcommands"] = sorted(bspec["subcommands"])
        if bspec.get("subcommand_paths"):
            entry["subcommands"] = sorted(
                " ".join(_norm_path_entry(e)["path"]) for e in bspec["subcommand_paths"]
            )

        flags = _flag_table(bspec.get("flags"))
        if flags:
            entry["flags"] = sorted({f["canonical"] for f in flags.values()})
        if bspec.get("short_flags") == "forbidden":
            entry["note"] = "long flags only (e.g. --follow, not -f)"

        pspec = bspec.get("positionals") or {}
        if pspec.get("path_prefixes"):
            entry["paths_limited_to"] = pspec["path_prefixes"]
        if bspec.get("deny_subcommands"):
            entry["never_permitted"] = sorted(bspec["deny_subcommands"])
        denied_resources = (bspec.get("positionals") or {}).get("deny")
        if denied_resources:
            entry["never_readable"] = sorted(denied_resources)

        # Per-subcommand flags matter for docker, where `logs` and `ps` differ.
        nested = {}
        for raw in bspec.get("subcommand_paths") or []:
            e = _norm_path_entry(raw)
            if e.get("flags"):
                nested[" ".join(e["path"])] = sorted(_flag_table(e["flags"]).keys())
        if nested:
            entry["subcommand_flags"] = nested

        out[binary] = entry
    return out
