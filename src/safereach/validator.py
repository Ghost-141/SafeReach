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
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "BUILTIN_DENY_PATHS",
    "MUTATING_VERBS",
    "RESOURCE_ALIASES",
    "Rejected",
    "check_log_dir",
    "check_log_source",
    "docker_host_deny_targets",
    "keeps_tail",
    "trim_output",
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

#: Characters that are shell operators when they appear OUTSIDE quotes. ``shlex`` does
#: not split on these — it glues them onto adjacent tokens — so this is a belt-and-braces
#: check that produces a much better error message than "unknown flag '-h;'".
#:
#: Note that ``{`` and ``}`` are deliberately absent: ``docker inspect --format
#: '{{.State.Status}}'`` and ``curl -w '%{http_code}'`` both need them, and brace
#: expansion is inert once the token is re-quoted. Security here comes from the
#: re-quoting in :func:`render`, not from this set — this exists to turn a confusing
#: "unknown flag '-h;'" into a message that explains the actual problem.
#:
#: Inside quotes the same characters are just text. ``grep -E "timeout|ECONNRESET"`` is a
#: search pattern, not a pipe: the token is re-quoted before it leaves this machine and
#: executed with no shell on the host, so refusing it bought nothing and cost the agent
#: alternation, anchors and grouping in every log search.
_SHELL_META_CHARS = frozenset(";&|<>`$()")

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


#: Paths the agent may never name, in any argument, on any host, in any container.
#:
#: Lives here — the one module inlined into every shim — rather than in the shim or the
#: CLI, so there is exactly one list. A host policy file can ADD patterns, never remove
#: these: a denylist a careless edit can empty is not a control. Matched against the
#: whole token and against its basename, so ``*.env`` catches ``/opt/app/.env``.
BUILTIN_DENY_PATHS: tuple[str, ...] = (
    "*.env",
    "*.env.*",
    ".env*",
    "*.envrc",
    "*/secrets/*",
    "*/secret/*",
    "*secrets.yml",
    "*secrets.yaml",
    "*secrets.json",
    "*database.yml",
    "*database.yaml",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.gpg",
    "*.asc",
    "*.kdbx",
    "*.ovpn",
    "*.ppk",
    "id_rsa*",
    "id_dsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*_rsa",
    "*_ed25519",
    "*/.ssh/*",
    "*/.gnupg/*",
    "*credentials*",
    "*.kubeconfig",
    "*/.kube/config",
    "*/.aws/*",
    "*/.azure/*",
    "*/.config/gcloud/*",
    "*/.docker/config.json",
    "*/.netrc",
    ".netrc",
    "*/.git-credentials",
    "*/.pgpass",
    "*.htpasswd",
    "*_history",
    # PM2 keeps every managed app's full environment in dump.pm2 and module settings in
    # module_conf.json, both beside its logs directory. Found on a live host: a scan
    # offered ~/.pm2/ itself as a "log directory" because pm2.log lives there.
    "*/.pm2/dump.pm2*",
    "*/.pm2/module_conf.json",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers*",
    # The process and kernel views carry every environment variable of every process
    # (`/proc/<pid>/environ`) and the kernel's own keys. Nothing diagnostic lives there
    # that `ps`, `ss` and `df` do not already report in a shape that can be masked.
    # `/dev` is deliberately absent: `curl -o /dev/null` is the one legitimate write.
    "/proc/*",
    "/sys/*",
    # This tool's own policy and binary. The diag account cannot write them; it must not
    # be able to read them either, or a digest key in the policy file is one `cat` away.
    "/etc/safereach/*",
    "/usr/local/bin/safereach-shim",
)

#: Directories a host's log-path policy may never name, whatever the operator types.
#: A log directory is a leaf — `/opt/app/logs/` — and these are the roots that would
#: quietly turn "read the app's logs" into "read the app": its config, its uploads,
#: every other user's home. Matched exactly; a directory *below* one of them is fine.
BROAD_LOG_ROOTS: frozenset[str] = frozenset(
    {
        "/",
        "/app/",
        "/data/",
        "/home/",
        "/mnt/",
        "/opt/",
        "/root/",
        "/run/",
        "/srv/",
        "/tmp/",
        "/usr/",
        "/usr/local/",
        "/var/",
        "/var/lib/",
        "/var/www/",
    }
)

#: Trees a log path may not sit under at all. Container storage is the whole filesystem
#: of every container, `.env` files included; the rest hold no logs worth the exposure.
_FORBIDDEN_LOG_TREES: tuple[str, ...] = (
    "/boot/",
    "/dev/",
    "/etc/",
    "/proc/",
    "/sys/",
    "/var/lib/containerd/",
    "/var/lib/docker/",
    "/var/lib/kubelet/",
)

_LOG_DIR_RE = re.compile(r"/[A-Za-z0-9._/\-]{1,200}")

#: kubectl resource abbreviations, expanded before a positional deny is checked.
#: `kubectl get sa` and `kubectl get serviceaccounts` are the same request; denying one
#: spelling and not the other is not a denial.
RESOURCE_ALIASES: dict[str, str] = {
    "cm": "configmaps",
    "configmap": "configmaps",
    "csr": "certificatesigningrequests",
    "deploy": "deployments",
    "deployment": "deployments",
    "ds": "daemonsets",
    "ep": "endpoints",
    "ev": "events",
    "ing": "ingresses",
    "ingress": "ingresses",
    "no": "nodes",
    "node": "nodes",
    "ns": "namespaces",
    "namespace": "namespaces",
    "po": "pods",
    "pod": "pods",
    "pv": "persistentvolumes",
    "pvc": "persistentvolumeclaims",
    "rs": "replicasets",
    "sa": "serviceaccounts",
    "serviceaccount": "serviceaccounts",
    "sc": "storageclasses",
    "secret": "secrets",
    "sts": "statefulsets",
    "svc": "services",
    "service": "services",
}


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


def check_log_dir(path: str, deny_paths: list[str] | tuple[str, ...] = BUILTIN_DENY_PATHS) -> str:
    """Normalise one host log directory, or raise :class:`Rejected` saying why it is unsafe.

    The single gate for every log directory, wherever it was typed: `enroll --log-path`,
    `hosts.yaml`, and — because the host trusts nothing it did not check itself — the
    shim reading its own policy file. Returns the path with exactly one trailing slash,
    which is what makes the prefix test a directory test: `/opt/app/logs/` does not
    admit `/opt/app/logs-evil/`.
    """
    if not isinstance(path, str) or not _LOG_DIR_RE.fullmatch(path):
        raise Rejected(
            f"log path {path!r} must be absolute and use only letters, digits, '.', '_', '-' "
            "and '/'"
        )
    parts = path.split("/")
    if ".." in parts or "." in parts or "//" in path:
        raise Rejected(f"log path {path!r} must not contain '.', '..' or '//' segments")
    norm = path.rstrip("/") + "/"
    if norm in BROAD_LOG_ROOTS or (norm.startswith("/home/") and norm.count("/") <= 3):
        raise Rejected(
            f"log path {norm!r} is too broad — it would expose far more than logs",
            "name the directory the application writes its logs into, e.g. /opt/app/logs/",
        )
    for tree in _FORBIDDEN_LOG_TREES:
        if norm.startswith(tree):
            raise Rejected(f"log path {norm!r} is under {tree}, which never holds readable logs")
    # Dot-directories are tools' state and configuration — ~/.pm2 (dump.pm2 carries every
    # app's environment), ~/.vscode-server, ~/.config — not application logs. The one
    # exception is PM2's own logs directory, which is exactly where PM2 apps log.
    hidden = [p for p in parts if p.startswith(".")]
    if hidden and "/.pm2/logs/" not in norm:
        raise Rejected(
            f"log path {norm!r} is inside a hidden directory ({hidden[0]}), which holds tool "
            "state and configuration rather than logs",
            "for PM2 use ~/.pm2/logs/; otherwise name the application's own log directory",
        )
    denied = _denied_path(norm, list(deny_paths)) or _denied_path(
        norm.rstrip("/"), list(deny_paths)
    )
    if denied:
        raise Rejected(f"log path {norm!r} is on the protected-path list ({denied})")
    return norm


#: A log source is addressed by name — `read_logs(source="api")` — so the agent never
#: composes a path. Names are YAML keys and tool arguments, hence the narrow alphabet.
LOG_SOURCE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,47}")
_LOG_GLOB_RE = re.compile(r"[A-Za-z0-9._*\-]{1,64}")
_CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}")
_UNIT_NAME_RE = re.compile(r"[A-Za-z0-9@._:\-]{1,128}")


def check_log_source(
    name: str, raw: Any, deny_paths: list[str] | tuple[str, ...] = BUILTIN_DENY_PATHS
) -> dict[str, str]:
    """Normalise one named log source, or raise :class:`Rejected`.

    Three kinds, each pinned to what it may name:

    * ``file`` — a directory (through :func:`check_log_dir`) and a basename glob. The glob
      cannot contain ``/`` or ``**``, so it never reaches below or beside the directory.
    * ``docker`` — a container name; read with ``docker logs``.
    * ``journal`` — a systemd unit; read with ``journalctl -u``.

    Shared by hosts.yaml loading, enrolment and the shim, which re-checks its own policy.
    """
    if not isinstance(name, str) or not LOG_SOURCE_NAME_RE.fullmatch(name):
        raise Rejected(
            f"log source name {name!r} must be lowercase letters, digits, '.', '_' or '-' "
            "(at most 48 characters)"
        )
    if not isinstance(raw, dict):
        raise Rejected(f"log source {name!r} must be a mapping with a 'kind'")
    kind = raw.get("kind")
    if kind == "file":
        directory = check_log_dir(str(raw.get("dir", "")), deny_paths)
        glob = str(raw.get("glob") or "*")
        if not _LOG_GLOB_RE.fullmatch(glob) or "**" in glob:
            raise Rejected(f"log source {name!r}: glob {glob!r} must be a plain file-name pattern")
        return {"kind": "file", "dir": directory, "glob": glob}
    if kind == "docker":
        container = str(raw.get("container", ""))
        if not _CONTAINER_NAME_RE.fullmatch(container):
            raise Rejected(f"log source {name!r}: invalid container name {container!r}")
        return {"kind": "docker", "container": container}
    if kind == "journal":
        unit = str(raw.get("unit", ""))
        if not _UNIT_NAME_RE.fullmatch(unit) or unit.startswith("-"):
            raise Rejected(f"log source {name!r}: invalid unit name {unit!r}")
        return {"kind": "journal", "unit": unit}
    raise Rejected(f"log source {name!r}: kind must be file, docker or journal (got {kind!r})")


def _within(value: str, prefixes: list[str]) -> bool:
    """Directory-prefix test that also accepts the directory itself without its slash.

    `ls /var/log` names the same directory as `ls /var/log/`; refusing the first form was
    a papercut with no security content, since the prefix is the directory either way.
    """
    return any(value.startswith(p) or value + "/" == p for p in prefixes)


def _denied_positional(value: str, deny: dict[str, Any]) -> str | None:
    """Match a denied positional, tolerating the forms a resource name can take.

    `kubectl get secret`, `secrets`, `secret/db-creds` and `secrets.v1.core` all name the
    same thing, so the value is normalised to its first path- and dot-separated component
    before comparison. Denying only the bare word would leave three trivial spellings
    open.
    """
    head = value.lower().split("/")[0].split(".")[0]
    head = RESOURCE_ALIASES.get(head, head)
    for name, reason in deny.items():
        denied = str(name).lower()
        if head == RESOURCE_ALIASES.get(denied, denied):
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

    prefixes = list(pspec.get("path_prefixes") or [])
    prefixes_key = pspec.get("path_prefixes_from")
    if prefixes_key:
        # Prefixes supplied by the host's own policy rather than by the spec — the
        # container-exec case, where every host's log directory differs. Default-deny:
        # a host that has not said where the agent may read has nowhere it may read.
        prefixes = list(ctx.get(prefixes_key) or [])
        if not prefixes:
            raise Rejected(
                "this host has no permitted paths configured for this command",
                f"the operator sets '{prefixes_key}' in the host policy (enroll --exec-path)",
            )
    extra_key = pspec.get("extra_path_prefixes_from")
    if extra_key:
        # Added to the spec's own prefixes, never replacing them: /var/log stays readable
        # everywhere, and a host that runs a PM2 or Node app writing to
        # /opt/app/logs/ says so in its policy (enroll --log-path) instead of the agent
        # finding the files with `ls` and then being refused at `tail`.
        prefixes += [p for p in ctx.get(extra_key) or [] if p not in prefixes]
    if prefixes:
        # Reject traversal before the prefix check, so ``/var/log/../../etc/shadow``
        # cannot satisfy the prefix and then climb out of it.
        if ".." in value.split("/"):
            raise Rejected(
                f"path {value!r} contains '..'",
                "use an absolute path with no parent-directory segments",
            )
        if not _within(value, prefixes):
            raise Rejected(
                f"path {value!r} is outside the permitted locations",
                f"permitted prefixes: {', '.join(prefixes)}"
                + (
                    " — application log directories are added per host with "
                    "`safereach enroll <host> --log-path DIR`"
                    if extra_key
                    else ""
                ),
            )
        if ctx.get("resolve_symlinks"):
            _check_resolved(value, prefixes, ctx)

    allow_key = pspec.get("host_allowlist_from")
    if allow_key:
        _check_url_host(value, ctx.get(allow_key) or [], ctx.get("curl_deny_targets") or [])


def _check_resolved(value: str, prefixes: list[str], ctx: dict[str, Any]) -> None:
    """Re-test a path after resolving symlinks. Only the shim sets ``resolve_symlinks``.

    The string checks above are all the client can do — the path does not exist on this
    machine. On the host it does, and an application's own log directory is writable by
    the application, so `/opt/app/logs/x.log -> /opt/app/.env` is one careless deploy
    script away. /var/log is root's; an app log directory is not.
    """
    real = os.path.realpath(value)
    if real == value.rstrip("/") or real + "/" == value:
        return
    real_prefixes = [os.path.realpath(p).rstrip("/") + "/" for p in prefixes]
    if not _within(real, real_prefixes):
        raise Rejected(
            f"path {value!r} resolves outside the permitted locations",
            "symlinks may not lead out of a permitted directory",
        )
    denied = _denied_path(real, ctx.get("deny_paths") or [])
    if denied:
        raise Rejected(
            f"path {value!r} resolves to a protected path ({denied})",
            "secrets are deliberately unreadable; ask the operator for the value",
        )


#: Ports a bare hostname entry in ``curl_targets`` covers. ``localhost`` used to mean
#: *every* port on the box, which put the Docker API, Elasticsearch, Consul and whatever
#: else listens on loopback one GET away. A bare name now means the web ports only; any
#: other port has to be written out as ``host:port``.
_DEFAULT_WEB_PORTS = frozenset({80, 443})


def _parse_target(entry: str) -> tuple[str, int | None]:
    """``host``, ``host:port`` or ``[v6]:port`` → ``(host, port-or-None)``."""
    entry = entry.strip().lower()
    if entry.startswith("["):
        host, _, rest = entry[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return host, (int(port) if port.isdigit() else None)
    host, sep, port = entry.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return entry, None


def _target_matches(host: str, port: int, entry: str) -> bool:
    e_host, e_port = _parse_target(entry)
    if e_host != host:
        return False
    if e_port is None:
        return port in _DEFAULT_WEB_PORTS
    return e_port == port


def docker_host_deny_targets(docker_host: str | None) -> list[str]:
    """The ``host:port`` spellings that reach a TCP Docker proxy.

    Derived from the host's own ``docker_host`` so the operator does not have to remember
    to deny it. The Docker API over curl bypasses every structural mask ``docker inspect``
    output gets, and ``GET /containers/<id>/archive?path=/app`` is a tar of the
    application directory.
    """
    if not docker_host:
        return []
    try:
        parts = urlsplit(docker_host)
    except ValueError:  # pragma: no cover - urlsplit is very permissive
        return []
    if parts.scheme != "tcp" or not parts.hostname or not parts.port:
        return []
    names = {parts.hostname.lower()}
    if parts.hostname.lower() in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        names |= {"localhost", "127.0.0.1", "[::1]"}
    return sorted(f"{n}:{parts.port}" for n in names)


def _check_url_host(url: str, allowed: list[str], denied: list[str] | None = None) -> None:
    """Pin a URL's target host **and port** to this host's allowlist.

    Without this, ``curl`` on an internal box is an outbound exfiltration channel. The
    scheme is pinned separately by the force-injected ``--proto =http,https``.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise Rejected(f"could not parse URL {url!r}: {exc}") from exc

    if parts.scheme not in {"http", "https"}:
        raise Rejected(
            f"URL scheme {parts.scheme or '(none)'!r} is not permitted",
            "only http:// and https:// targets are allowed",
        )
    host = parts.hostname
    if not host:
        raise Rejected(f"URL {url!r} has no host")
    host = host.lower()
    if port is None:
        port = 443 if parts.scheme == "https" else 80

    for entry in denied or []:
        if _target_matches(host, port, entry):
            raise Rejected(
                f"{host}:{port} is the Docker API on this host and is never a curl target",
                "use the `docker` command instead; its output is masked, raw API JSON is not",
            )

    if not allowed:
        raise Rejected(
            "this host has no permitted curl targets configured",
            "add the target as host:port to 'curl_targets' for this host in hosts.yaml",
        )
    if not any(_target_matches(host, port, entry) for entry in allowed):
        raise Rejected(
            f"{host}:{port} is not a permitted curl target for this host",
            f"permitted targets: {', '.join(allowed)} "
            "(a bare hostname covers ports 80 and 443 only)",
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

    # 3. Shell operators outside quotes. shlex would silently glue these onto a
    #    neighbouring token, so catching them here is purely for the error message —
    #    step 8 makes them inert regardless.
    meta = _unquoted_meta(command)
    if meta:
        raise Rejected(
            f"shell metacharacter {meta!r} is not permitted "
            "(no pipes, redirects, subshells or command chaining)",
            "run one command at a time and use the tool's own filtering flags, "
            'e.g. `journalctl -u nginx -n 200 --grep "timeout|refused"` — '
            "inside quotes, | ( ) $ are ordinary regex characters",
        )

    # 4. Tokenise, then hand the token list to the real validator.
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise Rejected(f"could not parse command: {exc}", "check for unbalanced quotes") from exc

    return validate_argv(argv, spec, allow=allow, ctx=ctx)


def _unquoted_meta(command: str) -> str | None:
    """The first shell operator character that sits outside any quotes, if one does.

    Follows POSIX quoting as ``shlex.split`` does: single quotes are literal to the next
    single quote, double quotes honour backslash escapes, and an unquoted backslash
    makes the next character literal. An unbalanced quote returns None here and is
    refused by the tokeniser in the next step with its own message.
    """
    quote: str | None = None
    i = 0
    while i < len(command):
        ch = command[i]
        if quote == "'":
            if ch == "'":
                quote = None
        elif quote == '"':
            if ch == "\\":
                i += 1
            elif ch == '"':
                quote = None
        elif ch == "\\":
            i += 1
        elif ch in "'\"":
            quote = ch
        elif ch in _SHELL_META_CHARS:
            return ch
        i += 1
    return None


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
        if inline is not None and value.startswith("-"):
            # Keep a dash-led value attached. Split into two tokens, `--sort=-rss` comes
            # back as `--sort -rss`, which the check above then reads as a dropped value
            # — so the shim refused what this side accepted, breaking idempotency.
            out.append(f"{name}={value}" if name.startswith("--") else f"{name}{value}")
        else:
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


def spec_summary(
    spec: dict[str, Any],
    allow: list[str] | None = None,
    ctx: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render the allowlist in a form an agent can read and act on.

    ``ctx`` is the host context; when given, host-supplied path prefixes (a host's log
    directories) are listed alongside the spec's own, so the agent reads the real
    locations instead of discovering them one refusal at a time.
    """
    ctx = ctx or {}
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
        paths: list[str] = []
        for rule in (pspec, pspec.get("rest") or {}):
            for prefix in [
                *(rule.get("path_prefixes") or []),
                *(ctx.get(rule.get("extra_path_prefixes_from") or "") or []),
            ]:
                if prefix not in paths:
                    paths.append(prefix)
        if paths:
            entry["paths_limited_to"] = paths
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


# --------------------------------------------------------------------------------------
# Output shaping — here because this module is inlined into the shim, and both sides
# must cut output the same way
# --------------------------------------------------------------------------------------

#: The last stderr line the shim writes when it cut a stream, followed by a JSON object
#: (``omitted_bytes``, ``kept``). The client strips it and sets ``truncated``; before
#: this, a host-side cut arrived just under the client's own limit and was reported as
#: not truncated at all.
TRUNCATION_TAG = "@safereach-truncated"

#: Binaries whose output is chronological, oldest first. When one of these overflows
#: the byte budget, the lines worth keeping are the LAST ones — the error the agent was
#: sent to find happened a minute ago, not at the start of the window it asked for.
_TAIL_FIRST_BINARIES = frozenset({"journalctl", "dmesg", "tail", "grep", "zgrep"})


def keeps_tail(argv: list[str]) -> bool:
    """Whether overflowing output from ``argv`` should keep its end rather than its start."""
    if not argv:
        return False
    binary = argv[0]
    if binary == "journalctl":
        return not any(t in ("-r", "--reverse") for t in argv[1:])
    if binary in _TAIL_FIRST_BINARIES:
        return True
    if binary in ("docker", "kubectl"):
        return "logs" in argv[1:4]
    return False


def trim_output(text: str, limit: int, keep_tail: bool) -> tuple[str, int]:
    """Cut ``text`` to at most ``limit`` characters on a line boundary.

    Returns ``(kept, omitted)``. A cut never leaves half a line at the seam: a partial
    first line (tail) or last line (head) is dropped, because a half-line of a stack
    trace reads as a different error.
    """
    if limit <= 0 or len(text) <= limit:
        return text, 0
    if keep_tail:
        kept = text[-limit:]
        nl = kept.find("\n")
        if 0 <= nl < len(kept) - 1:
            kept = kept[nl + 1 :]
    else:
        kept = text[:limit]
        nl = kept.rfind("\n")
        if nl > 0:
            kept = kept[: nl + 1]
    return kept, len(text) - len(kept)
