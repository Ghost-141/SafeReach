"""safereach-shim — the remote half of the security boundary.

Installed on each managed host at ``/usr/local/bin/safereach-shim`` and pinned as a forced
command in the diag user's ``authorized_keys``::

    command="/usr/local/bin/safereach-shim",no-port-forwarding,no-agent-forwarding,no-pty,\
no-X11-forwarding,no-user-rc ssh-ed25519 AAAA... agent-diag

With that in place the key can invoke **nothing but this file**, whatever string is sent.
sshd puts the requested command in ``$SSH_ORIGINAL_COMMAND`` and runs the shim instead.

Why this exists at all, given the MCP server already validates: the MCP server runs on the
agent's own machine, so a check that lives there is one the agent's environment can
influence — through a compromised server, a poisoned context, or a prompt injection
arriving in a log line the agent just read. Client-side validation is a UX feature. This
is the control that holds, because it sits outside everything the agent can reach.

Three rules this file obeys without exception:

* **Never trust the client.** Re-derive everything. The client's verdict is not consulted.
* **Fail closed.** Any unexpected condition exits non-zero without executing.
* **The host owns its own policy.** Per-host limits (curl targets, docker host, elevated
  recipes) come from ``/etc/safereach/config.json`` on this machine, not from the wire.
  What the server believes about a host is irrelevant to what the host permits.

Built by ``shim/build.py``, which inlines ``validator.py`` and embeds the spec so the
result is a single stdlib-only file that can be scp'd anywhere.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# --- BEGIN IMPORT SHIM (stripped by build.py) -----------------------------------------
# When run from the source tree these come from the package. In the built artifact the
# validator source is inlined directly above this block instead.
from safereach.redact import (  # noqa: E402
    mask_by_digest,
    mask_env_keys,
    redact_docker_inspect,
    redact_text,
)
from safereach.validator import Rejected, render, validate, validate_argv  # noqa: E402

# --- END IMPORT SHIM ------------------------------------------------------------------

# Replaced by build.py. The defaults keep the source tree runnable for tests.
EMBEDDED_SPEC: dict[str, Any] = {}
SHIM_VERSION = "dev"

#: Searched in order, first hit wins. The user-local path is what `enroll` writes: it
#: needs no root, which is the whole reason enrolment can be a single command run over
#: the SSH access you already have.
#: Compiled into the shim, so a hand-edited host policy can ADD patterns but never
#: remove these. A denylist a compromised or careless edit can empty is not a control.
BUILTIN_DENY_PATHS = (
    "*.env",
    "*.env.*",
    ".env*",
    "*.envrc",
    "*/secrets/*",
    "*/secret/*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.gpg",
    "*.asc",
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
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers*",
)

CONFIG_PATHS = (
    Path("/etc/safereach/config.json"),
    Path.home() / ".config" / "safereach-shim" / "config.json",
)
LOG_PATHS = (Path("/var/log/safereach.jsonl"), Path.home() / ".safereach-shim.jsonl")

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_BYTES = 65536

EXIT_REJECTED = 92
EXIT_INTERNAL = 93


def load_config() -> dict[str, Any]:
    """Host-local policy. A missing file means maximally restrictive, not permissive."""
    for path in CONFIG_PATHS:
        try:
            with path.open(encoding="utf-8") as fh:
                cfg = json.load(fh)
        except FileNotFoundError:
            continue
        except Exception as exc:
            # Fail closed: an unreadable policy file must not silently become "allow all".
            _die(EXIT_INTERNAL, f"safereach-shim: cannot read {path}: {exc}")
        if not isinstance(cfg, dict):
            _die(EXIT_INTERNAL, f"safereach-shim: {path}: config root must be an object")
        return cfg
    return {}


def audit(record: dict[str, Any]) -> None:
    """Append one line to the host's own audit log.

    This is the trail that survives the MCP server being wrong about what it thinks it
    sent, so it is written before the result goes back over the wire. Failure to log is
    never allowed to block execution — but it is also never silent.
    """
    record.setdefault("ts", time.time())
    record.setdefault("shim_version", SHIM_VERSION)
    record.setdefault("ssh_client", os.environ.get("SSH_CLIENT", "").split(" ")[0])
    line = json.dumps(record, separators=(",", ":"), default=str)
    for path in LOG_PATHS:
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return
        except OSError:
            continue
    print(f"safereach-shim: WARNING could not write audit log: {line}", file=sys.stderr)


def _die(code: int, message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def _is_env_bearing(argv: list[str]) -> bool:
    """Commands whose output carries a container's environment verbatim."""
    return argv[:2] == ["docker", "inspect"] or argv[:3] in (
        ["docker", "container", "inspect"],
        ["docker", "image", "inspect"],
        ["docker", "compose", "config"],
    )


def run_argv(argv: list[str], cfg: dict[str, Any]) -> int:
    """Execute a validated argv with no shell involved at all.

    ``subprocess`` with a list never goes through ``/bin/sh``, so there is no second
    parsing pass that could reinterpret a token. The re-quoting in the validator protects
    the SSH hop; this protects the final exec.
    """
    timeout = int(cfg.get("command_timeout", DEFAULT_TIMEOUT))
    max_bytes = int(cfg.get("max_output_bytes", DEFAULT_MAX_BYTES))

    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": os.environ.get("HOME", "/tmp"),
        "TERM": "dumb",
    }
    if cfg.get("docker_host"):
        env["DOCKER_HOST"] = str(cfg["docker_host"])

    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - argv is validated and never shell-parsed
            argv,
            capture_output=True,
            timeout=timeout,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        _die(EXIT_INTERNAL, f"safereach-shim: {argv[0]!r} is not installed on this host")
    except subprocess.TimeoutExpired:
        audit({"decision": "timeout", "argv": argv, "timeout_s": timeout})
        _die(EXIT_INTERNAL, f"safereach-shim: command exceeded {timeout}s and was killed")

    duration_ms = int((time.monotonic() - started) * 1000)
    out = proc.stdout[:max_bytes]
    err = proc.stderr[:max_bytes]
    truncated = len(proc.stdout) > max_bytes or len(proc.stderr) > max_bytes

    audit(
        {
            "decision": "allowed",
            "argv": argv,
            "exit_code": proc.returncode,
            "duration_ms": duration_ms,
            "bytes_out": len(proc.stdout),
            "truncated": truncated,
        }
    )

    # Redact ON THE HOST, before anything crosses the wire.
    #
    # The MCP server redacts too, but that is a second pass on data that has already
    # left the machine. Anyone with this key — including someone bypassing our client
    # entirely — would otherwise get `docker inspect` output with Config.Env intact,
    # which is precisely where a container's .env ends up.
    text_out = out.decode("utf-8", errors="replace")
    if _is_env_bearing(argv):
        text_out = redact_docker_inspect(text_out, cfg.get("env_allowlist") or [])
    text_out = mask_env_keys(text_out, cfg.get("secret_env_keys") or [])
    # Layer 3: catches a value with no variable name attached — a token in a stack
    # trace, a password quoted in an application log.
    text_out = mask_by_digest(text_out, cfg.get("secret_digests") or [], cfg.get("digest_key"))
    text_out = redact_text(text_out, cfg.get("redact_patterns") or [])

    sys.stdout.buffer.write(text_out.encode("utf-8"))
    sys.stderr.buffer.write(redact_text(err.decode("utf-8", errors="replace")).encode("utf-8"))
    if truncated:
        print(
            f"\n[safereach-shim] output truncated at {max_bytes} bytes",
            file=sys.stderr,
        )
    return proc.returncode


def handle_elevated(name: str, cfg: dict[str, Any]) -> int:
    """Run one named recipe.

    The agent sends a *name*, never a command line — there is no argument surface here at
    all. Each recipe is a fully-specified invocation paired with an exact-match sudoers
    entry. This is why ``sudo`` is not in the command allowlist: if the agent could pass
    arguments to sudo, the allowlist would be decorative.
    """
    recipes = cfg.get("elevated") or {}
    if name not in recipes:
        available = ", ".join(sorted(recipes)) or "(none configured)"
        audit({"decision": "rejected", "recipe": name, "reason": "unknown recipe"})
        _die(
            EXIT_REJECTED,
            f"Rejected: {name!r} is not a configured elevated recipe on this host\n"
            f"Available: {available}",
        )
    argv = list(recipes[name])
    if not argv or not all(isinstance(a, str) for a in argv):
        _die(EXIT_INTERNAL, f"safereach-shim: recipe {name!r} is malformed")
    audit({"decision": "elevated", "recipe": name, "argv": argv})
    return run_argv(argv, cfg)


def _decode_argv(payload: str) -> list[str]:
    try:
        argv = json.loads(payload)
    except (json.JSONDecodeError, ValueError) as exc:
        _die(EXIT_REJECTED, f"Rejected: @run payload is not valid JSON: {exc}")
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        _die(EXIT_REJECTED, "Rejected: @run payload must be a JSON array of strings")
    return argv


def _handle_run(payload: str, cfg: dict[str, Any]) -> int:
    """Validate a structured argv and execute it.

    Note that this is validated exactly as strictly as anything else. An argv sent
    directly over SSH with this key — bypassing our client entirely — goes through the
    same rules, which is the point of the shim existing at all.
    """
    argv = _decode_argv(payload)
    try:
        result = validate_argv(
            argv,
            EMBEDDED_SPEC,
            allow=cfg.get("allow"),
            ctx={
                "curl_targets": cfg.get("curl_targets") or [],
                "deny_paths": [*BUILTIN_DENY_PATHS, *(cfg.get("deny_paths") or [])],
            },
        )
    except Rejected as rej:
        audit({"decision": "rejected", "requested": argv, "reason": rej.reason})
        _die(EXIT_REJECTED, rej.render())
    except Exception as exc:
        audit({"decision": "error", "requested": argv, "error": repr(exc)})
        _die(EXIT_INTERNAL, f"safereach-shim: internal error during validation: {exc}")
    return run_argv(result.argv, cfg)


# --------------------------------------------------------------------------------------
# Container exec — opt-in, and NOT an escape hatch
# --------------------------------------------------------------------------------------

#: Commands permitted to run *inside* a container. Deliberately narrower than the host
#: allowlist and separate from it: container filesystems put logs in different places, so
#: the host's /var/log-only path rules would make this useless, while the host's full
#: command set would make it dangerous.
#:
#: The rule that makes this safe is that the inner argv goes through `validate_argv`
#: exactly like anything else. `docker exec app sh -c 'rm -rf /'` fails because `sh` is
#: not an allowlisted binary — not because of a special case for `sh`.
EXEC_INNER_SPEC = {
    "cat": {
        "description": "Read an application log inside the container",
        "flags": {"-n": {"value": None}},
        "positionals": {"max": 2, "pattern": r"/[A-Za-z0-9._/\-]{1,200}"},
    },
    "tail": {
        "description": "Last lines of a log inside the container",
        "flags": {"-n": {"alias": "--lines", "value": {"type": "int", "min": 1, "max": 2000}}},
        "positionals": {"max": 2, "pattern": r"/[A-Za-z0-9._/\-]{1,200}"},
        "deny_flags": {"-f": "streams forever", "--follow": "streams forever"},
    },
    "head": {
        "description": "First lines of a log inside the container",
        "flags": {"-n": {"alias": "--lines", "value": {"type": "int", "min": 1, "max": 2000}}},
        "positionals": {"max": 2, "pattern": r"/[A-Za-z0-9._/\-]{1,200}"},
    },
    "ls": {
        "description": "List a directory inside the container",
        "flags": {
            "-l": {"value": None},
            "-a": {"value": None},
            "-h": {"value": None},
            "-t": {"value": None},
            "-r": {"value": None},
        },
        # {0,200}: `ls /` is a legitimate first step when exploring a container.
        "positionals": {"max": 2, "pattern": r"/[A-Za-z0-9._/\-]{0,200}"},
    },
    "stat": {
        "description": "File metadata inside the container",
        "positionals": {"max": 2, "pattern": r"/[A-Za-z0-9._/\-]{0,200}"},
    },
    "ps": {
        "description": "Processes inside the container",
        "flags": {
            "-e": {"value": None},
            "-f": {"value": None},
            "-a": {"value": None},
            "-x": {"value": None},
            "-u": {"value": None},
        },
        "positionals": {"max": 0},
    },
    "df": {
        "description": "Disk usage inside the container",
        "flags": {"-h": {"value": None}, "-i": {"value": None}},
        "positionals": {"max": 2, "pattern": r"/[A-Za-z0-9._/\-]{0,200}"},
    },
    "grep": {
        "description": "Search a log inside the container",
        "flags": {
            "-i": {"value": None},
            "-n": {"value": None},
            "-c": {"value": None},
            "-E": {"value": None},
            "-F": {"value": None},
            "-m": {"alias": "--max-count", "value": {"type": "int", "min": 1, "max": 2000}},
            "-A": {"value": {"type": "int", "min": 0, "max": 20}},
            "-B": {"value": {"type": "int", "min": 0, "max": 20}},
        },
        "positionals": {
            "max": 3,
            "specs": [{"pattern": r"[^`$\\]{1,200}"}],
            "rest": {"pattern": r"/[A-Za-z0-9._/\-]{1,200}"},
        },
        "deny_flags": {"-f": "reads the pattern list from a file", "-r": "walks the filesystem"},
    },
    "env": None,  # placeholder removed below — env dumps the container's secrets
}
EXEC_INNER_SPEC.pop("env")

_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")


def handle_exec(payload: str, cfg: dict[str, Any]) -> int:
    """Run one allowlisted read-only command inside a container.

    Off unless the host was enrolled with --allow-exec. Three things make this materially
    different from handing over `docker exec`:

    * the inner argv is validated by the same validator, against a read-only spec, so
      there is no path to a shell;
    * `deny_paths` still applies, so `cat /app/.env` is refused inside the container just
      as it is on the host;
    * output goes through the same redaction pass on the way out.

    What it is NOT is an interactive session: no TTY, no stdin, no `-it`.
    """
    if not cfg.get("allow_exec"):
        _die(
            EXIT_REJECTED,
            "Rejected: container exec is not enabled on this host.\n"
            "Enrol with: safereach enroll <host> --hardened --allow-exec",
        )

    try:
        request = json.loads(payload)
        container = request["container"]
        argv = request["argv"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        _die(EXIT_REJECTED, f"Rejected: malformed @exec payload: {exc}")

    if not isinstance(container, str) or not _CONTAINER_RE.match(container):
        _die(EXIT_REJECTED, f"Rejected: invalid container name {container!r}")
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        _die(EXIT_REJECTED, "Rejected: argv must be a list of strings")

    allowed_containers = cfg.get("exec_containers") or []
    if allowed_containers and container not in allowed_containers:
        _die(
            EXIT_REJECTED,
            f"Rejected: {container!r} is not an exec-permitted container on this host.\n"
            f"Permitted: {', '.join(allowed_containers)}",
        )

    try:
        inner = validate_argv(
            argv,
            EXEC_INNER_SPEC,
            allow=cfg.get("exec_allow"),
            ctx={"deny_paths": [*BUILTIN_DENY_PATHS, *(cfg.get("deny_paths") or [])]},
        )
    except Rejected as rej:
        audit(
            {
                "decision": "rejected",
                "exec_container": container,
                "requested": argv,
                "reason": rej.reason,
            }
        )
        _die(EXIT_REJECTED, rej.render())

    full = ["docker", "exec", container, *inner.argv]
    audit({"decision": "exec", "container": container, "argv": inner.argv})
    return run_argv(full, cfg)


def _handle_check(command: str, cfg: dict[str, Any]) -> int:
    """Dry-run the validator: report the verdict, execute nothing.

    Used by the differential test that asserts this bundled copy of the validator agrees
    with the in-process one on every input, and by `doctor` when investigating a
    disagreement. It discloses nothing the agent cannot already learn from
    `describe_commands`.
    """
    stripped = command.strip()
    validator = validate_argv if stripped.startswith("[") else validate
    subject: Any = _decode_argv(stripped) if stripped.startswith("[") else command
    try:
        result = validator(
            subject,
            EMBEDDED_SPEC,
            allow=cfg.get("allow"),
            ctx={"curl_targets": cfg.get("curl_targets") or []},
        )
    except Rejected as rej:
        print(rej.render(), file=sys.stderr)
        return EXIT_REJECTED
    print(render(result.argv))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv

    # Direct invocation, used by shim-update and by the version handshake.
    if args and args[0] in {"--version", "-V"}:
        print(SHIM_VERSION)
        return 0

    requested = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not requested and args:
        requested = " ".join(args)

    if not requested.strip():
        _die(
            EXIT_REJECTED,
            "Rejected: this key runs diagnostics only and provides no interactive shell.",
        )

    cfg = load_config()

    # Control channel. '@' cannot begin a valid binary name, so these can never collide
    # with a real command.
    if requested.startswith("@"):
        parts = shlex.split(requested[1:])
        if not parts:
            _die(EXIT_REJECTED, "Rejected: empty control command")
        verb, rest = parts[0], parts[1:]
        if verb == "version":
            print(SHIM_VERSION)
            return 0
        if verb == "ping":
            print(json.dumps({"ok": True, "version": SHIM_VERSION}))
            return 0
        if verb == "elevated":
            if len(rest) != 1:
                _die(EXIT_REJECTED, "Rejected: @elevated takes exactly one recipe name")
            return handle_elevated(rest[0], cfg)
        if verb == "run":
            # The wire format. argv arrives as a JSON array so there is no tokenisation
            # step here at all — the one place the two validators could have disagreed.
            return _handle_run(requested[1:].partition(" ")[2], cfg)
        if verb == "exec":
            return handle_exec(requested[1:].partition(" ")[2], cfg)
        if verb == "check":
            # Validate without executing. The command arrives on stdin rather than as an
            # argument so it is not parsed twice — re-splitting it here would mangle the
            # caller's quoting and make the check disagree with the real path, which is
            # precisely the divergence this exists to detect.
            return _handle_check(sys.stdin.read(), cfg)
        _die(EXIT_REJECTED, f"Rejected: unknown control command {verb!r}")

    try:
        result = validate(
            requested,
            EMBEDDED_SPEC,
            allow=cfg.get("allow"),
            ctx={"curl_targets": cfg.get("curl_targets") or []},
        )
    except Rejected as rej:
        audit({"decision": "rejected", "requested": requested, "reason": rej.reason})
        _die(EXIT_REJECTED, rej.render())
    except Exception as exc:  # fail closed on anything unexpected
        audit({"decision": "error", "requested": requested, "error": repr(exc)})
        _die(EXIT_INTERNAL, f"safereach-shim: internal error during validation: {exc}")

    # A divergence between what the client sent and what we accepted is worth noticing:
    # it means the two validators disagree, which is drift or tampering rather than a
    # routine denial.
    rendered = render(result.argv)
    if rendered != requested.strip():
        audit(
            {
                "decision": "normalised",
                "requested": requested,
                "executed": rendered,
            }
        )

    return run_argv(result.argv, cfg)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - last-resort fail-closed
        print(f"safereach-shim: unhandled error: {exc!r}", file=sys.stderr)
        raise SystemExit(EXIT_INTERNAL) from exc
