"""Scrub secrets out of command output before it reaches the agent.

Defence in depth, not a primary control. The allowlist already keeps the agent away from
``/etc/shadow`` and private keys — but a legitimate diagnostic command can still surface a
credential incidentally. ``systemctl show`` prints ``Environment=``; ``docker inspect``
prints the container's whole environment; a stack trace in a log can contain a connection
string. Once that text is in the agent's context it is also in a transcript, so it is
worth removing on the way past.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections import Counter
from typing import Any

__all__ = [
    "redact_text",
    "redact_docker_inspect",
    "mask_env_keys",
    "mask_by_digest",
    "digest_value",
    "is_maskable_value",
    "shannon_entropy",
    "MASK",
]

MASK = "***REDACTED***"

#: Ordered so the most specific patterns win. Each captures the "keep" prefix in group 1
#: and replaces only the secret itself, which keeps output diagnosable — an agent can
#: still see that DATABASE_URL is set, just not what it is.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        f"{MASK} (private key)",
    ),
    (
        # The keyword is allowed to sit inside a longer identifier. `\b` would not match
        # before PASSWORD in DB_PASSWORD, because `_` is a word character — which meant
        # the single most common spelling of a leaked credential
        # (DB_PASSWORD=, AWS_SECRET_ACCESS_KEY=, MYSQL_ROOT_PASSWORD=) passed straight
        # through. Surrounding identifier characters are matched explicitly instead.
        re.compile(
            r"([A-Za-z0-9_.\-]*"
            r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
            r"auth[_-]?token|client[_-]?secret|credential)"
            r"[A-Za-z0-9_.\-]*)(\s*[=:]\s*)(\S+)",
            re.IGNORECASE,
        ),
        rf"\1\2{MASK}",
    ),
    # Connection strings: keep scheme and host, drop the credentials.
    (
        re.compile(r"\b([a-z][a-z0-9+.\-]*://)([^:/@\s]+):([^@\s]+)@"),
        rf"\1\2:{MASK}@",
    ),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), MASK),
    (re.compile(r"\b(ghp_[A-Za-z0-9]{20,})\b"), MASK),
    (re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), MASK),
    (re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+)\b"), MASK),
    (
        re.compile(r"^(Authorization\s*:\s*)(\S+.*)$", re.IGNORECASE | re.MULTILINE),
        rf"\1{MASK}",
    ),
)


def redact_text(text: str, extra: list[str] | None = None) -> str:
    """Apply the generic scrub, plus any host-configured extra patterns."""
    if not text:
        return text
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    for raw in extra or []:
        try:
            out = re.sub(raw, MASK, out)
        except re.error:
            # A malformed user pattern must not take the whole result down.
            continue
    return out


def redact_docker_inspect(text: str, env_allowlist: list[str] | None = None) -> str:
    """Mask ``Config.Env`` values in ``docker inspect`` output.

    This needs structural handling rather than the generic regexes above, for two
    reasons. It is one of the most useful diagnostic commands, so it *will* be called
    constantly — and its ``Env`` array is exactly where ``DATABASE_URL`` and
    ``AWS_SECRET_ACCESS_KEY`` live, under names the generic patterns do not match.

    Variable **names** stay visible so the agent can still reason about what is
    configured; only values are masked, and only for names outside the host's
    ``env_allowlist``.
    """
    allowed = set(env_allowlist or [])
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Not JSON (a --format query, or an error). Fall back to a line-wise pass so
        # something like `DATABASE_URL=postgres://...` is still caught.
        return _mask_env_lines(text, allowed)

    _walk_and_mask(data, allowed)
    return json.dumps(data, indent=2)


def _walk_and_mask(node: Any, allowed: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "Env" and isinstance(value, list):
                node[key] = [_mask_env_entry(e, allowed) for e in value]
            else:
                _walk_and_mask(value, allowed)
    elif isinstance(node, list):
        for item in node:
            _walk_and_mask(item, allowed)


def _mask_env_entry(entry: Any, allowed: set[str]) -> Any:
    if not isinstance(entry, str) or "=" not in entry:
        return entry
    name, _, _value = entry.partition("=")
    if name in allowed:
        return entry
    return f"{name}={MASK}"


_ENV_LINE_RE = re.compile(r"^(\s*)([A-Z_][A-Z0-9_]{2,})=(.*)$", re.MULTILINE)


def _mask_env_lines(text: str, allowed: set[str]) -> str:
    def sub(match: re.Match[str]) -> str:
        indent, name, _value = match.groups()
        if name in allowed:
            return match.group(0)
        return f"{indent}{name}={MASK}"

    return _ENV_LINE_RE.sub(sub, text)


# --------------------------------------------------------------------------------------
# Masking by variable name, learned from the host's own .env files
# --------------------------------------------------------------------------------------


def mask_env_keys(text: str, keys: list[str] | None) -> str:
    """Mask the value of every named variable, in whatever shape it appears.

    The generic patterns above match on the *word* — ``password``, ``token``, ``secret``.
    That misses everything an application names differently: ``SALT``, ``ENCRYPTION_AT``,
    ``NEXTAUTH_URL``, ``SMTP_USER``. So enrolment reads the key NAMES out of the host's
    .env files (never the values) and hands them here, which turns "mask things that look
    secret" into "mask exactly the things this host treats as configuration".

    The values themselves are never stored, transmitted, or hashed — only names, which
    are not secret. That is what makes this safe to keep in a config file.

    Four shapes are covered because env values surface in all of them:
    ``KEY=value`` (shell, ``docker inspect`` Env, ``systemctl show``), ``KEY: value``
    (YAML, compose), ``"KEY": "value"`` (JSON), and ``KEY = value`` (ini).
    """
    if not keys or not text:
        return text

    out = text
    for key in keys:
        if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-]{0,96}", key):
            continue
        k = re.escape(key)
        # JSON: "KEY": "value"  /  "KEY": value
        out = re.sub(rf'("{k}"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}}\s]+)', rf'\1"{MASK}"', out)
        # KEY=value  (stops at whitespace, quote or comma — covers shell and JSON arrays)
        out = re.sub(rf"(\b{k}=)([^\s\"',]+)", rf"\1{MASK}", out)
        # KEY: value  and  KEY = value
        out = re.sub(rf"(^\s*{k}\s*[:=]\s*)(\S.*)$", rf"\1{MASK}", out, flags=re.MULTILINE)
    return out


# --------------------------------------------------------------------------------------
# LAYER 3 — masking by value digest
# --------------------------------------------------------------------------------------

#: Values below this length, or below this entropy, are excluded. Masking `postgres` or
#: `true` everywhere would make every diagnostic unreadable, which is how a control ends
#: up switched off. Short low-entropy values stay covered by name-based masking.
MIN_SECRET_LEN = 12
MIN_SECRET_ENTROPY = 3.0

#: Common configuration values that are long enough to pass the length gate but carry no
#: secrecy. Masking these would hide exactly the facts an operator needs.
VALUE_STOPLIST = frozenset(
    {
        "development",
        "production",
        "staging",
        "localhost",
        "postgres",
        "postgresql",
        "127.0.0.1",
        "0.0.0.0",
        "true",
        "false",
        "null",
        "none",
        "default",
        "disabled",
        "enabled",
        "/usr/local/bin",
        "/usr/local/sbin",
        "info",
        "debug",
        "warning",
        "error",
    }
)

#: Split on anything that can bound a value in the wild — URL punctuation, quotes, JSON
#: and YAML syntax — so a secret inside `postgres://user:SECRET@host` is isolated as its
#: own token rather than hiding inside a longer string.
_TOKEN_SPLIT_RE = re.compile(r"[\s\"'`,;:|&<>(){}\[\]=@/?\\]+")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Distinguishes `hunter2!` from a 32-byte key."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_maskable_value(value: str) -> bool:
    """Whether a value is worth matching by digest.

    The gate exists to protect the output's usefulness, not the secret: anything rejected
    here is still masked by name (Layer 2) if it appears as ``KEY=value``. What this
    prevents is a low-entropy value like ``production`` being redacted out of every line
    it appears in.
    """
    if len(value) < MIN_SECRET_LEN:
        return False
    if value.lower() in VALUE_STOPLIST:
        return False
    if value.startswith("/") and " " not in value:  # filesystem paths
        return False
    return shannon_entropy(value) >= MIN_SECRET_ENTROPY


def digest_value(value: str, key: bytes) -> str:
    """HMAC of a secret value. Only this ever leaves the file the value lives in."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def mask_by_digest(text: str, digests: list[str] | None, key: str | None) -> str:
    """Mask any token whose HMAC matches a known secret.

    This is the layer that catches a value appearing **without** its variable name — a
    password in a stack trace, a token quoted in an application log. Name-based masking
    cannot see those, because there is no name to match on.

    Plaintext values are never stored: enrolment computes the digests as root, where the
    values already are, and only the digests travel. The diag account holds hashes of
    secrets it cannot itself read.
    """
    if not text or not digests or not key:
        return text

    wanted = set(digests)
    key_bytes = key.encode("utf-8")
    out_parts: list[str] = []
    position = 0

    for match in _TOKEN_SPLIT_RE.finditer(text):
        token = text[position : match.start()]
        if token and is_maskable_value(token) and digest_value(token, key_bytes) in wanted:
            out_parts.append(MASK)
        else:
            out_parts.append(token)
        out_parts.append(match.group(0))
        position = match.end()

    tail = text[position:]
    if tail and is_maskable_value(tail) and digest_value(tail, key_bytes) in wanted:
        out_parts.append(MASK)
    else:
        out_parts.append(tail)

    return "".join(out_parts)
