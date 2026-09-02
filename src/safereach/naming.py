"""Host aliases: stable identity, validation, and name files.

The alias is the name an agent types, the name in `list_hosts`, and the name in every
audit record. It is the primary handle on a machine, so it is worth treating as data with
rules rather than as a string that happened to fall out of discovery.

Two ideas do most of the work here:

* **A name is not an identity.** :func:`host_id` derives a stable digest from
  ``hostname:port`` at enrolment. The alias answers "what do I call this today"; the id
  answers "is this the same machine as last month". Without it a rename silently severs a
  host's audit history — and a rename is most likely exactly when something has gone
  wrong and that history matters.

* **A name reaches `ssh` as an argument.** ``user@host`` as an alias is not resolvable by
  asyncssh, which takes the connect target literally; that bug shipped once already.
  Validation is therefore strict, and rejections say which rule was broken.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Any

__all__ = [
    "InvalidName",
    "host_id",
    "validate_alias",
    "suggest_alias",
    "load_names_file",
    "RESERVED_ALIASES",
    "ALIAS_RE",
]

#: DNS-ish: safe as a YAML key, a CLI argument, and an ssh target.
ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$", re.IGNORECASE)

MAX_ALIAS_LEN = 63

#: Names that collide with flag semantics elsewhere in the CLI or the tools.
RESERVED_ALIASES = frozenset({"all", "none", "null", "default", "localhost", "any", "host"})


class InvalidName(ValueError):
    """An alias that cannot be used. Carries the rule that was broken."""

    def __init__(self, reason: str, suggestion: str | None = None) -> None:
        self.reason = reason
        self.suggestion = suggestion
        super().__init__(reason)

    def render(self) -> str:
        if self.suggestion:
            return f"{self.reason}\nTry: {self.suggestion}"
        return self.reason


# --------------------------------------------------------------------------------------
# Stable identity
# --------------------------------------------------------------------------------------


def host_id(hostname: str, port: int = 22) -> str:
    """A stable id for a machine, independent of what it is currently called.

    Derived from the connection target rather than randomly generated, so re-enrolling a
    host that was previously removed produces the same id and rejoins its history.
    """
    digest = hashlib.sha256(f"{hostname.strip().lower()}:{port}".encode())
    return "h" + digest.hexdigest()[:12]


# --------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_alias(name: str, existing: set[str] | None = None) -> str:
    """Check an alias and return it normalised, or raise :class:`InvalidName`."""
    if not name or not name.strip():
        raise InvalidName("a host name cannot be empty")

    candidate = name.strip()

    if "@" in candidate:
        # asyncssh takes the connect target literally, so `deploy@web-01` is resolved as
        # a DNS name and fails. This exact shape shipped as a bug once.
        raise InvalidName(
            f"{candidate!r} contains '@' — a host name is a label, not a login",
            f"use {candidate.split('@')[-1]!r} and keep the user in the host's config",
        )
    if any(ch.isspace() for ch in candidate):
        raise InvalidName(
            f"{candidate!r} contains whitespace",
            candidate.replace(" ", "-").lower(),
        )
    if len(candidate) > MAX_ALIAS_LEN:
        raise InvalidName(f"{candidate!r} is too long (max {MAX_ALIAS_LEN} characters)")
    if candidate.lower() in RESERVED_ALIASES:
        raise InvalidName(f"{candidate!r} is reserved — it collides with a flag or tool argument")
    if not ALIAS_RE.match(candidate):
        cleaned = re.sub(r"[^a-z0-9._-]+", "-", candidate.lower()).strip("-.")
        raise InvalidName(
            f"{candidate!r} is not a valid host name — use letters, digits, dot, dash "
            "or underscore, starting with a letter or digit",
            cleaned or None,
        )
    if existing and candidate in existing:
        raise InvalidName(f"{candidate!r} is already the name of another host")

    return candidate


def is_bare_address(name: str) -> bool:
    """Legal as a name, but the very thing this feature exists to replace."""
    return _is_address(name)


# --------------------------------------------------------------------------------------
# Suggestions
# --------------------------------------------------------------------------------------


def suggest_alias(ssh_alias: str | None, hostname: str | None) -> str:
    """Best available name, in descending order of usefulness.

    An explicit `~/.ssh/config` entry is a name a human already chose, so it wins. Failing
    that, the first DNS label is usually meaningful (`web-01.internal` → `web-01`). The
    raw address is the last resort — and is what the current implementation always
    produced, which is why hosts end up called `203.96.189.202`.
    """
    for candidate in (ssh_alias, hostname):
        if not candidate:
            continue
        value = candidate.strip()
        if not value or _is_address(value):
            continue
        label = value.split(".")[0].split("@")[-1]
        try:
            return validate_alias(label)
        except InvalidName:
            continue

    # Last resort. This must never return something validate_alias would reject —
    # a suggestion the code cannot accept is worse than no suggestion at all.
    fallback = (hostname or ssh_alias or "").strip().split("@")[-1]
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", fallback.lower()).strip("-.")
    if not cleaned or cleaned in RESERVED_ALIASES:
        cleaned = f"host-{host_id(fallback or 'unknown')[1:7]}"
    return cleaned[:MAX_ALIAS_LEN]


# --------------------------------------------------------------------------------------
# Name files
# --------------------------------------------------------------------------------------


def load_names_file(path: Path, known: set[str] | None = None) -> tuple[dict[str, str], list[str]]:
    """Parse a names file into ``{identifier: alias}``, plus notes worth printing.

    Accepts three shapes, because people write all three:

    * canonical flat — ``10.0.1.5: prod-web``
    * reversed flat — ``prod-web: 10.0.1.5``
    * explicit long — ``hosts: {prod-web: {match: 10.0.1.5}}``

    Direction for the flat forms is resolved against the identifiers actually known
    (``known``), falling back to which side parses as an IP address. When neither test
    settles it, the entry is **rejected** rather than guessed: a mapping read backwards
    points the agent at the wrong machine, which is far worse than an error.
    """
    import yaml

    raw = yaml.safe_load(Path(path).expanduser().read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping")

    notes: list[str] = []
    mapping: dict[str, str] = {}

    # Explicit long form removes all ambiguity, so it is handled first and separately.
    if "hosts" in raw and isinstance(raw["hosts"], dict):
        for alias, body in raw["hosts"].items():
            if not isinstance(body, dict) or "match" not in body:
                raise ValueError(f"{path}: host {alias!r} needs a 'match:' identifier")
            mapping[str(body["match"])] = validate_alias(str(alias))
        return mapping, notes

    known = known or set()
    reversed_count = 0

    for left, right in raw.items():
        left, right = str(left), str(right)
        left_known, right_known = left in known, right in known

        if left_known and not right_known:
            identifier, alias = left, right
        elif right_known and not left_known:
            identifier, alias = right, left
            reversed_count += 1
        elif _is_address(left) and not _is_address(right):
            identifier, alias = left, right
        elif _is_address(right) and not _is_address(left):
            identifier, alias = right, left
            reversed_count += 1
        else:
            raise ValueError(
                f"{path}: cannot tell which side of '{left}: {right}' is the host and "
                "which is the name. Use the explicit form:\n"
                f"  hosts:\n    {right}: {{ match: {left} }}"
            )

        mapping[identifier] = validate_alias(alias)

    if reversed_count:
        notes.append(
            f"read {reversed_count} entr{'y' if reversed_count == 1 else 'ies'} as "
            "name → host (the reverse of the canonical form)"
        )
    return mapping, notes


def write_names_file(hosts: dict[str, Any], path: Path) -> None:
    """Dump the current mapping as a starting point for editing.

    The realistic workflow is edit-then-apply, not authoring from scratch.
    """
    lines = [
        "# Host names for safereach. Edit the names on the right, then apply with:",
        "#     safereach rename --from this-file.yaml",
        "#",
        "# The left side identifies the machine and should not be changed.",
        "hosts:",
    ]
    for alias, cfg in sorted(hosts.items()):
        target = getattr(cfg, "hostname", None) or getattr(cfg, "ssh_config_host", None) or alias
        lines.append(f"  {alias}: {{ match: {target} }}")
    Path(path).expanduser().write_text("\n".join(lines) + "\n", encoding="utf-8")
