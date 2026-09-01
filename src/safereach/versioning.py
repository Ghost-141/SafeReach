"""Shim fingerprinting.

The realistic failure mode for a fleet is not a clever bypass — it is one host quietly
running a six-month-old shim with a looser spec. So the shim is stamped with a hash of
exactly the two things that determine what it will accept: the validator source and the
command spec. The server computes the same hash and refuses to talk to a host whose stamp
does not match.

Both sides must compute this identically, so it lives here and ``shim/build.py`` imports
it rather than reimplementing it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

__all__ = ["fingerprint", "validator_source_path", "validator_source"]

FINGERPRINT_LENGTH = 12


def validator_source_path() -> Path:
    return Path(__file__).with_name("validator.py")


def validator_source() -> str:
    """Every source file that decides what the shim does or reveals.

    ``redact.py`` is included because it is inlined into the shim too: a change to what
    gets masked must invalidate every deployed shim, exactly like a change to the
    allowlist.
    """
    base = validator_source_path()
    return base.read_text(encoding="utf-8") + base.with_name("redact.py").read_text(
        encoding="utf-8"
    )


def fingerprint(spec: dict[str, Any], source: str | None = None) -> str:
    """Stable short hash of (validator source + command spec).

    ``sort_keys`` and fixed separators keep this stable across YAML round-trips and
    dict ordering, so an unchanged config always produces an unchanged stamp.
    """
    digest = hashlib.sha256()
    digest.update((source if source is not None else validator_source()).encode("utf-8"))
    digest.update(b"\0")
    digest.update(
        json.dumps(spec, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    )
    return digest.hexdigest()[:FINGERPRINT_LENGTH]
