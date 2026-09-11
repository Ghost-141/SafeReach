"""Bundle the validator, the redaction pass and the command spec into ``safereach-shim``.

The output is one self-contained, stdlib-only Python file that can be copied onto any host
with a Python 3 interpreter and nothing else. That constraint is the whole reason
``validator.py`` and ``redact.py`` are stdlib-only: installing a package on every
production host is an operational cost that will quietly not happen, whereas copying one
file will.

This lives **inside the package**, not only in ``shim/build.py``, for a reason that bit
0.1.0 and 0.1.1: the wheel shipped ``shim_main.py`` but no way to assemble it, so
``enroll``, ``provision`` and ``shim-update`` all failed from a ``uvx`` install with
"cannot locate shim/build.py". Every input the bundle needs — ``validator.py``,
``redact.py``, ``commands.yaml``, ``shim_main.py`` — is already in the wheel, so the shim
is built here at runtime from the exact sources the server is running. There is no
packaged artifact that can go stale, and the fingerprint the shim reports matches the one
the server expects by construction rather than by a build step remembering to run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .config import load_command_spec, resolve_data_file
from .versioning import fingerprint, validator_source_path

__all__ = ["build", "write"]

_FUTURE_RE = re.compile(r"^from __future__ import .*$\n", re.MULTILINE)
_IMPORT_SHIM_RE = re.compile(
    r"^# --- BEGIN IMPORT SHIM.*?^# --- END IMPORT SHIM.*?$\n",
    re.MULTILINE | re.DOTALL,
)

_HEADER = '''#!/usr/bin/env python3
"""safereach-shim — GENERATED FILE, DO NOT EDIT.

Assembled by safereach from validator.py + redact.py + commands.yaml + shim_main.py.
Edit those and redeploy:

    safereach shim-update --all

Fingerprint: {version}
"""
from __future__ import annotations
'''


def build(spec_path: Path | None = None) -> tuple[str, str]:
    """Return ``(source, fingerprint)`` for the bundled shim.

    ``spec_path`` overrides the packaged ``commands.yaml``; tests use it to prove a spec
    change flips the fingerprint.
    """
    spec = load_command_spec(spec_path)
    validator_src = validator_source_path().read_text(encoding="utf-8")
    redact_src = validator_source_path().with_name("redact.py").read_text(encoding="utf-8")
    version = fingerprint(spec, validator_src + redact_src)

    shim_src = resolve_data_file("shim_main.py").read_text(encoding="utf-8")

    # The source-tree shim imports the validator from the package so it stays runnable
    # and testable in place. In the bundle the validator source is inlined instead, so
    # that import block is removed rather than satisfied.
    shim_src, n = _IMPORT_SHIM_RE.subn("", shim_src)
    if n != 1:
        raise RuntimeError(
            f"expected exactly one IMPORT SHIM block in shim_main.py, found {n}. "
            "The markers must not be edited — the bundler relies on them."
        )

    # `from __future__` must be the first statement in the file, so it is hoisted into
    # the header and removed from every input.
    validator_body = _FUTURE_RE.sub("", validator_src)
    redact_body = _FUTURE_RE.sub("", redact_src)
    shim_body = _FUTURE_RE.sub("", shim_src)

    shim_body = _replace_assignment(
        shim_body, "EMBEDDED_SPEC", "EMBEDDED_SPEC = json.loads(_EMBEDDED_SPEC_JSON)"
    )
    shim_body = _replace_assignment(shim_body, "SHIM_VERSION", f'SHIM_VERSION = "{version}"')

    spec_json = json.dumps(spec, sort_keys=True, separators=(",", ":"), default=str)

    parts = [
        _HEADER.format(version=version),
        "\n# " + "=" * 84,
        "# Inlined from safereach/validator.py",
        "# " + "=" * 84 + "\n",
        validator_body,
        "\n# " + "=" * 84,
        "# Inlined from safereach/redact.py",
        "# " + "=" * 84 + "\n",
        redact_body,
        "\n# " + "=" * 84,
        "# Embedded command spec (from commands.yaml)",
        "# " + "=" * 84 + "\n",
        f"_EMBEDDED_SPEC_JSON = r'''{spec_json}'''\n",
        "\n# " + "=" * 84,
        "# Inlined from shim_main.py",
        "# " + "=" * 84 + "\n",
        shim_body,
    ]
    source = "\n".join(parts)

    # Compile before returning: a shim that fails to import would fail closed, but it
    # would fail closed on every host at once.
    compile(source, "safereach-shim", "exec")
    return source, version


def write(out: Path, spec_path: Path | None = None) -> str:
    """Build and write the shim to ``out`` (mode 0755). Returns the fingerprint."""
    source, version = build(spec_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(source, encoding="utf-8")
    out.chmod(0o755)
    return version


def _replace_assignment(source: str, name: str, replacement: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}\s*[:=].*$", re.MULTILINE)
    new_source, count = pattern.subn(replacement, source, count=1)
    if count != 1:
        raise RuntimeError(f"could not find the {name} placeholder in shim_main.py")
    return new_source
