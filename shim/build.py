#!/usr/bin/env python3
"""Bundle the validator and the command spec into a single stdlib-only ``safereach-shim``.

The output is one self-contained Python file with no third-party imports, so it can be
scp'd onto any host with a Python 3 interpreter and nothing else. That constraint is the
whole reason ``validator.py`` is stdlib-only: installing and upgrading a package on every
production host is an operational cost that will quietly not happen, whereas copying one
file will.

Usage::

    python shim/build.py                 # -> shim/dist/safereach-shim
    python shim/build.py --out /tmp/x    # explicit destination
    python shim/build.py --print-version # just the fingerprint
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from safereach.config import load_command_spec  # noqa: E402
from safereach.versioning import fingerprint, validator_source_path  # noqa: E402

REDACT_PATH = validator_source_path().with_name("redact.py")

FUTURE_RE = re.compile(r"^from __future__ import .*$\n", re.MULTILINE)
IMPORT_SHIM_RE = re.compile(
    r"^# --- BEGIN IMPORT SHIM.*?^# --- END IMPORT SHIM.*?$\n",
    re.MULTILINE | re.DOTALL,
)

HEADER = '''#!/usr/bin/env python3
"""safereach-shim — GENERATED FILE, DO NOT EDIT.

Built by shim/build.py from validator.py + commands.yaml. Edit those and rebuild:

    python shim/build.py && safereach shim-update --all

Fingerprint: {version}
"""
from __future__ import annotations
'''


def build(spec_path: Path | None = None) -> tuple[str, str]:
    """Return ``(source, fingerprint)`` for the bundled shim."""
    spec = load_command_spec(spec_path)
    validator_src = validator_source_path().read_text(encoding="utf-8")
    redact_src = REDACT_PATH.read_text(encoding="utf-8")
    version = fingerprint(spec, validator_src + redact_src)

    shim_src = (Path(__file__).parent / "shim_main.py").read_text(encoding="utf-8")

    # The source-tree shim imports the validator from the package so it stays runnable
    # and testable in place. In the bundle the validator source is inlined instead, so
    # that import block is removed rather than satisfied.
    shim_src, n = IMPORT_SHIM_RE.subn("", shim_src)
    if n != 1:
        raise SystemExit(
            f"expected exactly one IMPORT SHIM block in shim_main.py, found {n}. "
            "The markers must not be edited — build.py relies on them."
        )

    # `from __future__` must be the first statement in the file, so it is hoisted into
    # the header and removed from both inputs.
    validator_body = FUTURE_RE.sub("", validator_src)
    redact_body = FUTURE_RE.sub("", redact_src)
    shim_body = FUTURE_RE.sub("", shim_src)

    shim_body = _replace_assignment(
        shim_body,
        "EMBEDDED_SPEC",
        "EMBEDDED_SPEC = json.loads(_EMBEDDED_SPEC_JSON)",
    )
    shim_body = _replace_assignment(shim_body, "SHIM_VERSION", f'SHIM_VERSION = "{version}"')

    spec_json = json.dumps(spec, sort_keys=True, separators=(",", ":"), default=str)

    parts = [
        HEADER.format(version=version),
        "\n# " + "=" * 84,
        "# Inlined from src/safereach/validator.py",
        "# " + "=" * 84 + "\n",
        validator_body,
        "\n# " + "=" * 84,
        "# Inlined from src/safereach/redact.py",
        "# " + "=" * 84 + "\n",
        redact_body,
        "\n# " + "=" * 84,
        "# Embedded command spec (from config/commands.yaml)",
        "# " + "=" * 84 + "\n",
        f"_EMBEDDED_SPEC_JSON = r'''{spec_json}'''\n",
        "\n# " + "=" * 84,
        "# Inlined from shim/shim_main.py",
        "# " + "=" * 84 + "\n",
        shim_body,
    ]
    return "\n".join(parts), version


def _replace_assignment(source: str, name: str, replacement: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}\s*[:=].*$", re.MULTILINE)
    new_source, count = pattern.subn(replacement, source, count=1)
    if count != 1:
        raise SystemExit(f"could not find the {name} placeholder in shim_main.py")
    return new_source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO / "shim" / "dist" / "safereach-shim")
    parser.add_argument("--spec", type=Path, default=None)
    parser.add_argument("--print-version", action="store_true")
    args = parser.parse_args()

    source, version = build(args.spec)

    if args.print_version:
        print(version)
        return 0

    # Compile before writing: shipping a shim that fails to import would fail closed,
    # but it would fail closed on every host at once.
    try:
        compile(source, str(args.out), "exec")
    except SyntaxError as exc:
        print(f"build produced invalid Python: {exc}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(source, encoding="utf-8")
    args.out.chmod(0o755)
    print(f"built {args.out} ({len(source)} bytes, fingerprint {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
