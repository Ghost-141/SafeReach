#!/usr/bin/env python3
"""Build ``safereach-shim`` from a source checkout.

Thin wrapper around :mod:`safereach.shimbuild`, which is where the bundling actually
happens — inside the package, so the published wheel can build the shim too. This file
exists so ``python shim/build.py`` keeps working for CI and for anyone who wants the
artifact without installing the CLI.

Usage::

    python shim/build.py                 # -> shim/dist/safereach-shim
    python shim/build.py --out /tmp/x    # explicit destination
    python shim/build.py --print-version # just the fingerprint
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from safereach import shimbuild  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO / "shim" / "dist" / "safereach-shim")
    parser.add_argument("--spec", type=Path, default=None)
    parser.add_argument("--print-version", action="store_true")
    args = parser.parse_args()

    try:
        if args.print_version:
            print(shimbuild.build(args.spec)[1])
            return 0
        version = shimbuild.write(args.out, args.spec)
    except (RuntimeError, SyntaxError) as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 1

    print(f"built {args.out} ({args.out.stat().st_size} bytes, fingerprint {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
