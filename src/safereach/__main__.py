"""Allow `python -m safereach`, which is the fallback registration when the
console script is not on the agent's PATH."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
