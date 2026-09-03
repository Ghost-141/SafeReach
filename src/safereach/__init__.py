"""SafeReach — read-only remote diagnostics over SSH, exposed as an MCP server."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Read from installed package metadata rather than a literal here.
    #
    # A hard-coded string is a second source of truth that drifts silently: 0.1.1 shipped
    # reporting `safereach 0.1.0`, and because `install` pins agents to __version__, it
    # would have wired every agent to `uvx safereach@0.1.0` — the previous release.
    # Derived, it cannot disagree with the wheel it came from.
    __version__ = version("safereach")
except PackageNotFoundError:  # running from a source tree with no install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
