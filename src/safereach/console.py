"""Terminal output — bound to stderr, always.

**The rule this module exists to enforce: nothing here may ever write to stdout.**

In server mode stdout carries JSON-RPC. A single byte of decoration on it corrupts the
stream and every agent reports an opaque parse failure with no clue where it came from.
`rich` writes to stdout by default, so binding the console to stderr once, here, is safer
than remembering to pass ``file=`` at two hundred call sites.

`tests/test_stdio_clean.py` asserts this by spawning the server and requiring stdout to be
pure JSON-RPC, which is what turns the convention into a guarantee.

Colour is suppressed automatically when output is piped, when ``NO_COLOR`` is set, or on a
dumb terminal — so `safereach doctor | tee log` stays readable and greppable.
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.table import Table
from rich.theme import Theme

__all__ = ["console", "status_table", "STATUS_STYLES", "status_mark", "is_interactive"]

#: One vocabulary for state, used by every command. `doctor`, `discover`, `enroll` and
#: `audit` all report the same kinds of outcome, and they should not each invent a colour.
THEME = Theme(
    {
        "ok": "bold green",
        "warn": "bold yellow",
        "bad": "bold red",
        "muted": "dim",
        "heading": "bold cyan",
        "cmd": "bold",
        "path": "cyan",
        "host": "bold magenta",
    }
)

console = Console(
    stderr=True,  # never stdout — see the module docstring
    theme=THEME,
    # rich already disables colour when piped; NO_COLOR is honoured explicitly because
    # users set it expecting it to be obeyed everywhere.
    no_color=bool(os.environ.get("NO_COLOR")),
    soft_wrap=False,
    highlight=False,  # no automatic number/path colouring — it fights the explicit styles
)

#: Plain-text fallbacks, used when colour is unavailable. The word carries the meaning so
#: the output still reads correctly in a log file or a CI transcript.
STATUS_STYLES = {
    "ok": ("ok", "ok"),
    "warn": ("!!", "warn"),
    "bad": ("XX", "bad"),
    "skip": ("--", "muted"),
}


def status_mark(status: str) -> str:
    """A styled status marker, e.g. ``[ok]ok[/ok]``.

    Named `status_mark` rather than `mark` because several commands already use `mark`
    as a local for the same idea, and the shadowing is silent until it is not.
    """
    label, style = STATUS_STYLES.get(status, ("??", "muted"))
    return f"[{style}]{label}[/{style}]"


def status_table(*columns: str, title: str | None = None, show_header: bool | None = None) -> Table:
    """A table styled consistently across commands.

    No borders, deliberately. A box drawn around six rows of status is noise, and its
    absence keeps output pasteable into an issue or a log without turning into rubble
    when the terminal is narrower than the frame.

    Headers are shown only when the columns are actually named — an unnamed column still
    reserves a header row, which renders as an empty coloured bar.
    """
    from rich import box

    named = any(c.strip() for c in columns)
    table = Table(
        title=title,
        box=box.SIMPLE_HEAD if named else None,
        title_style="heading",
        title_justify="left",
        header_style="heading",
        show_header=named if show_header is None else show_header,
        pad_edge=False,
        show_edge=False,
        padding=(0, 2, 0, 0),
    )
    for column in columns:
        table.add_column(column, overflow="fold")
    return table


def is_interactive() -> bool:
    """Whether a human is watching, for progress display and prompting."""
    return sys.stderr.isatty() and not os.environ.get("SAFEREACH_NO_TTY")
