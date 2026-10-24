"""Turn what a host's log scan found into a checklist, and the chosen items into policy.

The scan itself runs on the host (:mod:`safereach.hostlogs`) and reports facts only. This
module is the operator's side: a catalogue of well-known locations, the rules that turn
facts into named candidates and decide which are pre-ticked, the checklist dialogue, and
the round trip that runs ``hostlogs`` over SSH.

Everything here that decides what may be READ goes through ``validator.check_log_source``
— the same function the shim uses on its own policy — so a candidate that would be
refused on the host is never offered in the first place.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .validator import BUILTIN_DENY_PATHS, Rejected, check_log_dir, check_log_source

__all__ = [
    "CATALOGUE",
    "Candidate",
    "build_candidates",
    "choose",
    "parse_source_arg",
    "render_checklist",
    "run_hostlogs",
    "yaml_lines",
]

#: Anything written within this window is "in use" and pre-ticked.
RECENT_S = 24 * 3600


@dataclass(frozen=True)
class CatalogueEntry:
    name: str
    dirs: tuple[str, ...] = ()
    glob: str = "*.log*"
    units: tuple[str, ...] = ()
    #: Pre-ticked whenever it exists, recent or not.
    always: bool = False
    #: Never pre-ticked: useful, but not usually what an investigation starts with.
    never: bool = False


#: Well-known locations, offered only when the scan confirms they exist and are non-empty.
CATALOGUE: tuple[CatalogueEntry, ...] = (
    CatalogueEntry("syslog", dirs=("/var/log/",), glob="syslog*", always=True),
    CatalogueEntry("messages", dirs=("/var/log/",), glob="messages*", always=True),
    CatalogueEntry("auth", dirs=("/var/log/",), glob="auth.log*", never=True),
    CatalogueEntry("secure", dirs=("/var/log/",), glob="secure*", never=True),
    CatalogueEntry("nginx", dirs=("/var/log/nginx/",), units=("nginx.service",)),
    CatalogueEntry("apache", dirs=("/var/log/apache2/", "/var/log/httpd/")),
    CatalogueEntry(
        "postgres",
        dirs=("/var/log/postgresql/",),
        units=("postgresql.service",),
    ),
    CatalogueEntry(
        "mysql",
        dirs=("/var/log/mysql/", "/var/log/mariadb/"),
        units=("mysql.service", "mysqld.service", "mariadb.service"),
    ),
    CatalogueEntry(
        "redis", dirs=("/var/log/redis/",), units=("redis.service", "redis-server.service")
    ),
)


@dataclass
class Candidate:
    name: str
    spec: dict[str, str]
    detail: str
    selected: bool = False
    warning: str | None = None

    def describe(self) -> str:
        if self.spec["kind"] == "file":
            return f"{self.spec['dir']}{self.spec['glob']}"
        if self.spec["kind"] == "docker":
            return f"container {self.spec['container']}"
        return f"journal {self.spec['unit']}"


# --------------------------------------------------------------------------------------
# Facts -> candidates
# --------------------------------------------------------------------------------------


def _age(now: float, mtime: float | None) -> str:
    if mtime is None:
        return "empty"
    secs = max(0, int(now - mtime))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"written {secs // size}{unit} ago"
    return "written just now"


def _size(n: int) -> str:
    for unit in ("GB", "MB", "KB"):
        scale = {"GB": 1 << 30, "MB": 1 << 20, "KB": 1 << 10}[unit]
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n} B"


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", text.lower()).strip("-._")
    return (slug or "app")[:40]


_NAME_NOISE = {"log", "logs", "opt", "srv", "var", "www", "home", "data", "app", "storage"}


def _name_for_dir(directory: str) -> str:
    """`/opt/shop/api/logs/` → `shop-api`; `/var/log/billing/` → `billing`.

    The two most specific path components that are not generic container words. Named
    after the path rather than the unit, because one unit (a PM2 daemon) often writes
    several apps' logs, and its own log directory would otherwise collide with theirs.
    """
    parts = [p for p in directory.strip("/").split("/") if p and p.lower() not in _NAME_NOISE]
    if directory.startswith("/home/") and parts:
        parts = parts[1:]
    return _slug("-".join(parts[-2:])) if parts else ""


def _glob_for(names: list[str]) -> str:
    return "*.log*" if any(".log" in n for n in names) else "*"


def _matching(facts: dict[str, Any], glob: str) -> bool:
    from fnmatch import fnmatchcase

    return any(fnmatchcase(n, glob) for n in facts.get("names") or [])


def build_candidates(
    facts: dict[str, Any], existing: dict[str, dict[str, str]] | None = None
) -> tuple[list[Candidate], list[str]]:
    """Return ``(candidates, skipped)`` — skipped lines say what was found but not offered."""
    existing = existing or {}
    now = float(facts.get("now") or time.time())
    dirs: dict[str, dict[str, Any]] = facts.get("dirs") or {}
    out: list[Candidate] = []
    skipped: list[str] = []
    taken: set[str] = set()
    covered: set[tuple[str, str]] = set()

    def add(
        name: str, raw: dict[str, str], detail: str, selected: bool, warning: str | None
    ) -> None:
        base, n = _slug(name), 2
        name = base
        while name in taken:
            name, n = f"{base}-{n}", n + 1
        try:
            spec = check_log_source(name, raw)
        except Rejected as rej:
            skipped.append(
                f"{raw.get('dir') or raw.get('unit') or raw.get('container')}: {rej.reason}"
            )
            return
        taken.add(name)
        if spec["kind"] == "file":
            covered.add((spec["dir"], spec["glob"]))
        out.append(Candidate(name, spec, detail, selected, warning))

    def file_detail(d: dict[str, Any], who: str = "") -> tuple[str, bool, str | None]:
        recent = d.get("newest_mtime") is not None and now - d["newest_mtime"] < RECENT_S
        parts = [p for p in (who, _age(now, d.get("newest_mtime")), _size(d.get("bytes", 0))) if p]
        warning = None
        if d.get("hazards"):
            warning = f"directory also holds {', '.join(d['hazards'][:3])} — never readable"
        if d.get("readable") is False:
            warning = "this account cannot read it" + (f"; {warning}" if warning else "")
        return "  ".join(parts), recent, warning

    # Sources already in hosts.yaml stay ticked, whatever the scan says now.
    for name, spec in existing.items():
        taken.add(name)
        if spec["kind"] == "file":
            covered.add((spec["dir"], spec["glob"]))
        out.append(Candidate(name, dict(spec), "already configured", True))

    for entry in CATALOGUE:
        for directory in entry.dirs:
            d = dirs.get(directory) or {}
            if not d.get("files") or not _matching(d, entry.glob):
                continue
            if (directory, entry.glob) in covered:
                break
            detail, recent, warning = file_detail(d)
            selected = not entry.never and (entry.always or recent)
            add(
                entry.name,
                {"kind": "file", "dir": directory, "glob": entry.glob},
                detail,
                selected,
                warning,
            )
            break

    # Directories processes are writing to right now, grouped by directory.
    by_dir: dict[str, dict[str, Any]] = {}
    for log in facts.get("open_logs") or []:
        directory = log["path"].rsplit("/", 1)[0] + "/"
        by_dir.setdefault(directory, log)
    for directory in facts.get("pm2_dirs") or []:
        by_dir.setdefault(directory, {"comm": "pm2", "unit": None})
    for directory, log in sorted(by_dir.items()):
        if directory.startswith("/var/log/") and any(
            directory == dir_ for e in CATALOGUE for dir_ in e.dirs
        ):
            continue
        d = dirs.get(directory) or {}
        glob = _glob_for(d.get("names") or [])
        if (directory, glob) in covered:
            continue
        try:
            check_log_dir(directory)
        except Rejected as rej:
            skipped.append(f"{directory}: {rej.reason}")
            continue
        if "/.pm2/logs/" in directory:
            owner = directory.split("/")[2] if directory.startswith("/home/") else "root"
            name = f"pm2-{owner}"
        else:
            name = _name_for_dir(directory) or log.get("comm") or "app"
        who = " ".join(
            x for x in (log.get("comm"), f"({log['unit']})" if log.get("unit") else "") if x
        )
        detail, recent, warning = file_detail(d, who)
        add(name, {"kind": "file", "dir": directory, "glob": glob}, detail, recent, warning)

    # Services: application units, and catalogue services that also log to journald.
    empty = facts.get("journal_empty") or {}
    units = [u["unit"] for u in facts.get("app_units") or []]
    units += [
        u
        for e in CATALOGUE
        for u in e.units
        if u in (facts.get("running_units") or []) and u not in units
    ]
    for unit in units:
        if any(c.spec.get("unit") == unit for c in out):
            continue
        is_empty = empty.get(unit)
        detail = "empty — this service logs to files, not journald" if is_empty else "journald"
        add(
            unit.removesuffix(".service"),
            {"kind": "journal", "unit": unit},
            detail,
            is_empty is False,
            None,
        )

    for container in facts.get("containers") or []:
        if any(c.spec.get("container") == container for c in out):
            continue
        add(container, {"kind": "docker", "container": container}, "docker logs", False, None)

    return out, skipped


# --------------------------------------------------------------------------------------
# The checklist
# --------------------------------------------------------------------------------------


def render_checklist(alias: str, candidates: list[Candidate], skipped: list[str]) -> str:
    lines = [f"{alias} — log sources found"]
    if not candidates:
        lines.append("   (none)")
    width = max((len(c.name) for c in candidates), default=8)
    for i, c in enumerate(candidates, 1):
        mark = "x" if c.selected else " "
        row = f"  {i:>2} [{mark}] {c.name:<{width}}  {c.spec['kind']:<7} {c.describe()}"
        if c.detail:
            row += f"   {c.detail}"
        if c.warning:
            row += f"   ⚠ {c.warning}"
        lines.append(row)
    for line in skipped:
        lines.append(f"      skipped: {line}")
    return "\n".join(lines)


_HELP = (
    "Toggle with numbers (e.g. `2 5`), add a directory with `a /path/to/logs/ [name]`, "
    "`n` to tick nothing, Enter to accept."
)


def choose(
    alias: str,
    candidates: list[Candidate],
    skipped: list[str],
    ask: Callable[[str], str],
    show: Callable[[str], None],
) -> dict[str, dict[str, str]]:
    """Run the checklist dialogue; return the chosen sources by name.

    ``ask`` and ``show`` are injected so the dialogue is testable without a terminal and
    so prompts go to stderr in real use (stdout is the MCP channel when serving).
    """
    while True:
        show(render_checklist(alias, candidates, skipped))
        answer = ask(_HELP + "\n> ").strip()
        if not answer:
            return {c.name: c.spec for c in candidates if c.selected}
        if answer.lower() == "n":
            for c in candidates:
                c.selected = False
            continue
        if answer.startswith("a "):
            parts = answer[2:].split()
            try:
                directory = check_log_dir(parts[0])
            except (Rejected, IndexError) as exc:
                show(f"  cannot add: {getattr(exc, 'reason', 'name a directory')}")
                continue
            name = parts[1] if len(parts) > 1 else _slug(directory.rstrip("/").rsplit("/", 1)[-1])
            try:
                spec = check_log_source(name, {"kind": "file", "dir": directory, "glob": "*"})
            except Rejected as rej:
                show(f"  cannot add: {rej.reason}")
                continue
            if any(c.name == name for c in candidates):
                show(f"  cannot add: {name!r} is already on the list")
                continue
            candidates.append(Candidate(name, spec, "added by hand", True))
            continue
        for token in answer.replace(",", " ").split():
            if token.isdigit() and 1 <= int(token) <= len(candidates):
                c = candidates[int(token) - 1]
                c.selected = not c.selected
            else:
                show(f"  ignored {token!r}")


# --------------------------------------------------------------------------------------
# Arguments, YAML, transport
# --------------------------------------------------------------------------------------


def parse_source_arg(text: str) -> tuple[str, dict[str, str]]:
    """``name=/dir/[:glob]``, ``name=docker:CONTAINER`` or ``name=journal:UNIT``."""
    name, sep, value = text.partition("=")
    if not sep or not value:
        raise Rejected(
            f"--log-source {text!r} must be NAME=/dir/[:glob], NAME=docker:CONTAINER "
            "or NAME=journal:UNIT"
        )
    if value.startswith("docker:"):
        raw = {"kind": "docker", "container": value[len("docker:") :]}
    elif value.startswith("journal:"):
        raw = {"kind": "journal", "unit": value[len("journal:") :]}
    else:
        directory, _, glob = value.partition(":")
        raw = {"kind": "file", "dir": directory, "glob": glob or "*"}
    return name, check_log_source(name, raw)


def yaml_lines(sources: dict[str, dict[str, str]], indent: str = "    ") -> list[str]:
    """``log_sources:`` for hosts.yaml. JSON objects are valid YAML flow mappings."""
    if not sources:
        return []
    lines = [f"{indent}log_sources:"]
    for name, spec in sorted(sources.items()):
        lines.append(f"{indent}  {name}: {json.dumps(spec)}")
    return lines


def run_hostlogs(
    ssh_argv: list[str], mode: str, params: dict[str, Any], *, sudo: bool, timeout: int = 60
) -> tuple[int, dict[str, Any] | None, str]:
    """Run :mod:`hostlogs` on the host; return ``(exit code, parsed JSON or None, stderr)``.

    The program goes on stdin and its parameters as one base64 argument, so nothing the
    host sees is shell-interpreted beyond a fixed command line.
    """
    source = Path(__file__).with_name("hostlogs.py").read_text(encoding="utf-8")
    blob = base64.b64encode(json.dumps(params).encode("utf-8")).decode("ascii")
    remote = f"{'sudo -n ' if sudo else ''}python3 -I - {mode} {blob}"
    try:
        proc = subprocess.run(
            [*ssh_argv, remote],
            input=source,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, None, f"timed out after {timeout}s"
    parsed: dict[str, Any] | None = None
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
            except ValueError:
                parsed = None
            break
    return proc.returncode, parsed, proc.stderr.strip()


def discovery_params(root_if_hardened: bool = False) -> dict[str, Any]:
    return {
        "dirs": sorted({d for e in CATALOGUE for d in e.dirs}),
        "units": sorted({u for e in CATALOGUE for u in e.units}),
        "deny": list(BUILTIN_DENY_PATHS),
        "root_if_hardened": root_if_hardened,
    }
