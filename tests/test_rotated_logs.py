"""Searching rotated logs — the incident an agent could not find (0.5.2).

The app rotated daily and compressed every earlier day to `.gz`, so anything older than
today existed only in compressed files. On a host enrolled before 0.5.0 the allow list
had `grep` but no `zgrep`, and `read_logs` dropped every `.gz` silently; it also read at
most the three newest files whatever `since` said. A request ID from earlier in the week
returned "no lines matched". The agent then tried `grep -l` (refused: not allowlisted)
and the old host spelling `Synapse-Sandbox` (refused: unknown host).
"""

from __future__ import annotations

import gzip
import json
import os
import time
from pathlib import Path

import pytest
from test_shim import run_shim

from safereach.config import HostConfig, Settings
from safereach.validator import Rejected, effective_allow, spec_summary, validate, validate_argv

REQUEST_ID = "3d7ad9d0-3087-4671-9e83-319474ac94bb"
LOGS = "/opt/app/api/logs/"


# --------------------------------------------------------------------------------------
# zgrep is implied by grep
# --------------------------------------------------------------------------------------


def test_zgrep_is_permitted_wherever_grep_is(spec: dict, ctx: dict) -> None:
    argv = ["zgrep", "-c", REQUEST_ID, "/var/log/syslog.2.gz"]
    validate_argv(argv, spec, allow=["grep", "tail"], ctx=ctx)


def test_zgrep_is_still_refused_without_grep(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected, match="not permitted on this host"):
        validate_argv(["zgrep", "x", "/var/log/syslog.2.gz"], spec, allow=["tail"], ctx=ctx)


def test_effective_allow_adds_only_what_is_implied() -> None:
    assert effective_allow(["grep", "df"]) == {"grep", "zgrep", "df"}
    assert effective_allow(["df"]) == {"df"}


def test_describe_commands_shows_implied_zgrep(spec: dict) -> None:
    assert "zgrep" in spec_summary(spec, ["grep"])


# --------------------------------------------------------------------------------------
# grep -l, and one search over a two-week window
# --------------------------------------------------------------------------------------


def test_grep_can_list_matching_files(spec: dict, ctx: dict) -> None:
    log_ctx = {**ctx, "log_path_prefixes": [LOGS]}
    for binary in ("grep", "zgrep"):
        argv = validate(
            f"{binary} -l {REQUEST_ID} {LOGS}debug-2026-11-08.log.gz", spec, ctx=log_ctx
        ).argv
        assert "-l" in argv


def test_grep_takes_a_two_week_window_of_files_but_no_more(spec: dict, ctx: dict) -> None:
    log_ctx = {**ctx, "log_path_prefixes": [LOGS]}
    files = [f"{LOGS}debug-2026-10-{d:02d}.log.gz" for d in range(1, 33)]
    validate_argv(["zgrep", "-h", REQUEST_ID, *files], spec, ctx=log_ctx)
    with pytest.raises(Rejected, match="at most"):
        validate_argv(["zgrep", "-h", REQUEST_ID, *files, f"{LOGS}x.log"], spec, ctx=log_ctx)


def test_more_files_never_widens_the_path_rules(spec: dict, ctx: dict) -> None:
    log_ctx = {**ctx, "log_path_prefixes": [LOGS]}
    files = [f"{LOGS}d{i}.log.gz" for i in range(20)] + ["/etc/shadow"]
    with pytest.raises(Rejected):
        validate_argv(["zgrep", "x", *files], spec, ctx=log_ctx)


# --------------------------------------------------------------------------------------
# Host names
# --------------------------------------------------------------------------------------


def _settings(*aliases: str) -> Settings:
    return Settings(hosts={a: HostConfig(alias=a, ssh_config_host=a.lower()) for a in aliases})


def test_old_capitalised_alias_still_finds_the_host() -> None:
    settings = _settings("synapse-sandbox", "synapse-main")
    assert settings.host("Synapse-Sandbox").alias == "synapse-sandbox"


def test_case_match_must_be_unique() -> None:
    settings = _settings("web", "WEB")
    with pytest.raises(KeyError, match="unknown host"):
        settings.host("Web")


def test_unknown_host_is_still_unknown() -> None:
    with pytest.raises(KeyError, match="configured hosts: synapse-main"):
        _settings("synapse-main").host("Synapse-App")


# --------------------------------------------------------------------------------------
# The shim: read_logs over a rotated directory, on a pre-0.5 allow list
# --------------------------------------------------------------------------------------


@pytest.fixture
def rotated(tmp_path: Path) -> Path:
    """Today's plain debug/error pair plus 14 earlier days compressed, two files a day."""
    logs = tmp_path / "app" / "logs"
    logs.mkdir(parents=True)
    now = time.time()
    for days_ago in range(14, 0, -1):
        for kind in ("debug", "error"):
            path = logs / f"{kind}-day{days_ago:02d}.log.gz"
            body = f"{kind} day {days_ago} routine\n"
            if days_ago == 6 and kind == "debug":
                body += f"rate limit exceeded requestId={REQUEST_ID}\n"
            with gzip.open(path, "wt") as fh:
                fh.write(body)
            stamp = now - days_ago * 86400 + 3600
            os.utime(path, (stamp, stamp))
    (logs / "debug-today.log").write_text("debug today routine\n")
    (logs / "error-today.log").write_text("error today routine\n")
    return logs


def _policy(tmp_path: Path, logs: Path, allow: list[str]) -> Path:
    conf = tmp_path / "config.json"
    conf.write_text(
        json.dumps(
            {
                "allow": allow,
                "log_sources": {"api": {"kind": "file", "dir": str(logs), "glob": "*.log*"}},
            }
        )
    )
    return conf


def _read(shim: Path, conf: Path, **request: object) -> tuple[int, str, str]:
    return run_shim(shim, conf, "@logs " + json.dumps(request))


#: The allow list `enroll` wrote before 0.5.0: grep, no zgrep.
PRE_05_ALLOW = ["journalctl", "systemctl", "tail", "head", "grep", "stat", "ls", "docker"]


def test_request_id_in_an_older_compressed_day_is_found(
    shim_path: Path, tmp_path: Path, rotated: Path
) -> None:
    code, out, err = _read(
        shim_path,
        _policy(tmp_path, rotated, PRE_05_ALLOW),
        source="api",
        grep=REQUEST_ID,
        since="14d",
    )
    assert code == 0, err
    assert out == f"rate limit exceeded requestId={REQUEST_ID}"
    assert "30 file(s)" in err


def test_search_without_since_covers_the_newest_32_files(
    shim_path: Path, tmp_path: Path, rotated: Path
) -> None:
    code, out, err = _read(
        shim_path, _policy(tmp_path, rotated, PRE_05_ALLOW), source="api", grep=REQUEST_ID
    )
    assert code == 0, err
    assert REQUEST_ID in out


def test_files_beyond_the_cap_are_reported_not_silently_dropped(
    shim_path: Path, tmp_path: Path, rotated: Path
) -> None:
    for i in range(5):
        (rotated / f"extra-{i}.log").write_text("extra\n")
    _, _, err = _read(
        shim_path,
        _policy(tmp_path, rotated, PRE_05_ALLOW),
        source="api",
        grep="routine",
        since="30d",
    )
    assert "32 file(s)" in err
    assert "older file(s) not searched" in err


def test_tailing_without_a_pattern_still_reads_only_the_newest(
    shim_path: Path, tmp_path: Path, rotated: Path
) -> None:
    code, out, err = _read(
        shim_path, _policy(tmp_path, rotated, PRE_05_ALLOW), source="api", lines=5
    )
    assert code == 0, err
    assert "today routine" in out
    assert "day 14" not in out


def test_empty_files_do_not_use_up_the_cap(shim_path: Path, tmp_path: Path, rotated: Path) -> None:
    for i in range(40):
        (rotated / f"meiliSync-{i:02d}.log").write_text("")
    code, out, err = _read(
        shim_path,
        _policy(tmp_path, rotated, PRE_05_ALLOW),
        source="api",
        grep=REQUEST_ID,
        since="14d",
    )
    assert code == 0, err
    assert REQUEST_ID in out
    assert "30 file(s)" in err and "not searched" not in err
