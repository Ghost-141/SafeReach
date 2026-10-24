"""Log reads that failed in production, and the attacks the fixes must not open.

Every case in the first half is a request an agent actually made against a PM2-hosted
Node service and had refused or answered with nothing: application logs outside /var/log,
regex alternation in a search pattern, `ls /var/log` without the slash, `--sort=-rss`
accepted here and refused by the shim. The second half is what widening any of that
could have cost, asserted as refusals.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from test_shim import run_shim

from safereach.config import HostConfig
from safereach.server import _hint
from safereach.ssh import ExecResult, _take_truncation_tag
from safereach.validator import (
    TRUNCATION_TAG,
    Rejected,
    check_log_dir,
    keeps_tail,
    render,
    spec_summary,
    trim_output,
    validate,
    validate_argv,
)

APP_LOGS = "/opt/app/api/logs/"


@pytest.fixture
def log_ctx(ctx: dict) -> dict:
    return {**ctx, "log_path_prefixes": [APP_LOGS]}


def _accepts(command: str, spec: dict, ctx: dict) -> list[str]:
    argv = validate(command, spec, ctx=ctx).argv
    # Round trip: what the client sends, the shim must accept unchanged.
    assert validate_argv(argv, spec, ctx=ctx).argv == argv
    assert validate(render(argv), spec, ctx=ctx).argv == argv
    return argv


# --------------------------------------------------------------------------------------
# Application log directories
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"tail -n 200 {APP_LOGS}error-2026-09-20.log",
        f"head -n 20 {APP_LOGS}debug-2026-09-21.log",
        f"grep -c error {APP_LOGS}error-2026-09-20.log",
        f"grep -r -n -i timeout {APP_LOGS}",
        f"zgrep -c error {APP_LOGS}error-2026-09-19.log.gz",
        f"ls -l {APP_LOGS}",
        f"ls -l {APP_LOGS.rstrip('/')}",
        f"stat {APP_LOGS}error-2026-09-20.log",
    ],
)
def test_configured_log_directory_is_readable(command: str, spec: dict, log_ctx: dict) -> None:
    _accepts(command, spec, log_ctx)


def test_log_directory_is_refused_until_configured(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected) as exc:
        validate(f"tail -n 20 {APP_LOGS}error.log", spec, ctx=ctx)
    assert "--log-path" in (exc.value.suggestion or "")


def test_var_log_stays_readable_alongside_host_directories(spec: dict, log_ctx: dict) -> None:
    _accepts("tail -n 20 /var/log/nginx/error.log", spec, log_ctx)


@pytest.mark.parametrize(
    "command",
    [
        f"tail -n 5 {APP_LOGS}../.env",
        f"tail -n 5 {APP_LOGS}../../../etc/shadow",
        f"tail -n 5 {APP_LOGS}.env",
        f"grep x {APP_LOGS}config/secrets/db.json",
        f"grep x {APP_LOGS}server.key",
        "tail -n 5 /opt/app/api/logs-evil/x.log",
        "tail -n 5 /opt/app/api/.env",
        "tail -n 5 /etc/shadow",
        "grep -r password /opt/app/",
        f"cat {APP_LOGS}error.log",
        f"zgrep -r x {APP_LOGS}",
        f"zgrep -f /etc/shadow {APP_LOGS}x.gz",
    ],
)
def test_log_directory_does_not_widen_into_its_neighbours(
    command: str, spec: dict, log_ctx: dict
) -> None:
    with pytest.raises(Rejected):
        validate(command, spec, ctx=log_ctx)


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/opt",
        "/opt/",
        "/srv/",
        "/home/",
        "/home/app/",
        "/root",
        "/var/",
        "/var/lib/",
        "/var/lib/docker/containers/",
        "/etc/nginx/",
        "/proc/1/",
        "/opt/app/../../etc/",
        "/opt/app/./logs/",
        "/opt//app/logs/",
        "relative/logs/",
        "/opt/app/.ssh/",
        "/opt/app/secrets/",
        "/home/app/.pm2/",
        "/home/app/.vscode-server/cli/",
        "/opt/app/.cache/logs/",
        "/opt/app logs/",
        "/opt/app/logs/$(id)/",
    ],
)
def test_check_log_dir_refuses_broad_or_sensitive_directories(path: str) -> None:
    with pytest.raises(Rejected):
        check_log_dir(path)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/opt/app/logs", "/opt/app/logs/"),
        ("/opt/app/logs/", "/opt/app/logs/"),
        ("/home/app/.pm2/logs", "/home/app/.pm2/logs/"),
        ("/root/.pm2/logs/", "/root/.pm2/logs/"),
        ("/var/www/site/storage/logs", "/var/www/site/storage/logs/"),
        ("/var/lib/postgresql/16/main/log/", "/var/lib/postgresql/16/main/log/"),
    ],
)
def test_check_log_dir_normalises_leaf_directories(path: str, expected: str) -> None:
    assert check_log_dir(path) == expected


def test_host_config_validates_log_paths() -> None:
    host = HostConfig(alias="a", ssh_config_host="a", log_paths=["/opt/app/logs", "/opt/app/logs/"])
    assert host.log_paths == ["/opt/app/logs/"]
    with pytest.raises(ValueError, match="too broad"):
        HostConfig(alias="a", ssh_config_host="a", log_paths=["/opt/"])


def test_describe_commands_lists_the_host_log_directories(spec: dict, log_ctx: dict) -> None:
    summary = spec_summary(spec, ["tail", "grep"], log_ctx)
    assert summary["tail"]["paths_limited_to"] == ["/var/log/", APP_LOGS]
    assert summary["grep"]["paths_limited_to"] == ["/var/log/", APP_LOGS]


# --------------------------------------------------------------------------------------
# Search patterns are regexes, not shell
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "pattern"),
    [
        (
            'journalctl -u app --grep "processUpload|uploadVectors|embed"',
            "processUpload|uploadVectors|embed",
        ),
        ("grep -E 'timeout|ECONNRESET' /var/log/syslog", "timeout|ECONNRESET"),
        ('grep -E "error$" /var/log/syslog', "error$"),
        (r'grep -E "\d{3}" /var/log/syslog', r"\d{3}"),
        ('grep -E "(GET|POST) /api" /var/log/nginx/access.log', "(GET|POST) /api"),
        (
            "grep -n -E 'HTTP/[0-9.]+\" 50[234] ' /var/log/nginx/access.log",
            'HTTP/[0-9.]+" 50[234] ',
        ),
        (r"grep a\|b /var/log/syslog", "a|b"),
        ('grep "$(id)" /var/log/syslog', "$(id)"),
    ],
)
def test_quoted_regex_reaches_the_tool_as_one_inert_argument(
    command: str, pattern: str, spec: dict, ctx: dict
) -> None:
    argv = _accepts(command, spec, ctx)
    assert pattern in argv


@pytest.mark.parametrize(
    "command",
    [
        'grep "a" /var/log/syslog | sh',
        "grep a /var/log/syslog; id",
        "grep $(id) /var/log/syslog",
        "grep `id` /var/log/syslog",
        "grep 'a' /var/log/syslog && id",
        'grep "a"|sh /var/log/syslog',
        "grep 'a'>/tmp/x /var/log/syslog",
        "grep a /var/log/syslog &",
    ],
)
def test_unquoted_operators_are_still_refused(command: str, spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected, match="metacharacter"):
        validate(command, spec, ctx=ctx)


# --------------------------------------------------------------------------------------
# Validator fixes
# --------------------------------------------------------------------------------------


def test_ls_accepts_a_permitted_directory_without_its_slash(spec: dict, ctx: dict) -> None:
    assert _accepts("ls -l /var/log", spec, ctx) == ["ls", "-l", "/var/log"]


def test_ls_slashless_match_is_exact_not_a_prefix(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected):
        validate("ls -l /var/lo", spec, ctx=ctx)


def test_dash_led_inline_value_survives_the_round_trip(spec: dict, ctx: dict) -> None:
    argv = _accepts("ps -e -o rss,comm --sort=-rss", spec, ctx)
    assert argv == ["ps", "-e", "-o", "rss,comm", "--sort=-rss"]


def test_separated_dash_led_value_is_still_a_dropped_value(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected, match="expects a value"):
        validate("ps -e --sort -rss", spec, ctx=ctx)


# --------------------------------------------------------------------------------------
# Output shaping
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "tail"),
    [
        (["journalctl", "-u", "x"], True),
        (["journalctl", "-u", "x", "-r"], False),
        (["docker", "logs", "api"], True),
        (["docker", "container", "logs", "api"], True),
        (["docker", "compose", "logs"], True),
        (["kubectl", "logs", "pod"], True),
        (["tail", "-n", "5", "/var/log/x"], True),
        (["grep", "x", "/var/log/x"], True),
        (["dmesg", "-T"], True),
        (["docker", "ps"], False),
        (["ps", "-e"], False),
        (["df", "-h"], False),
    ],
)
def test_keeps_tail(argv: list[str], tail: bool) -> None:
    assert keeps_tail(argv) is tail


def test_trim_output_keeps_the_newest_whole_lines() -> None:
    text = "".join(f"line {i}\n" for i in range(100))
    kept, omitted = trim_output(text, 50, keep_tail=True)
    assert kept.endswith("line 99\n")
    assert kept.startswith("line ")
    assert omitted == len(text) - len(kept)
    assert len(kept) <= 50


def test_trim_output_head_mode_cuts_at_a_line_end() -> None:
    text = "".join(f"line {i}\n" for i in range(100))
    kept, _ = trim_output(text, 50, keep_tail=False)
    assert kept.startswith("line 0\n")
    assert kept.endswith("\n")


def test_trim_output_leaves_short_text_alone() -> None:
    assert trim_output("abc\n", 50, keep_tail=True) == ("abc\n", 0)


def test_client_reads_and_strips_the_shim_truncation_tag() -> None:
    stderr = f"warning: x\n\n{TRUNCATION_TAG} " + json.dumps(
        {"omitted_bytes": 1234, "kept": "tail"}
    )
    rest, omitted = _take_truncation_tag(stderr)
    assert omitted == 1234
    assert TRUNCATION_TAG not in rest
    assert "warning: x" in rest
    assert _take_truncation_tag("plain") == ("plain", None)


# --------------------------------------------------------------------------------------
# Hints for dead ends
# --------------------------------------------------------------------------------------


def _result(stdout: str = "", stderr: str = "", code: int = 0) -> ExecResult:
    return ExecResult(exit_code=code, stdout=stdout, stderr=stderr, truncated=False, duration_ms=1)


def test_empty_journal_points_at_the_application_log_directories() -> None:
    host = HostConfig(alias="a", ssh_config_host="a", log_paths=[APP_LOGS])
    hint = _hint(host, ["journalctl", "-u", "pm2-app", "--no-pager"], _result("-- No entries --\n"))
    assert hint and APP_LOGS in hint


def test_empty_journal_without_log_paths_says_how_to_add_them() -> None:
    host = HostConfig(alias="a", ssh_config_host="a")
    hint = _hint(host, ["journalctl", "-u", "pm2-app"], _result("-- No entries --"))
    assert hint and "--log-path" in hint


def test_restricted_dmesg_points_at_the_kernel_journal() -> None:
    host = HostConfig(alias="a", ssh_config_host="a")
    hint = _hint(
        host,
        ["dmesg", "-T"],
        _result(stderr="dmesg: read kernel buffer failed: Operation not permitted", code=1),
    )
    assert hint and "journalctl -k" in hint


def test_no_hint_for_ordinary_output() -> None:
    host = HostConfig(alias="a", ssh_config_host="a")
    assert _hint(host, ["journalctl", "-u", "x"], _result("Oct 22 boot\n")) is None


# --------------------------------------------------------------------------------------
# The shim: host policy, symlinks, streaming truncation
# --------------------------------------------------------------------------------------


@pytest.fixture
def app_logs(tmp_path: Path) -> Path:
    logs = tmp_path / "app" / "logs"
    logs.mkdir(parents=True)
    (logs / "app.log").write_text("".join(f"request {i} ok\n" for i in range(1, 501)))
    (tmp_path / "app" / "settings.txt").write_text("API_TOKEN=hunter2\n")
    return logs


def _conf(tmp_path: Path, **policy: object) -> Path:
    conf = tmp_path / "config.json"
    conf.write_text(json.dumps(policy), encoding="utf-8")
    return conf


def _run(shim: Path, conf: Path, argv: list[str]) -> tuple[int, str, str]:
    return run_shim(shim, conf, "@run " + json.dumps(argv))


def test_shim_reads_a_configured_log_directory(
    shim_path: Path, tmp_path: Path, app_logs: Path
) -> None:
    conf = _conf(tmp_path, log_path_prefixes=[str(app_logs)])
    code, out, _ = _run(shim_path, conf, ["tail", "-n", "2", str(app_logs / "app.log")])
    assert code == 0
    assert out.splitlines() == ["request 499 ok", "request 500 ok"]


def test_shim_refuses_the_directory_without_policy(
    shim_path: Path, tmp_path: Path, app_logs: Path
) -> None:
    code, _, err = _run(shim_path, _conf(tmp_path), ["tail", "-n", "2", str(app_logs / "app.log")])
    assert code == 92
    assert "outside the permitted locations" in err


def test_shim_ignores_an_unsafe_policy_entry(shim_path: Path, tmp_path: Path) -> None:
    conf = _conf(tmp_path, log_path_prefixes=["/", "/opt/", "/etc/"])
    code, _, err = _run(shim_path, conf, ["tail", "-n", "2", "/etc/hostname"])
    assert code == 92
    audit = (tmp_path / "audit.jsonl").read_text()
    assert audit.count('"policy-ignored"') == 3


def test_shim_refuses_a_symlink_out_of_the_log_directory(
    shim_path: Path, tmp_path: Path, app_logs: Path
) -> None:
    os.symlink(app_logs.parent / "settings.txt", app_logs / "innocent.log")
    conf = _conf(tmp_path, log_path_prefixes=[str(app_logs)])
    code, out, err = _run(shim_path, conf, ["tail", "-n", "5", str(app_logs / "innocent.log")])
    assert code == 92
    assert "resolves outside" in err
    assert "hunter2" not in out


def test_shim_keeps_the_newest_lines_of_an_oversized_log(
    shim_path: Path, tmp_path: Path, app_logs: Path
) -> None:
    conf = _conf(tmp_path, log_path_prefixes=[str(app_logs)], max_log_output_bytes=200)
    code, out, err = _run(shim_path, conf, ["tail", "-n", "500", str(app_logs / "app.log")])
    assert code == 0
    lines = out.splitlines()
    assert lines[-1] == "request 500 ok"
    assert all(line.startswith("request ") and line.endswith(" ok") for line in lines)
    tag = [line for line in err.splitlines() if line.startswith(TRUNCATION_TAG)]
    assert tag and json.loads(tag[0][len(TRUNCATION_TAG) :])["kept"] == "tail"


def test_shim_keeps_the_head_of_non_log_output(
    shim_path: Path, tmp_path: Path, app_logs: Path
) -> None:
    conf = _conf(tmp_path, log_path_prefixes=[str(app_logs)], max_output_bytes=200)
    code, out, err = _run(shim_path, conf, ["head", "-n", "500", str(app_logs / "app.log")])
    assert code == 0
    assert out.splitlines()[0] == "request 1 ok"
    tag = [line for line in err.splitlines() if line.startswith(TRUNCATION_TAG)]
    assert tag and json.loads(tag[0][len(TRUNCATION_TAG) :])["kept"] == "head"


def test_shim_runs_a_quoted_regex_without_a_shell(
    shim_path: Path, tmp_path: Path, app_logs: Path
) -> None:
    conf = _conf(tmp_path, log_path_prefixes=[str(app_logs)])
    code, out, _ = _run(
        shim_path, conf, ["grep", "-E", "-c", "request (7|77) ok$", str(app_logs / "app.log")]
    )
    assert code == 0
    assert out == "2"
