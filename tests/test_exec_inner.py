"""Container exec: the inner allowlist is as constrained as the host one.

`--allow-exec` was reviewed as accepting `cat /proc/1/environ` and any config file in
the container. Content-reading commands now take their permitted prefixes from the host
policy and refuse everything when none are set; the process and kernel views are on the
compiled-in deny list.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "shim"))

from shim_main import EXEC_INNER_SPEC  # noqa: E402

from safereach.validator import BUILTIN_DENY_PATHS, Rejected, validate_argv  # noqa: E402

READERS = ["cat", "tail", "head", "grep"]


def _ctx(prefixes: list[str] | None) -> dict:
    return {"deny_paths": list(BUILTIN_DENY_PATHS), "exec_path_prefixes": prefixes or []}


@pytest.mark.parametrize("binary", READERS)
def test_content_readers_refuse_everything_without_prefixes(binary: str) -> None:
    argv = (
        [binary, "x", "/app/storage/logs/app.log"]
        if binary == "grep"
        else [binary, "/app/storage/logs/app.log"]
    )
    with pytest.raises(Rejected, match="no permitted paths"):
        validate_argv(argv, EXEC_INNER_SPEC, ctx=_ctx(None))


@pytest.mark.parametrize("binary", READERS)
def test_content_readers_accept_inside_a_prefix(binary: str) -> None:
    argv = (
        [binary, "x", "/app/storage/logs/app.log"]
        if binary == "grep"
        else [binary, "/app/storage/logs/app.log"]
    )
    result = validate_argv(argv, EXEC_INNER_SPEC, ctx=_ctx(["/app/storage/logs/"]))
    assert result.argv[-1] == "/app/storage/logs/app.log"


@pytest.mark.parametrize(
    "path",
    [
        "/proc/1/environ",
        "/proc/self/environ",
        "/proc/1/cmdline",
        "/sys/kernel/debug/x",
        "/app/.env",
        "/app/.env.production",
        "/app/config/database.yml",
        "/app/config/secrets.yaml",
        "/run/secrets/db_password",
        "/root/.bash_history",
        "/app/storage/logs/../../.env",
        "/etc/app/app.conf",
        "/var/www/html/wp-config.php",
    ],
)
def test_content_readers_refuse_outside_or_denied(path: str) -> None:
    with pytest.raises(Rejected):
        validate_argv(["cat", path], EXEC_INNER_SPEC, ctx=_ctx(["/app/storage/logs/", "/var/log/"]))


def test_metadata_commands_do_not_need_prefixes() -> None:
    """`ls`, `stat`, `df`, `ps` return names and numbers, never contents."""
    ctx = _ctx(None)
    validate_argv(["ls", "-l", "/app"], EXEC_INNER_SPEC, ctx=ctx)
    validate_argv(["stat", "/app/storage"], EXEC_INNER_SPEC, ctx=ctx)
    validate_argv(["df", "-h"], EXEC_INNER_SPEC, ctx=ctx)
    validate_argv(["ps", "-e"], EXEC_INNER_SPEC, ctx=ctx)


def test_metadata_commands_still_respect_the_deny_list() -> None:
    for argv in (["ls", "/proc/1/"], ["stat", "/proc/1/environ"], ["ls", "/run/secrets/"]):
        with pytest.raises(Rejected, match="protected-path"):
            validate_argv(argv, EXEC_INNER_SPEC, ctx=_ctx(None))


def test_no_shell_inside_the_container() -> None:
    for argv in (["sh", "-c", "id"], ["bash"], ["env"], ["printenv"], ["python3", "-c", "1"]):
        with pytest.raises(Rejected, match="not an allowlisted"):
            validate_argv(argv, EXEC_INNER_SPEC, ctx=_ctx(["/app/"]))
