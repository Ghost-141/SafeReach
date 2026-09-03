"""stdout must carry JSON-RPC and nothing else.

This is the most common way a working MCP server appears broken: one stray print — a
banner, a warning, a progress line — corrupts the protocol stream and the agent reports
an opaque parse failure with no indication of the cause. Both the happy path and the
bad-config path are checked, because the error path is where a diagnostic print is most
tempting to add.
"""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

INIT_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "stdio-clean-test", "version": "1.0"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
TOOLS_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


def _hosts_yaml(tmp_path: Path) -> Path:
    path = tmp_path / "hosts.yaml"
    path.write_text(
        "defaults:\n"
        "  known_hosts: ~/.ssh/known_hosts\n"
        f"  audit_log: {tmp_path / 'audit.jsonl'}\n"
        "hosts:\n"
        "  demo:\n"
        "    hostname: 127.0.0.1\n"
        "    user: diag\n"
        "    key: ~/.ssh/id_ed25519_demo\n"
        "    description: test\n"
        "    allow: [df]\n",
        encoding="utf-8",
    )
    return path


class Session:
    """A live stdio session against the server.

    Deliberately does *not* close stdin after writing. Piping every message in and
    closing immediately races the server's shutdown-on-EOF against its reply, which
    showed up as an intermittently empty tools/list. Reads are drained by a thread
    against a deadline, and the process is terminated explicitly at the end.
    """

    def __init__(self, config: Path) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "safereach", "--config", str(config)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=REPO,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(Path.home()),
                "PYTHONPATH": str(REPO / "src"),
                "PYTHONUNBUFFERED": "1",
            },
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self._stderr: str | None = None
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put("")  # sentinel: stream closed

    def send(self, message: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def collect(self, until_id: int | None = None, timeout: float = 15.0) -> list[str]:
        """Read raw lines until the given response id arrives, the stream ends, or timeout."""
        out: list[str] = []
        deadline = timeout
        while deadline > 0:
            try:
                line = self.lines.get(timeout=0.5)
            except queue.Empty:
                deadline -= 0.5
                continue
            if line == "":
                break
            out.append(line)
            if until_id is not None:
                try:
                    if json.loads(line).get("id") == until_id:
                        break
                except json.JSONDecodeError:
                    break  # let the caller assert on the malformed line
        return out

    def close(self) -> str:
        """Shut down and drain every pipe.

        Idempotent, because the bad-config test calls this explicitly and then again via
        __exit__. Pipes are closed rather than left to the GC: the suite runs with
        `filterwarnings = ["error"]`, so a leaked ResourceWarning fails the test.
        """
        if self._stderr is not None:
            return self._stderr

        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

        # The reader loop ends at EOF, which the process exit above guarantees.
        self._reader.join(timeout=2)

        self._stderr = self.proc.stderr.read() if self.proc.stderr else ""
        for pipe in (self.proc.stdout, self.proc.stderr):
            if pipe and not pipe.closed:
                pipe.close()
        return self._stderr

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def assert_pure_jsonrpc(lines: list[str]) -> list[dict]:
    messages = []
    for line in lines:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            pytest.fail(f"non-JSON line on stdout: {line!r}")
        assert message.get("jsonrpc") == "2.0", f"not a JSON-RPC message: {line!r}"
        messages.append(message)
    return messages


def test_stdout_is_pure_jsonrpc(tmp_path: Path) -> None:
    with Session(_hosts_yaml(tmp_path)) as session:
        session.send(INIT_REQUEST)
        lines = session.collect(until_id=1)
    messages = assert_pure_jsonrpc(lines)
    assert messages, "server produced no response"


def test_initialize_advertises_all_tools(tmp_path: Path) -> None:
    with Session(_hosts_yaml(tmp_path)) as session:
        session.send(INIT_REQUEST)
        session.collect(until_id=1)
        session.send(INITIALIZED)
        session.send(TOOLS_LIST)
        lines = session.collect(until_id=2)

    tools: list[str] = []
    for message in assert_pure_jsonrpc(lines):
        if message.get("id") == 2:
            tools = [t["name"] for t in message["result"]["tools"]]

    assert set(tools) == {
        "list_hosts",
        "select_host",
        "describe_commands",
        "run_command",
        "run_on_hosts",
        "run_elevated",
        "run_in_container",
        "check_connectivity",
    }, f"unexpected tool set: {tools}"


def test_host_is_optional_on_run_command(tmp_path: Path) -> None:
    """`host` must be optional, or the agent cannot be asked which server to use."""
    with Session(_hosts_yaml(tmp_path)) as session:
        session.send(INIT_REQUEST)
        session.collect(until_id=1)
        session.send(INITIALIZED)
        session.send(TOOLS_LIST)
        lines = session.collect(until_id=2)

    schema = None
    for message in assert_pure_jsonrpc(lines):
        if message.get("id") == 2:
            for tool in message["result"]["tools"]:
                if tool["name"] == "run_command":
                    schema = tool["inputSchema"]

    assert schema is not None
    assert "command" in schema["required"]
    assert "host" not in schema.get("required", []), "host must be optional"


def test_describe_commands_reaches_the_agent(tmp_path: Path) -> None:
    """The allowlist has to be discoverable, or the agent guesses and burns turns."""
    with Session(_hosts_yaml(tmp_path)) as session:
        session.send(INIT_REQUEST)
        session.collect(until_id=1)
        session.send(INITIALIZED)
        session.send(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "describe_commands", "arguments": {}},
            }
        )
        lines = session.collect(until_id=3)

    payload = None
    for message in assert_pure_jsonrpc(lines):
        if message.get("id") == 3:
            payload = message["result"]

    assert payload is not None, "no response to describe_commands"
    body = json.dumps(payload)

    # With exactly one host configured, the description is scoped to that host's allow
    # list rather than the whole spec. Listing commands the agent cannot actually run
    # there would just buy it a rejection later.
    assert "df" in body, "the host's permitted command should be described"
    assert "docker" not in body, "commands the host does not allow must not be offered"
    assert "No pipes" in body or "no pipes" in body.lower()


def test_bad_config_keeps_stdout_clean(tmp_path: Path) -> None:
    """The error path is where a stray print is most likely to creep in."""
    bad = tmp_path / "hosts.yaml"
    bad.write_text("hosts:\n  demo:\n    this_key_does_not_exist: 1\n", encoding="utf-8")

    with Session(bad) as session:
        session.send(INIT_REQUEST)
        lines = session.collect(until_id=1, timeout=8)
        stderr = session.close()

    assert_pure_jsonrpc(lines)  # a traceback on stdout would fail here
    assert stderr.strip(), "the failure should be reported on stderr"


def test_missing_config_keeps_stdout_clean(tmp_path: Path) -> None:
    with Session(tmp_path / "nope.yaml") as session:
        session.send(INIT_REQUEST)
        lines = session.collect(until_id=1, timeout=8)
    assert_pure_jsonrpc(lines)


def test_help_does_not_start_the_server() -> None:
    """`--help` must print usage, not fall through to stdio mode.

    It used to: the dispatch asked "is a subcommand absent" rather than "are these only
    server arguments", so `--help` started the server and died looking for hosts.yaml.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "safereach", "--help"],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "PYTHONPATH": str(REPO / "src")},
        check=False,
    )
    combined = proc.stdout + proc.stderr
    assert "SafeReach" in combined
    assert "Quick start" in combined
    assert "discover" in combined
    assert "Traceback" not in combined


def test_bare_invocation_on_a_tty_shows_help_not_a_silent_server() -> None:
    """A human typing `safereach` should not watch a server wait on stdin forever.

    Agents launch it over a pipe, never a TTY, so the two cases are distinguishable —
    and `test_stdout_is_pure_jsonrpc` above proves the pipe case still starts a server.
    """
    proc = subprocess.run(
        ["script", "-qec", f"{sys.executable} -m safereach", "/dev/null"],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "PYTHONPATH": str(REPO / "src")},
        timeout=30,
        check=False,
    )
    combined = proc.stdout + proc.stderr
    assert "SafeReach" in combined
    assert "Quick start" in combined, "the grouped listing should be what a human sees"
    assert "enroll" in combined and "doctor" in combined


def test_help_groups_commands_by_task() -> None:
    """The generated list says which commands exist; the grouping says which to run."""
    from safereach.cli import COMMAND_GROUPS

    titles = [title for title, _ in COMMAND_GROUPS]
    assert titles == ["Setting up servers", "Connecting agents", "Checking and debugging"]

    listed = {cmd for _, rows in COMMAND_GROUPS for cmd, _ in rows}
    assert {"enroll", "install", "doctor", "rename", "validate"} <= listed
    for _, rows in COMMAND_GROUPS:
        for cmd, description in rows:
            assert description and not description.endswith("."), (
                f"{cmd}: descriptions read as labels, not sentences"
            )


def test_every_subcommand_explains_itself() -> None:
    """`help=` only ever fed the parent listing, so per-command help had no description."""
    from safereach.cli import build_parser

    sub = next(
        a for a in build_parser()._actions if isinstance(a, argparse.__dict__["_SubParsersAction"])
    )
    for name, parser in sub.choices.items():
        assert parser.description, f"`safereach {name} --help` has no description"


# --------------------------------------------------------------------------------------
# Rich output must never reach stdout
# --------------------------------------------------------------------------------------


def test_rich_console_is_bound_to_stderr() -> None:
    """The single rule that makes coloured output safe in an MCP server.

    stdout carries JSON-RPC. rich writes to stdout by default, so one styled line there
    corrupts the stream and every agent reports an opaque parse failure with no clue
    where it came from. Binding the console once is the guarantee; this asserts it.
    """
    from safereach.console import console

    assert console.stderr is True, "the shared console must never write to stdout"


@pytest.mark.parametrize("command", [["--help"], ["install", "--list"], ["validate", "df -h"]])
def test_cli_commands_write_nothing_to_stdout(command: list[str]) -> None:
    """Every human-facing command keeps stdout empty, tables included."""
    proc = subprocess.run(
        [sys.executable, "-m", "safereach", *command],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "PYTHONPATH": str(REPO / "src")},
        timeout=60,
        check=False,
    )
    assert proc.stdout == "", (
        f"`safereach {' '.join(command)}` wrote to stdout, which is the protocol "
        f"channel:\n{proc.stdout[:400]}"
    )
    assert proc.stderr.strip(), "output should still be produced, on stderr"


def test_colour_is_dropped_when_piped() -> None:
    """Piped output must stay greppable — `safereach doctor | tee log` is normal usage."""
    proc = subprocess.run(
        [sys.executable, "-m", "safereach", "install", "--list"],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "PYTHONPATH": str(REPO / "src")},
        timeout=60,
        check=False,
    )
    assert "\x1b[" not in proc.stderr, "ANSI escapes leaked into non-TTY output"
    assert "Claude Code" in proc.stderr, "the content itself must survive"


def test_no_color_env_is_honoured() -> None:
    """Users who set NO_COLOR expect it obeyed everywhere, not just where convenient."""
    proc = subprocess.run(
        [sys.executable, "-m", "safereach", "--help"],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(Path.home()),
            "PYTHONPATH": str(REPO / "src"),
            "NO_COLOR": "1",
        },
        timeout=60,
        check=False,
    )
    assert "\x1b[" not in proc.stderr


def test_shim_bundle_never_imports_rich() -> None:
    """rich is a CLI dependency; the shim must stay stdlib-only to remain scp-able."""
    for module in ("validator.py", "redact.py"):
        source = (REPO / "src" / "safereach" / module).read_text(encoding="utf-8")
        assert "rich" not in source, f"{module} must not depend on rich"
