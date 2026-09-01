"""Differential test: the bundled shim must agree with the in-process validator.

This is the test that makes the two-sided design trustworthy. The shim is a *generated*
artifact — `build.py` inlines the validator source and embeds the spec — so what is
really under test is that the bundling step did not alter behaviour. A divergence means a
host would accept something this server refuses, or vice versa, which is exactly the
drift the version stamp exists to prevent but cannot detect within a single build.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import ACCEPTS, ATTACKS, CURL_TARGETS

from safereach.validator import Rejected, render, validate
from safereach.versioning import fingerprint

ALL_INPUTS = [c for _, c in ATTACKS] + [c for c, _ in ACCEPTS]

#: Loads the built shim as a real module, overrides its config path, and runs one verb.
#: Importing rather than re-exec'ing the source package keeps this honest: it exercises
#: the actual bundled artifact, including the embedded spec.
#:
#: The explicit SourceFileLoader is required — the shim has no .py suffix, so
#: spec_from_file_location cannot infer a loader and returns None.
_HARNESS = """
import importlib.util, os, pathlib, sys
from importlib.machinery import SourceFileLoader

shim_file, conf_path, verb = sys.argv[1], sys.argv[2], sys.argv[3]
loader = SourceFileLoader("safereach_shim_under_test", shim_file)
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
# Must be registered before exec: @dataclass resolves postponed annotations by looking
# its own module up in sys.modules, and fails with an opaque AttributeError otherwise.
sys.modules[loader.name] = mod
loader.exec_module(mod)

mod.CONFIG_PATHS = (pathlib.Path(conf_path),)
mod.LOG_PATHS = (pathlib.Path(conf_path).parent / "audit.jsonl",)
os.environ["SSH_ORIGINAL_COMMAND"] = verb
sys.exit(mod.main([]))
"""


@pytest.fixture(scope="module")
def shim_conf(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Host policy matching the fixtures the in-process validator is given."""
    conf = tmp_path_factory.mktemp("shimconf") / "config.json"
    conf.write_text(json.dumps({"curl_targets": CURL_TARGETS}), encoding="utf-8")
    return conf


def run_shim(shim: Path, conf: Path, verb: str, stdin: str = "") -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, "-c", _HARNESS, str(shim), str(conf), verb],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


@pytest.mark.parametrize("command", ALL_INPUTS, ids=[c[:48] or "empty" for c in ALL_INPUTS])
def test_shim_agrees_with_in_process_validator(
    command: str, shim_path: Path, shim_conf: Path, spec: dict, ctx: dict
) -> None:
    try:
        expected = render(validate(command, spec, ctx=ctx).argv)
        accepted_here = True
    except Rejected:
        expected = ""
        accepted_here = False

    code, out, err = run_shim(shim_path, shim_conf, "@check", stdin=command)
    accepted_there = code == 0

    assert accepted_there == accepted_here, (
        f"validators disagree on {command!r}: "
        f"in-process={'accept' if accepted_here else 'reject'}, "
        f"shim={'accept' if accepted_there else 'reject'} ({out or err})"
    )
    if accepted_here:
        assert out == expected, f"different argv for {command!r}"


def test_shim_version_matches_server_fingerprint(shim_path: Path, spec: dict) -> None:
    """The stamp is what lets the server detect a drifted host."""
    proc = subprocess.run(
        [sys.executable, str(shim_path), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout.strip() == fingerprint(spec)


def test_shim_is_stdlib_only(shim_path: Path) -> None:
    """It has to run on hosts where installing packages is not acceptable.

    Parsed with `ast` rather than searched as text: a substring check matches the
    validator's own docstring, which explains this very rule.
    """
    tree = ast.parse(shim_path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])

    third_party = imported - set(sys.stdlib_module_names)
    assert not third_party, f"shim bundle imports non-stdlib modules: {sorted(third_party)}"
    assert "safereach" not in imported, "the package import was not stripped by build.py"


def test_shim_refuses_bare_invocation(shim_path: Path) -> None:
    """No command means no shell — the forced command's whole point."""
    proc = subprocess.run(
        [sys.executable, str(shim_path)],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
        check=False,
    )
    assert proc.returncode != 0
    assert "no interactive shell" in proc.stderr


def test_shim_fails_closed_on_unreadable_config(shim_path: Path, tmp_path: Path) -> None:
    """A corrupt policy file must not degrade into 'allow everything'."""
    bad = tmp_path / "config.json"
    bad.write_text("{ this is not json", encoding="utf-8")
    code, _out, err = run_shim(shim_path, bad, "df -h")
    assert code != 0
    assert "cannot read" in err


def test_shim_honours_host_allow_list(shim_path: Path, tmp_path: Path) -> None:
    """The host's own policy narrows the embedded spec, independently of the server."""
    conf = tmp_path / "config.json"
    conf.write_text(json.dumps({"allow": ["df"], "curl_targets": []}), encoding="utf-8")

    code, _out, _err = run_shim(shim_path, conf, "@check", stdin="df -h")
    assert code == 0

    code, _out, err = run_shim(shim_path, conf, "@check", stdin="journalctl -n 5")
    assert code != 0
    assert "not permitted on this host" in err


def test_shim_executes_a_real_command(shim_path: Path, shim_conf: Path) -> None:
    """End to end: an allowlisted command actually runs and returns output."""
    code, out, _err = run_shim(shim_path, shim_conf, "df -h")
    assert code == 0
    assert "Filesystem" in out


def test_shim_rejects_unknown_control_verb(shim_path: Path, shim_conf: Path) -> None:
    code, _out, err = run_shim(shim_path, shim_conf, "@wat")
    assert code != 0
    assert "unknown control command" in err


def test_elevated_requires_a_configured_recipe(shim_path: Path, shim_conf: Path) -> None:
    """With no recipes configured, every recipe name is refused."""
    code, _out, err = run_shim(shim_path, shim_conf, "@elevated dmesg-recent")
    assert code != 0
    assert "not a configured elevated recipe" in err


def test_ping_reports_version(shim_path: Path, shim_conf: Path, spec: dict) -> None:
    code, out, _err = run_shim(shim_path, shim_conf, "@ping")
    assert code == 0
    assert json.loads(out) == {"ok": True, "version": fingerprint(spec)}


# --------------------------------------------------------------------------------------
# The structured wire format
# --------------------------------------------------------------------------------------


def test_run_accepts_structured_argv(shim_path: Path, shim_conf: Path) -> None:
    """argv travels as JSON, so the remote side never tokenises a string."""
    code, out, _err = run_shim(shim_path, shim_conf, '@run ["df","-h"]')
    assert code == 0
    assert "Filesystem" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["rm", "-rf", "/"],
        ["sh", "-c", "id"],
        ["docker", "exec", "app", "id"],
        ["/bin/sh"],
        ["tail", "-n", "5", "/etc/shadow"],
        ["curl", "file:///etc/passwd"],
        ["journalctl", "--follow"],
        ["df", "-h;", "rm"],
    ],
    ids=lambda a: " ".join(a)[:40],
)
def test_hand_crafted_argv_is_refused(shim_path: Path, shim_conf: Path, argv: list[str]) -> None:
    """The bypass case: argv sent straight over SSH, never touching our client.

    This is what the shim is *for*. Our own client would never produce these, so nothing
    on this machine is being tested here — only the remote boundary.
    """
    payload = "@run " + json.dumps(argv)
    code, _out, err = run_shim(shim_path, shim_conf, payload)
    assert code != 0, f"{argv} was executed"
    assert "Rejected" in err


@pytest.mark.parametrize(
    "payload",
    ["@run not-json", '@run {"a":1}', '@run ["df",5]', "@run []", "@run"],
)
def test_malformed_run_payloads_fail_closed(shim_path: Path, shim_conf: Path, payload: str) -> None:
    code, _out, err = run_shim(shim_path, shim_conf, payload)
    assert code != 0
    assert "Rejected" in err or "safereach-shim" in err


def test_argv_and_string_paths_agree(
    shim_path: Path, shim_conf: Path, spec: dict, ctx: dict
) -> None:
    """The two entry points must reach the same verdict on the same command."""
    for command in ("journalctl -u ssh -n 5", "docker logs app", "df -h"):
        argv = validate(command, spec, ctx=ctx).argv
        _c1, via_string, _e1 = run_shim(shim_path, shim_conf, "@check", stdin=command)
        _c2, via_argv, _e2 = run_shim(shim_path, shim_conf, "@check", stdin=json.dumps(argv))
        assert via_string == via_argv, f"paths disagree for {command!r}"


# --------------------------------------------------------------------------------------
# Host-side redaction
# --------------------------------------------------------------------------------------


def test_redaction_is_inlined_into_the_shim(shim_path: Path) -> None:
    """Masking must happen on the host, not only in the MCP server.

    The server redacts too, but that is a second pass on data that has already crossed
    the wire. Anyone holding the enrolled key — including someone bypassing our client —
    would otherwise get `docker inspect` with Config.Env intact, which is exactly where a
    container's .env ends up.
    """
    source = shim_path.read_text(encoding="utf-8")
    assert "redact_docker_inspect" in source
    assert "_is_env_bearing" in source
    assert "REDACTED" in source


def test_fingerprint_covers_redaction_changes(tmp_path: Path, spec: dict) -> None:
    """A change to what gets masked must invalidate every deployed shim.

    Otherwise a host could keep running an older, more permissive redaction pass while
    reporting a version the server considers current.
    """
    from safereach.versioning import fingerprint, validator_source_path

    validator = validator_source_path().read_text(encoding="utf-8")
    redact = validator_source_path().with_name("redact.py").read_text(encoding="utf-8")

    baseline = fingerprint(spec, validator + redact)
    changed = fingerprint(spec, validator + redact + "\n# a redaction tweak\n")
    assert baseline != changed
