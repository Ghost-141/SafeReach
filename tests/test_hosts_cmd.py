"""`safereach hosts`: the operator's list of configured hosts, addresses included.

The MCP tool `list_hosts` hides addresses from the agent on purpose. This command is the
other side of that decision — the person who wrote hosts.yaml gets to read it back as a
table — so the tests pin both that the address IS shown here and that nothing needs the
network to show it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CONFIG = """\
defaults:
  known_hosts: ~/.ssh/known_hosts
hosts:
  prod-web:
    hostname: 10.0.1.5
    user: diag
    port: 2222
    key: ~/.ssh/id_ed25519_diag
    description: "diag@10.0.1.5 (hardened)"
    allow: [df]
  lab:
    ssh_config_host: lab-box
    require_shim: false
    description: "throwaway"
    allow: [df]
"""


def _run(*args: str, config: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "safereach", "--config", str(config), *args],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": str(config.parent), "NO_COLOR": "1"},
    )


def test_table_shows_alias_and_address(tmp_path: Path) -> None:
    config = tmp_path / "hosts.yaml"
    config.write_text(CONFIG, encoding="utf-8")
    proc = _run("hosts", config=config)
    assert proc.returncode == 0, proc.stderr
    out = proc.stderr  # the console is bound to stderr; stdout stays clean
    assert "prod-web" in out and "10.0.1.5" in out and "2222" in out and "diag" in out
    assert "lab" in out and "lab-box" in out
    assert "enrolled" in out and "client-only" in out
    assert proc.stdout == ""


def test_json_is_on_stdout_and_complete(tmp_path: Path) -> None:
    config = tmp_path / "hosts.yaml"
    config.write_text(CONFIG, encoding="utf-8")
    proc = _run("hosts", "--json", config=config)
    assert proc.returncode == 0, proc.stderr
    rows = {r["alias"]: r for r in json.loads(proc.stdout)}
    assert rows["prod-web"] == {
        "alias": "prod-web",
        "address": "10.0.1.5",
        "user": "diag",
        "port": 2222,
        "mode": "enrolled",
        "description": "diag@10.0.1.5 (hardened)",
    }
    assert rows["lab"]["address"] == "~/.ssh/config: lab-box"
    assert rows["lab"]["mode"] == "client-only"
    assert rows["lab"]["port"] == 22


def test_no_hosts_says_so(tmp_path: Path) -> None:
    config = tmp_path / "hosts.yaml"
    config.write_text("hosts: {}\n", encoding="utf-8")
    proc = _run("hosts", config=config)
    assert proc.returncode == 1
    assert "no hosts configured" in proc.stderr
    assert "safereach enroll" in proc.stderr


def test_missing_config_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    proc = _run("hosts", config=tmp_path / "nope.yaml")
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "no hosts.yaml found" in proc.stderr
