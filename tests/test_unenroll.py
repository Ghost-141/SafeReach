"""`safereach unenroll`: everything enrolment installed comes back out.

Two halves. The local half — removing the host's block from hosts.yaml without touching
anything else in the file — runs for real here. The remote half runs as root on a host
and is asserted as text: the order of operations is what makes each intermediate state
safe, and that order is what these tests pin. The end-to-end suite executes it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from safereach import cli
from safereach.cli import (
    UNENROLL_ROOT_SCRIPT,
    UNENROLL_USER_SCRIPT,
    _remove_host_entry,
    _strip_markers_sh,
    build_parser,
)

CONFIG = """\
# Written by `safereach enroll`.
defaults:
  audit_log: {audit}

hosts:
  prod-web:
    id: h1
    hostname: 10.0.1.5
    user: diag
    port: 22
    description: "diag@10.0.1.5 (hardened)"
    allow: [df, journalctl]
    # a comment inside the block that mentions prod-web
    curl_targets: [localhost]

  prod-web-2:
    id: h2
    hostname: 10.0.1.6
    user: diag
    key: ~/.ssh/k
    description: "second"
    allow: [df]
"""


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "hosts.yaml"
    path.write_text(CONFIG.format(audit=tmp_path / "audit.jsonl"), encoding="utf-8")
    return path


# --------------------------------------------------------------------------------------
# hosts.yaml surgery
# --------------------------------------------------------------------------------------


def test_removes_exactly_one_block_and_keeps_the_rest(config: Path) -> None:
    out = _remove_host_entry(config.read_text(encoding="utf-8"), "prod-web")
    data = yaml.safe_load(out)
    assert list(data["hosts"]) == ["prod-web-2"]
    assert data["hosts"]["prod-web-2"]["hostname"] == "10.0.1.6"
    assert "# Written by `safereach enroll`." in out  # comments outside the block survive
    assert "mentions prod-web" not in out  # comments inside the block go with it
    assert "10.0.1.5" not in out


def test_a_prefix_of_another_alias_is_not_matched(config: Path) -> None:
    """`prod-web` must not swallow `prod-web-2`, and vice versa."""
    out = _remove_host_entry(config.read_text(encoding="utf-8"), "prod-web-2")
    data = yaml.safe_load(out)
    assert list(data["hosts"]) == ["prod-web"]
    assert data["hosts"]["prod-web"]["hostname"] == "10.0.1.5"


def test_removing_the_last_host_leaves_a_loadable_file(tmp_path: Path) -> None:
    text = "defaults:\n  port: 22\nhosts:\n  only:\n    hostname: h\n    user: u\n    key: k\n"
    out = _remove_host_entry(text, "only")
    data = yaml.safe_load(out)
    assert data["hosts"] is None or data["hosts"] == {}
    assert data["defaults"]["port"] == 22


def test_refuses_an_absent_or_ambiguous_host(config: Path) -> None:
    with pytest.raises(RuntimeError, match="found 0"):
        _remove_host_entry(config.read_text(encoding="utf-8"), "nope")
    doubled = (
        config.read_text(encoding="utf-8")
        + "\n  prod-web:\n    hostname: dup\n    user: u\n    key: k\n"
    )
    with pytest.raises(RuntimeError, match="found 2"):
        _remove_host_entry(doubled, "prod-web")


# --------------------------------------------------------------------------------------
# The remote scripts, as text
# --------------------------------------------------------------------------------------


def _root(**kw: object) -> str:
    base = dict(
        diag_user="diag",
        remove_user=0,
        purge_log=0,
        proxy_port="2375",
        strip=_strip_markers_sh('"$HOME_DIR/.ssh/.ak.new"'),
    )
    base.update(kw)
    return UNENROLL_ROOT_SCRIPT.format(**base)


def test_root_script_order_keeps_every_intermediate_state_safe() -> None:
    s = _root()
    # sshd: validate before reload, and never reload an invalid config
    assert s.index("rm -f /etc/ssh/sshd_config.d/zz-safereach-diag.conf") < s.index("sshd -t")
    assert s.index("sshd -t") < s.index("systemctl reload ssh")
    assert "removed-config-invalid" in s
    # the firewall rule names the account: delete it before the account can be deleted
    assert s.index("iptables -D OUTPUT") < s.index("userdel")
    # append-only flag comes off before the log is touched
    assert s.index("chattr -a /var/log/safereach.jsonl") < s.index('"$PURGE_LOG" = "1"')
    # every root-owned artefact of hardened enrolment is named
    for path in (
        "/etc/sudoers.d/safereach",
        "/usr/local/bin/safereach-shim",
        "/etc/safereach",
        "/etc/tmpfiles.d/safereach.conf",
        "/run/safereach",
        "safereach-docker-proxy",
    ):
        assert path in s, path


def test_root_script_keeps_the_log_and_the_account_by_default() -> None:
    s = _root()
    assert 'PURGE_LOG="0"' in s and 'REMOVE_USER="0"' in s
    assert "LOG=kept" in s and "USER=kept" in s
    s = _root(remove_user=1, purge_log=1)
    assert 'PURGE_LOG="1"' in s and 'REMOVE_USER="1"' in s
    assert "userdel -r" in s


def test_user_script_reverses_plain_enrol_only() -> None:
    s = UNENROLL_USER_SCRIPT.format(strip=_strip_markers_sh('"$HOME/.ssh/.ak.new"'), purge_log=0)
    assert 'rm -f "$HOME/.local/bin/safereach-shim"' in s
    assert 'rm -rf "$HOME/.config/safereach-shim"' in s
    assert "sudo" not in s and "/etc/" not in s  # nothing root-owned from this half
    # the marker strip is the same one enrolment uses, so it removes exactly our line
    assert "grep -vF" in s and 'mv "$HOME/.ssh/.ak.new" "$HOME/.ssh/authorized_keys"' in s


# --------------------------------------------------------------------------------------
# The command, without a host
# --------------------------------------------------------------------------------------


def _parse(*argv: str, config: Path) -> object:
    return build_parser().parse_args(["--config", str(config), "unenroll", *argv])


def test_dry_run_prints_both_scripts_and_touches_nothing(
    config: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    def boom(*a, **k):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError("dry-run must not run anything")

    monkeypatch.setattr(cli.subprocess, "run", boom)
    args = _parse("prod-web", "--dry-run", config=config)
    assert cli.cmd_unenroll(args) == 0
    err = capsys.readouterr().err
    assert "as the connecting account" in err and "as root" in err
    assert "zz-safereach-diag.conf" in err
    assert "prod-web" in config.read_text(encoding="utf-8")


def test_refuses_without_yes(config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a, **k):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError("must not touch the host without --yes")

    monkeypatch.setattr(cli.subprocess, "run", boom)
    assert cli.cmd_unenroll(_parse("prod-web", config=config)) == 1
    assert "prod-web" in config.read_text(encoding="utf-8")


def test_local_only_drops_the_entry_and_backs_up(
    config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a, **k):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError("--local-only must not touch the host")

    monkeypatch.setattr(cli.subprocess, "run", boom)
    assert cli.cmd_unenroll(_parse("prod-web", "--local-only", "--yes", config=config)) == 0
    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert list(data["hosts"]) == ["prod-web-2"]
    backups = list(config.parent.glob("hosts.yaml.bak-*"))
    assert len(backups) == 1 and "prod-web" in backups[0].read_text(encoding="utf-8")
    audit = (config.parent / "audit.jsonl").read_text(encoding="utf-8")
    assert '"decision":"unenrolled"' in audit and '"host":"prod-web"' in audit


def test_host_stays_when_the_key_still_works(config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A host that still answers the enrolled key must not be forgotten."""
    calls: list[list[str]] = []

    def fake_run(cmd, **kw):  # noqa: ANN001, ANN003
        calls.append(list(cmd))
        return subprocess.CompletedProcess(
            cmd, 0, stdout="USER_CLEANUP=done\nSHIM=removed\n", stderr=""
        )

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli, "_admin_ssh_argv", lambda h, a, args: ["ssh", "admin"])
    rc = cli.cmd_unenroll(_parse("prod-web", "--yes", config=config))
    assert rc == 1
    assert "prod-web" in config.read_text(encoding="utf-8")
    # the key probe ran, with only the enrolled key and never the operator's own
    probe = [c for c in calls if "@ping" in c][0]
    assert "-F" in probe and "/dev/null" in probe and "IdentitiesOnly=yes" in probe


def test_unknown_host_is_an_error(config: Path) -> None:
    assert cli.cmd_unenroll(_parse("nope", "--yes", config=config)) == 1
