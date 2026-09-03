"""The rename command — the half of naming that edits the user's config file.

`tests/test_naming.py` covers the pure functions. This covers the part that rewrites
`hosts.yaml` in place, which is where a mistake costs the user their configuration rather
than just an error message.

The rewrite is targeted text editing rather than a YAML round-trip, for the same reason
the Codex TOML adapter is: a round-trip discards the comments the file is full of. That
choice is only safe if the pattern is genuinely anchored to a top-level host key — hence
the tests below for host names that also appear in descriptions, comments and values.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from safereach import naming
from safereach.cli import _apply_renames, _prompt, _resolve_enroll_names, _rewrite_alias
from safereach.config import load_settings

CONFIG = """\
# Written by `safereach enroll`.
# Do not lose this comment.
defaults:
  audit_log: {audit}

hosts:
  203.96.189.202:
    id: hec8e7d147c3f
    hostname: 203.96.189.202
    user: diag
    port: 22
    description: "diag@203.96.189.202 (hardened)"
    allow: [df, journalctl]
    curl_targets: [localhost, 127.0.0.1]

  web-01:
    hostname: 10.0.1.5
    user: diag
    description: "the 203.96.189.202 neighbour"
    allow: [df]
"""


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "hosts.yaml"
    path.write_text(CONFIG.format(audit=tmp_path / "audit.jsonl"), encoding="utf-8")
    return path


# --------------------------------------------------------------------------------------
# The rewrite itself
# --------------------------------------------------------------------------------------


def test_rewrite_replaces_the_host_key(config: Path) -> None:
    out = _rewrite_alias(config.read_text(), "203.96.189.202", "langfuse-prod")
    assert "\n  langfuse-prod:\n" in out
    assert "\n  203.96.189.202:\n" not in out


def test_rewrite_leaves_the_same_string_alone_elsewhere(config: Path) -> None:
    """The name appears in a description, a value and another host's text.

    Only the top-level key may change. A looser pattern would silently rewrite the
    `hostname:` the host actually connects to — and the rename would then point at a
    machine that does not exist.
    """
    out = _rewrite_alias(config.read_text(), "203.96.189.202", "langfuse-prod")
    assert "hostname: 203.96.189.202" in out, "the connection target must not change"
    assert 'description: "diag@203.96.189.202 (hardened)"' in out
    assert 'description: "the 203.96.189.202 neighbour"' in out


def test_rewrite_preserves_comments_and_other_hosts(config: Path) -> None:
    out = _rewrite_alias(config.read_text(), "203.96.189.202", "langfuse-prod")
    assert "# Do not lose this comment." in out
    assert "\n  web-01:\n" in out
    assert "curl_targets: [localhost, 127.0.0.1]" in out


def test_rewrite_refuses_when_the_host_is_absent(config: Path) -> None:
    with pytest.raises(RuntimeError, match="found 0"):
        _rewrite_alias(config.read_text(), "not-a-host", "whatever")


def test_rewrite_refuses_an_ambiguous_match() -> None:
    """Two keys with the same name is a broken file; editing it blind would worsen it."""
    text = "hosts:\n  dup:\n    hostname: a\n  dup:\n    hostname: b\n"
    with pytest.raises(RuntimeError, match="found 2"):
        _rewrite_alias(text, "dup", "new")


def test_rewrite_output_is_still_valid_yaml(config: Path) -> None:
    import yaml

    out = _rewrite_alias(config.read_text(), "203.96.189.202", "langfuse-prod")
    parsed = yaml.safe_load(out)
    assert set(parsed["hosts"]) == {"langfuse-prod", "web-01"}


# --------------------------------------------------------------------------------------
# Applying renames
# --------------------------------------------------------------------------------------


def test_apply_writes_a_backup_before_changing_anything(config: Path) -> None:
    original = config.read_text()
    settings = load_settings(config)
    assert _apply_renames(settings, [("203.96.189.202", "langfuse-prod")]) == 0

    backups = list(config.parent.glob("hosts.yaml.bak-*"))
    assert backups, "no backup was written"
    assert backups[0].read_text() == original


def test_apply_is_local_only_and_keeps_the_connection_intact(config: Path) -> None:
    """The claim the design rests on: renaming must not change how we reach the host."""
    settings = load_settings(config)
    _apply_renames(settings, [("203.96.189.202", "langfuse-prod")])

    host = load_settings(config).host("langfuse-prod")
    assert host.hostname == "203.96.189.202"
    assert host.user == "diag"
    assert host.allow == ["df", "journalctl"]


def test_apply_preserves_the_stable_id(config: Path) -> None:
    """Audit continuity across a rename is the entire reason `id` exists."""
    before = load_settings(config).host("203.96.189.202").id
    _apply_renames(load_settings(config), [("203.96.189.202", "langfuse-prod")])
    assert load_settings(config).host("langfuse-prod").id == before


def test_apply_records_the_rename_in_the_audit_log(config: Path, tmp_path: Path) -> None:
    """A rename changes how every later record reads, so it belongs in the log."""
    settings = load_settings(config)
    host_id = settings.host("203.96.189.202").id
    _apply_renames(settings, [("203.96.189.202", "langfuse-prod")])

    entries = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]
    renames = [e for e in entries if e["decision"] == "renamed"]
    assert len(renames) == 1
    assert renames[0]["previous_host"] == "203.96.189.202"
    assert renames[0]["host"] == "langfuse-prod"
    assert renames[0]["host_id"] == host_id


def test_apply_refuses_a_collision(config: Path) -> None:
    settings = load_settings(config)
    assert _apply_renames(settings, [("203.96.189.202", "web-01")]) == 1
    assert set(load_settings(config).hosts) == {"203.96.189.202", "web-01"}


def test_apply_refuses_an_invalid_name_without_touching_the_file(config: Path) -> None:
    original = config.read_text()
    assert _apply_renames(load_settings(config), [("web-01", "deploy@web")]) == 1
    assert config.read_text() == original, "a rejected rename must change nothing"


def test_apply_skips_unknown_hosts(config: Path) -> None:
    original = config.read_text()
    assert _apply_renames(load_settings(config), [("ghost", "new")]) == 1
    assert config.read_text() == original


def test_apply_handles_several_renames_at_once(config: Path) -> None:
    settings = load_settings(config)
    assert (
        _apply_renames(settings, [("203.96.189.202", "langfuse-prod"), ("web-01", "prod-web")]) == 0
    )
    assert set(load_settings(config).hosts) == {"langfuse-prod", "prod-web"}


def test_renaming_to_the_same_name_is_a_noop(config: Path) -> None:
    assert _apply_renames(load_settings(config), [("web-01", "web-01")]) == 1
    assert not list(config.parent.glob("hosts.yaml.bak-*")), "no backup for a no-op"


def test_a_partial_failure_still_applies_the_good_renames(config: Path) -> None:
    """One bad entry in a names file must not discard the rest."""
    settings = load_settings(config)
    _apply_renames(settings, [("203.96.189.202", "langfuse-prod"), ("web-01", "bad name")])
    hosts = set(load_settings(config).hosts)
    assert "langfuse-prod" in hosts
    assert "web-01" in hosts, "the invalid rename should have been skipped, not fatal"


# --------------------------------------------------------------------------------------
# Choosing names during enrolment
# --------------------------------------------------------------------------------------


def args(**kw: object) -> argparse.Namespace:
    defaults = {"name": None, "names": None, "no_prompt": True}
    return argparse.Namespace(**{**defaults, **kw})


def test_non_tty_never_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    """The regression that would make this feature actively harmful in CI."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("prompted in a non-TTY"))
    assert _prompt("label", "fallback") == "fallback"


def test_explicit_name_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "safereach.discovery.resolve_alias",
        lambda a: type("R", (), {"hostname": "10.0.1.5", "user": "diag", "port": 22})(),
    )
    assert _resolve_enroll_names(["web"], args(name="prod-web")) == {"web": "prod-web"}


def test_explicit_name_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "safereach.discovery.resolve_alias",
        lambda a: type("R", (), {"hostname": "10.0.1.5", "user": "diag", "port": 22})(),
    )
    with pytest.raises(naming.InvalidName, match="@"):
        _resolve_enroll_names(["web"], args(name="deploy@web"))


def test_name_flag_refuses_multiple_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "safereach.discovery.resolve_alias",
        lambda a: type("R", (), {"hostname": "10.0.1.5", "user": "diag", "port": 22})(),
    )
    with pytest.raises(SystemExit):
        _resolve_enroll_names(["a", "b"], args(name="one-name"))


def test_falls_back_to_suggestions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "safereach.discovery.resolve_alias",
        lambda a: type("R", (), {"hostname": "db.eu.internal", "user": "d", "port": 22})(),
    )
    assert _resolve_enroll_names(["db.eu.internal"], args()) == {"db.eu.internal": "db"}


def test_names_file_applied_at_enrolment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "safereach.discovery.resolve_alias",
        lambda a: type("R", (), {"hostname": "10.0.1.5", "user": "d", "port": 22})(),
    )
    names = tmp_path / "names.yaml"
    names.write_text("10.0.1.5: prod-web\n", encoding="utf-8")
    assert _resolve_enroll_names(["web"], args(names=str(names))) == {"web": "prod-web"}
