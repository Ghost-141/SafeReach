"""Named log sources: discovery facts → checklist → policy → `read_logs` on the host.

The facts fixture is shaped like a real PM2 host: a Node app writing dated files under
/opt, PM2's own out/err logs in the app user's home, a unit whose journal is empty because
the app logs to files, nginx, syslog, and two containers. The tests assert what the
operator is offered, what is pre-ticked, what is refused outright, and that the shim reads
exactly what a source names and nothing beside it.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml
from test_shim import run_shim

from safereach import cli, logsources
from safereach.config import HostConfig, load_settings
from safereach.hostlogs import _parents
from safereach.server import _describe_source
from safereach.validator import Rejected, check_log_source, validate, validate_argv

NOW = 1_800_000_000.0
HOSTLOGS = Path(__file__).resolve().parent.parent / "src" / "safereach" / "hostlogs.py"


# --------------------------------------------------------------------------------------
# check_log_source
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "raw", "expected"),
    [
        (
            "api",
            {"kind": "file", "dir": "/opt/shop/api/logs"},
            {"kind": "file", "dir": "/opt/shop/api/logs/", "glob": "*"},
        ),
        (
            "nginx",
            {"kind": "file", "dir": "/var/log/nginx/", "glob": "*.log*"},
            {"kind": "file", "dir": "/var/log/nginx/", "glob": "*.log*"},
        ),
        ("api-c", {"kind": "docker", "container": "api"}, {"kind": "docker", "container": "api"}),
        (
            "pg",
            {"kind": "journal", "unit": "postgresql@16-main.service"},
            {"kind": "journal", "unit": "postgresql@16-main.service"},
        ),
    ],
)
def test_check_log_source_normalises(name: str, raw: dict, expected: dict) -> None:
    assert check_log_source(name, raw) == expected


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("API", {"kind": "file", "dir": "/opt/a/logs/"}),
        ("a b", {"kind": "file", "dir": "/opt/a/logs/"}),
        ("x" * 49, {"kind": "file", "dir": "/opt/a/logs/"}),
        ("a", {"kind": "file", "dir": "/opt/"}),
        ("a", {"kind": "file", "dir": "/etc/"}),
        ("a", {"kind": "file", "dir": "/opt/a/logs/", "glob": "../*"}),
        ("a", {"kind": "file", "dir": "/opt/a/logs/", "glob": "**"}),
        ("a", {"kind": "file", "dir": "/opt/a/logs/", "glob": "sub/*.log"}),
        ("a", {"kind": "docker", "container": "-it"}),
        ("a", {"kind": "docker", "container": "a;b"}),
        ("a", {"kind": "journal", "unit": "--all"}),
        ("a", {"kind": "exec", "cmd": "sh"}),
        ("a", "not a mapping"),
    ],
)
def test_check_log_source_refuses(name: str, raw: object) -> None:
    with pytest.raises(Rejected):
        check_log_source(name, raw)


def test_host_config_folds_file_sources_into_log_dirs() -> None:
    host = HostConfig(
        alias="a",
        ssh_config_host="a",
        log_paths=["/opt/extra/logs/"],
        log_sources={
            "api": {"kind": "file", "dir": "/opt/shop/api/logs", "glob": "*.log*"},
            "c": {"kind": "docker", "container": "api"},
        },
    )
    assert host.log_dirs() == ["/opt/extra/logs/", "/opt/shop/api/logs/"]
    assert host.public_view()["log_sources"] == {"api": "file", "c": "docker"}
    with pytest.raises(ValueError):
        HostConfig(alias="a", ssh_config_host="a", log_sources={"x": {"kind": "file", "dir": "/"}})


# --------------------------------------------------------------------------------------
# Facts → candidates
# --------------------------------------------------------------------------------------


def _dir(
    names: list[str], age: float, hazards: list[str] | None = None, readable: bool = True
) -> dict:
    return {
        "exists": True,
        "files": len(names),
        "bytes": 1_200_000,
        "names": names,
        "newest": names[0] if names else None,
        "newest_mtime": NOW - age if names else None,
        "hazards": hazards or [],
        "readable": readable,
    }


@pytest.fixture
def facts() -> dict:
    return {
        "now": NOW,
        "dirs": {
            "/var/log/": _dir(["syslog", "syslog.1", "auth.log", "auth.log.1"], 60),
            "/var/log/nginx/": _dir(["access.log", "error.log"], 30),
            "/var/log/postgresql/": _dir(["postgresql-16-main.log"], 40 * 86400),
            "/opt/shop/api/logs/": _dir(["error-2026-10-22.log", "debug-2026-10-22.log"], 120),
            "/opt/shop/uploads/logs/": _dir(["import.log"], 300, hazards=[".env"]),
            "/home/app/.pm2/logs/": _dir(["api-out.log", "api-error.log"], 90),
            "/opt/": _dir(["install.log"], 600),
        },
        "open_logs": [
            {"path": "/var/log/syslog", "comm": "rsyslogd", "unit": "rsyslog.service"},
            {
                "path": "/opt/shop/api/logs/error-2026-10-22.log",
                "comm": "node",
                "unit": "pm2-app.service",
            },
            {
                "path": "/opt/shop/uploads/logs/import.log",
                "comm": "node",
                "unit": "pm2-app.service",
            },
            {"path": "/opt/install.log", "comm": "installer", "unit": None},
        ],
        "pm2_dirs": ["/home/app/.pm2/logs/"],
        "app_units": [{"unit": "pm2-app.service", "comm": "PM2 v5", "cwd": "/home/app"}],
        "running_units": ["nginx.service", "pm2-app.service", "postgresql.service"],
        "journal_empty": {
            "pm2-app.service": True,
            "nginx.service": False,
            "postgresql.service": False,
        },
        "containers": ["api", "worker"],
    }


def _by_name(candidates: list[logsources.Candidate]) -> dict[str, logsources.Candidate]:
    return {c.name: c for c in candidates}


def test_candidates_cover_every_kind_of_location(facts: dict) -> None:
    candidates, skipped = logsources.build_candidates(facts)
    found = _by_name(candidates)

    assert found["syslog"].spec == {"kind": "file", "dir": "/var/log/", "glob": "syslog*"}
    assert found["shop-api"].spec == {
        "kind": "file",
        "dir": "/opt/shop/api/logs/",
        "glob": "*.log*",
    }
    assert found["pm2-app"].spec == {
        "kind": "file",
        "dir": "/home/app/.pm2/logs/",
        "glob": "*.log*",
    }
    assert found["nginx"].spec["dir"] == "/var/log/nginx/"
    assert found["api"].spec == {"kind": "docker", "container": "api"}
    journal = [c for c in candidates if c.spec.get("unit") == "pm2-app.service"]
    assert journal and "logs to files, not journald" in journal[0].detail
    assert any("/opt/" in s and "too broad" in s for s in skipped)


def test_preselection_ticks_what_is_in_use(facts: dict) -> None:
    found = _by_name(logsources.build_candidates(facts)[0])
    ticked = {name for name, c in found.items() if c.selected}
    # Running containers are the application on a container host.
    assert {"syslog", "shop-api", "pm2-app", "nginx", "api", "worker"} <= ticked
    # Unticked: auth logs, a stale service log, an empty journal.
    assert not found["auth"].selected
    assert not found["postgres"].selected
    assert not [c for c in found.values() if c.spec.get("unit") == "pm2-app.service"][0].selected


# The cases below were found by running the scan against live hosts.


def test_pm2_home_and_editor_state_are_never_offered(facts: dict) -> None:
    facts["open_logs"] += [
        {"path": "/home/app/.pm2/pm2.log", "comm": "PM2 v5", "unit": "pm2-app.service"},
        {"path": "/home/app/.vscode-server/cli/x.log", "comm": "code", "unit": None},
    ]
    candidates, skipped = logsources.build_candidates(facts)
    dirs = {c.spec.get("dir") for c in candidates}
    assert "/home/app/.pm2/" not in dirs
    assert "/home/app/.vscode-server/cli/" not in dirs
    assert any(".pm2" in s and "hidden directory" in s for s in skipped)


def test_shared_directory_sources_report_their_own_size(facts: dict) -> None:
    facts["dirs"]["/var/log/"]["entries"] = [
        ["syslog", 20_000_000, NOW - 10],
        ["auth.log", 3_000, NOW - 5 * 86400],
        ["syslog.1", 1_000_000, NOW - 86400],
    ]
    found = _by_name(logsources.build_candidates(facts)[0])
    assert "20.0 MB" in found["syslog"].detail or "20.1 MB" in found["syslog"].detail
    assert "2.9 KB" in found["auth"].detail and "5d ago" in found["auth"].detail


def test_system_units_and_our_proxy_are_not_sources(facts: dict) -> None:
    facts["app_units"].append({"unit": "dbus.service", "comm": "dbus-daemon", "cwd": "/home/app"})
    facts["containers"].append("safereach-docker-proxy")
    found = logsources.build_candidates(facts)[0]
    assert not [c for c in found if c.spec.get("unit") == "dbus.service"]
    assert not [c for c in found if c.spec.get("container") == "safereach-docker-proxy"]


def test_journal_of_a_service_with_log_files_is_not_preticked(facts: dict) -> None:
    found = logsources.build_candidates(facts)[0]
    nginx_journal = [c for c in found if c.spec.get("unit") == "nginx.service"]
    assert nginx_journal and nginx_journal[0].name == "nginx-journal"
    assert not nginx_journal[0].selected


def test_directory_beside_a_secret_carries_a_warning(facts: dict) -> None:
    found = _by_name(logsources.build_candidates(facts)[0])
    warned = [c for c in found.values() if c.spec.get("dir") == "/opt/shop/uploads/logs/"]
    assert warned and ".env" in (warned[0].warning or "")


def test_configured_sources_stay_ticked_and_are_not_duplicated(facts: dict) -> None:
    existing = {"api-logs": {"kind": "file", "dir": "/opt/shop/api/logs/", "glob": "*.log*"}}
    candidates, _ = logsources.build_candidates(facts, existing)
    same_dir = [c for c in candidates if c.spec.get("dir") == "/opt/shop/api/logs/"]
    assert [c.name for c in same_dir] == ["api-logs"]
    assert same_dir[0].selected


def test_checklist_renders_every_candidate(facts: dict) -> None:
    candidates, skipped = logsources.build_candidates(facts)
    text = logsources.render_checklist("web-1", candidates, skipped)
    assert text.startswith("web-1 — log sources found")
    assert "[x] shop-api" in text
    assert "skipped: /opt/" in text


# --------------------------------------------------------------------------------------
# The dialogue
# --------------------------------------------------------------------------------------


def test_choose_toggles_adds_and_refuses(facts: dict) -> None:
    candidates, skipped = logsources.build_candidates(facts)
    api_index = next(i for i, c in enumerate(candidates, 1) if c.name == "api")
    answers = iter(
        [
            str(api_index),
            "a /opt/",
            "a /opt/shop/worker/logs worker",
            "a /opt/shop/worker/logs worker-files",
            "7x",
            "",
        ]
    )
    shown: list[str] = []
    chosen = logsources.choose(
        "web-1", candidates, skipped, ask=lambda _q: next(answers), show=shown.append
    )
    # `api` was pre-ticked (a running container); its number toggled it off.
    assert "api" not in chosen
    assert chosen["worker"] == {"kind": "docker", "container": "worker"}
    assert chosen["worker-files"] == {
        "kind": "file",
        "dir": "/opt/shop/worker/logs/",
        "glob": "*",
    }
    assert any("cannot add" in s and "too broad" in s for s in shown)
    assert any("'worker' is already on the list" in s for s in shown)
    assert any("ignored '7x'" in s for s in shown)


def test_choose_n_clears_every_tick(facts: dict) -> None:
    candidates, skipped = logsources.build_candidates(facts)
    answers = iter(["n", ""])
    chosen = logsources.choose(
        "h", candidates, skipped, ask=lambda _q: next(answers), show=lambda _s: None
    )
    assert chosen == {}


@pytest.mark.parametrize(
    ("arg", "expected"),
    [
        (
            "api=/opt/shop/api/logs/:*.log*",
            ("api", {"kind": "file", "dir": "/opt/shop/api/logs/", "glob": "*.log*"}),
        ),
        (
            "api=/opt/shop/api/logs",
            ("api", {"kind": "file", "dir": "/opt/shop/api/logs/", "glob": "*"}),
        ),
        ("w=docker:worker", ("w", {"kind": "docker", "container": "worker"})),
        (
            "pg=journal:postgresql.service",
            ("pg", {"kind": "journal", "unit": "postgresql.service"}),
        ),
    ],
)
def test_parse_source_arg(arg: str, expected: tuple) -> None:
    assert logsources.parse_source_arg(arg) == expected


@pytest.mark.parametrize(
    "arg", ["api", "api=", "api=/opt/", "API=/opt/a/logs/", "a=docker:", "a=/etc/x/"]
)
def test_parse_source_arg_refuses(arg: str) -> None:
    with pytest.raises(Rejected):
        logsources.parse_source_arg(arg)


# --------------------------------------------------------------------------------------
# hosts.yaml
# --------------------------------------------------------------------------------------

HOSTS_YAML = """\
# my fleet — comments must survive
defaults:
  audit_log: /tmp/audit.jsonl

hosts:
  web-1:
    ssh_config_host: web-1
    description: "app server"   # keep me
    log_sources:
      old: {"kind": "docker", "container": "old"}
    curl_targets: [localhost]

  db-1:
    ssh_config_host: db-1
"""


def test_set_host_log_sources_replaces_only_that_block(tmp_path: Path) -> None:
    sources = {
        "api": {"kind": "file", "dir": "/opt/shop/api/logs/", "glob": "*.log*"},
        "worker": {"kind": "docker", "container": "worker"},
    }
    text = cli._set_host_log_sources(HOSTS_YAML, "web-1", sources)
    assert "# my fleet — comments must survive" in text
    assert "# keep me" in text
    assert "old:" not in text
    path = tmp_path / "hosts.yaml"
    path.write_text(text)
    settings = load_settings(path)
    assert settings.host("web-1").log_sources == sources
    assert settings.host("web-1").curl_targets == ["localhost"]
    assert settings.host("db-1").log_sources == {}


def test_yaml_lines_round_trip() -> None:
    sources = {"api": {"kind": "file", "dir": "/opt/a/logs/", "glob": "*.log*"}}
    loaded = yaml.safe_load("\n".join(["x:", *logsources.yaml_lines(sources, indent="  ")]))
    assert loaded == {"x": {"log_sources": sources}}


# --------------------------------------------------------------------------------------
# hostlogs.py, run for real as the host would run it
# --------------------------------------------------------------------------------------


def _hostlogs(mode: str, params: dict, home: Path) -> tuple[int, dict]:
    blob = base64.b64encode(json.dumps(params).encode()).decode()
    proc = subprocess.run(
        [sys.executable, "-I", "-", mode, blob],
        input=HOSTLOGS.read_text(),
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
        check=False,
    )
    return proc.returncode, json.loads(proc.stdout.strip().splitlines()[-1])


def test_discover_reports_names_and_sizes_never_contents(tmp_path: Path) -> None:
    logs = tmp_path / "app" / "logs"
    logs.mkdir(parents=True)
    (logs / "app.log").write_text("SECRET-CONTENT-NEVER-REPORTED\n")
    (logs / ".env").write_text("TOKEN=x\n")
    code, facts = _hostlogs(
        "discover", logsources.discovery_params() | {"dirs": [f"{logs}/"]}, tmp_path
    )
    assert code == 0
    d = facts["dirs"][f"{logs}/"]
    assert d["names"] == ["app.log"]
    assert d["hazards"] == [".env"]
    assert d["readable"] is True
    assert "SECRET-CONTENT" not in json.dumps(facts)


def test_apply_rewrites_only_the_log_keys_of_the_user_policy(tmp_path: Path) -> None:
    policy = tmp_path / ".config" / "safereach-shim" / "config.json"
    policy.parent.mkdir(parents=True)
    policy.write_text(json.dumps({"allow": ["tail"], "digest_key": "k", "log_sources": {"x": {}}}))
    policy.chmod(0o640)
    sources = {"api": {"kind": "file", "dir": "/opt/a/logs/", "glob": "*"}}
    code, res = _hostlogs(
        "apply", {"log_sources": sources, "log_path_prefixes": ["/opt/b/logs/"]}, tmp_path
    )
    assert code == 0 and res["ok"] and res["acl"] == "not-applicable"
    written = json.loads(policy.read_text())
    assert written == {
        "allow": ["tail"],
        "digest_key": "k",
        "log_sources": sources,
        "log_path_prefixes": ["/opt/b/logs/"],
    }
    assert policy.stat().st_mode & 0o777 == 0o640


def test_parents_stop_below_the_root() -> None:
    assert _parents("/opt/shop/api/logs/") == ["/opt/shop/api/", "/opt/shop/", "/opt/"]


# --------------------------------------------------------------------------------------
# The shim: @logs
# --------------------------------------------------------------------------------------


@pytest.fixture
def source_dir(tmp_path: Path) -> Path:
    logs = tmp_path / "shop" / "logs"
    logs.mkdir(parents=True)
    old = logs / "app-2026-10-20.log"
    old.write_text("".join(f"old {i} ok\n" for i in range(50)))
    os.utime(old, (time.time() - 3 * 86400, time.time() - 3 * 86400))
    new = logs / "app-2026-10-22.log"
    new.write_text(
        "".join(f"new {i} {'ERROR timeout' if i % 10 == 0 else 'ok'}\n" for i in range(100))
    )
    (logs / ".env").write_text("TOKEN=hunter2\n")
    (tmp_path / "shop" / "secret.txt").write_text("hunter2\n")
    os.symlink(tmp_path / "shop" / "secret.txt", logs / "zz-link.log")
    return logs


def _policy(tmp_path: Path, source_dir: Path, glob: str = "*.log*", **extra: object) -> Path:
    conf = tmp_path / "config.json"
    conf.write_text(
        json.dumps(
            {
                "log_sources": {"app": {"kind": "file", "dir": str(source_dir), "glob": glob}},
                **extra,
            }
        )
    )
    return conf


def _logs(shim: Path, conf: Path, **request: object) -> tuple[int, str, str]:
    return run_shim(shim, conf, "@logs " + json.dumps(request))


def test_logs_reads_the_newest_lines_of_a_file_source(
    shim_path: Path, tmp_path: Path, source_dir: Path
) -> None:
    code, out, err = _logs(shim_path, _policy(tmp_path, source_dir), source="app", lines=3)
    assert code == 0
    assert out.splitlines() == ["new 97 ok", "new 98 ok", "new 99 ok"]
    assert "log source 'app'" in err


def test_logs_greps_across_files_in_time_order(
    shim_path: Path, tmp_path: Path, source_dir: Path
) -> None:
    code, out, _ = _logs(
        shim_path, _policy(tmp_path, source_dir), source="app", grep="old 4[89]|ERROR", lines=50
    )
    assert code == 0
    lines = out.splitlines()
    assert lines[:2] == ["old 48 ok", "old 49 ok"]
    assert lines[-1] == "new 90 ERROR timeout"
    assert len(lines) == 12


def test_logs_since_selects_files_by_date(
    shim_path: Path, tmp_path: Path, source_dir: Path
) -> None:
    code, out, _ = _logs(
        shim_path, _policy(tmp_path, source_dir), source="app", grep="ok", since="1d", lines=2000
    )
    assert code == 0
    assert "old" not in out and "new 1 ok" in out


def test_logs_strips_terminal_colours(shim_path: Path, tmp_path: Path, source_dir: Path) -> None:
    (source_dir / "app-2026-10-23.log").write_text(
        "2026-10-23 \x1b[33m\x1b[3mwarn\x1b[23m\x1b[39m: [BOOKMARKS] Forbidden\n"
    )
    # grep runs over the raw file, so the pattern avoids the coloured word itself.
    code, out, _ = _logs(shim_path, _policy(tmp_path, source_dir), source="app", grep="BOOKMARKS")
    assert code == 0
    assert out == "2026-10-23 warn: [BOOKMARKS] Forbidden"


def test_logs_skips_hidden_bookkeeping_files(
    shim_path: Path, tmp_path: Path, source_dir: Path
) -> None:
    (source_dir / ".abc-audit.json").write_text('{"hash": "deadbeef"}\n')
    code, out, err = _logs(
        shim_path, _policy(tmp_path, source_dir, glob="*"), source="app", grep="deadbeef"
    )
    assert "deadbeef" not in out
    assert ".abc-audit.json" not in err


def test_refusal_lists_each_permitted_prefix_once(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected) as exc:
        validate("tail -n 5 /opt/x.log", spec, ctx={**ctx, "log_path_prefixes": ["/var/log/"]})
    assert (exc.value.suggestion or "").count("/var/log/") == 1


def test_logs_never_reads_a_secret_or_a_symlink_out(
    shim_path: Path, tmp_path: Path, source_dir: Path
) -> None:
    code, out, err = _logs(
        shim_path, _policy(tmp_path, source_dir, glob="*"), source="app", grep="hunter2"
    )
    assert "hunter2" not in out
    assert ".env" not in err and "zz-link" not in err


def test_logs_reads_rotated_gz_files(shim_path: Path, tmp_path: Path, source_dir: Path) -> None:
    with gzip.open(source_dir / "app-2026-10-19.log.gz", "wt") as fh:
        fh.write("rotated ERROR disk full\n")
    code, out, _ = _logs(shim_path, _policy(tmp_path, source_dir), source="app", grep="ERROR disk")
    assert code == 0, out
    assert out.splitlines() == ["rotated ERROR disk full"]


@pytest.mark.parametrize(
    ("request_", "message"),
    [
        ({"source": "nope"}, "not a log source"),
        ({"source": "app", "lines": 0}, "lines must be"),
        ({"source": "app", "lines": 5000}, "lines must be"),
        ({"source": "app", "since": "yesterday; id"}, "since"),
        ({"source": "app", "grep": "("}, "not a valid regular expression"),
    ],
)
def test_logs_refuses_bad_requests(
    shim_path: Path, tmp_path: Path, source_dir: Path, request_: dict, message: str
) -> None:
    code, _, err = _logs(shim_path, _policy(tmp_path, source_dir), **request_)
    assert code == 92
    assert message in err


def test_logs_drops_an_unsafe_source_from_its_own_policy(shim_path: Path, tmp_path: Path) -> None:
    conf = tmp_path / "config.json"
    conf.write_text(
        json.dumps({"log_sources": {"root": {"kind": "file", "dir": "/", "glob": "*"}}})
    )
    code, _, err = _logs(shim_path, conf, source="root")
    assert code == 92 and "not a log source" in err
    assert '"policy-ignored"' in (tmp_path / "audit.jsonl").read_text()


@pytest.mark.parametrize(
    "argv",
    [
        [
            "journalctl",
            "-u",
            "pm2-app.service",
            "-n",
            "200",
            "--no-pager",
            "--since=-2h",
            "--grep=a|b",
        ],
        [
            "journalctl",
            "-u",
            "x.service",
            "-n",
            "5",
            "--no-pager",
            "--since=2026-10-22 14:05",
            "--until=-30min",
        ],
        [
            "docker",
            "logs",
            "--tail",
            "2000",
            "--since",
            "48h",
            "--until",
            "2026-10-22T14:05",
            "api",
        ],
    ],
)
def test_argv_shapes_built_by_logs_pass_the_spec(argv: list[str], spec: dict, ctx: dict) -> None:
    validate_argv(argv, spec, ctx=ctx)


def test_describe_source() -> None:
    assert (
        _describe_source({"kind": "file", "dir": "/opt/a/logs/", "glob": "*.log*"})
        == "files /opt/a/logs/*.log*"
    )
    assert _describe_source({"kind": "docker", "container": "api"}) == "container api"


# --------------------------------------------------------------------------------------
# CLI: enrol-time choice and `safereach logs`
# --------------------------------------------------------------------------------------


def _args(**kw: object) -> argparse.Namespace:
    base = {"no_discover": False, "accept_detected": False, "no_prompt": True}
    return argparse.Namespace(**{**base, **kw})


def test_enrol_takes_preselected_sources_when_not_interactive(
    monkeypatch: pytest.MonkeyPatch, facts: dict
) -> None:
    monkeypatch.setattr(logsources, "run_hostlogs", lambda *a, **k: (0, facts, ""))
    chosen = cli._choose_log_sources("web-1", ["ssh", "web-1"], {}, _args(), sudo=False)
    assert {"syslog", "shop-api", "pm2-app", "nginx", "api"} <= set(chosen)
    assert "auth" not in chosen


def test_enrol_accept_detected_takes_everything(
    monkeypatch: pytest.MonkeyPatch, facts: dict
) -> None:
    monkeypatch.setattr(logsources, "run_hostlogs", lambda *a, **k: (0, facts, ""))
    chosen = cli._choose_log_sources("web-1", ["ssh"], {}, _args(accept_detected=True), sudo=False)
    assert {"api", "worker", "auth"} <= set(chosen)


def test_enrol_keeps_configured_sources_when_the_scan_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        logsources, "run_hostlogs", lambda *a, **k: (127, None, "python3: not found")
    )
    existing = {"api": {"kind": "docker", "container": "api"}}
    assert cli._choose_log_sources("h", ["ssh"], existing, _args(), sudo=False) == existing


def test_enrol_no_discover_never_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("scan ran")

    monkeypatch.setattr(logsources, "run_hostlogs", boom)
    assert cli._choose_log_sources("h", ["ssh"], {}, _args(no_discover=True), sudo=False) == {}


def _logs_cli(tmp_path: Path, *words: str) -> int:
    path = tmp_path / "hosts.yaml"
    if not path.exists():
        path.write_text(HOSTS_YAML)
    parser = cli.build_parser()
    args = parser.parse_args(["--config", str(path), "logs", *words])
    return args.func(args)


def test_logs_add_and_remove_update_host_and_hosts_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pushed: list[dict] = []

    def fake(ssh_argv: list[str], mode: str, params: dict, *, sudo: bool, timeout: int = 60):
        pushed.append(params)
        return 0, {"ok": True, "acl": "not-applicable", "granted": [], "revoked": []}, ""

    monkeypatch.setattr(logsources, "run_hostlogs", fake)
    assert _logs_cli(tmp_path, "add", "web-1", "api=/opt/shop/api/logs/:*.log*") == 0
    assert pushed[-1]["log_sources"]["api"]["dir"] == "/opt/shop/api/logs/"
    assert "old" in pushed[-1]["log_sources"]
    host = load_settings(tmp_path / "hosts.yaml").host("web-1")
    assert set(host.log_sources) == {"old", "api"}

    assert _logs_cli(tmp_path, "remove", "web-1", "old") == 0
    assert set(load_settings(tmp_path / "hosts.yaml").host("web-1").log_sources) == {"api"}
    assert "# my fleet" in (tmp_path / "hosts.yaml").read_text()


def test_logs_refuses_an_unsafe_add_before_connecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(logsources, "run_hostlogs", lambda *a, **k: pytest.fail("connected"))
    assert _logs_cli(tmp_path, "add", "web-1", "root=/") == 2


def test_logs_hosts_yaml_untouched_when_the_host_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        logsources, "run_hostlogs", lambda *a, **k: (1, {"ok": False, "error": "no"}, "")
    )
    assert _logs_cli(tmp_path, "add", "web-1", "api=/opt/a/logs/") == 1
    assert (tmp_path / "hosts.yaml").read_text() == HOSTS_YAML


def test_logs_list_needs_no_network(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _logs_cli(tmp_path, "web-1") == 0
    assert "old" in capsys.readouterr().err
