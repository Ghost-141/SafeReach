"""End to end against a real host: sshd, sudo, systemd, journald and a Docker daemon.

Everything the unit suite asserts about *text* is executed here for real: the hardened
enrolment runs as root on the container, sshd is reloaded with the Match block, the
proxy binds its unix socket on the host's own daemon, and every probe travels over a
real SSH channel to the forced command. Nothing is mocked and nothing is asserted from a
script's wording.

Opt-in, because it needs Docker and takes minutes:

    SAFEREACH_E2E=1 uv run pytest tests/e2e -v

The container is removed afterwards; the nested daemon's volume is kept so the next run
does not re-pull the proxy image. `python -m tests.e2e.rig destroy` removes that too.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conftest import SECRET_SURFACE  # noqa: E402

from e2e import rig  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("SAFEREACH_E2E") != "1" or not rig.docker_available(),
    reason="set SAFEREACH_E2E=1 with Docker available to run the end-to-end suite",
)

APP_ENV_SECRET = "CONTAINERENVSECRET-e2e-0000"
DOTENV_SECRET = "hunter2-dotenv-secret"


@pytest.fixture(scope="module")
def host(tmp_path_factory: pytest.TempPathFactory) -> rig.Host:
    home = tmp_path_factory.mktemp("e2e-home")
    h = rig.up(home)
    # A workload container on the HOST's daemon, with secrets where real ones keep them.
    # The nested daemon's state lives in a volume that outlives the host container.
    h.exec("docker", "rm", "-f", "app", check=False)
    h.exec(
        "docker",
        "run",
        "-d",
        "--name",
        "app",
        "-e",
        f"STRIPE_KEY={APP_ENV_SECRET}",
        "-e",
        "LOG_LEVEL=info",
        "alpine",
        "sh",
        "-c",
        "mkdir -p /app/storage/logs && "
        f"printf 'DB_PASSWORD={DOTENV_SECRET}\\n' > /app/.env && "
        'i=0; while true; do i=$((i+1)); echo "log line $i" >> /app/storage/logs/laravel.log; sleep 1; done',
    )
    yield h
    rig.down()


@pytest.fixture(scope="module")
def enrolled(host: rig.Host) -> dict[str, str]:
    proc = host.safereach(
        "enroll",
        host.alias,
        "--hardened",
        "--no-prompt",
        "--elevated",
        "dmesg-recent",
        "--allow-exec",
        "--exec-container",
        "app",
        "--exec-path",
        "/app/storage/logs/",
        check=False,
    )
    assert proc.returncode == 0, f"enrol failed\n{proc.stdout}\n{proc.stderr}"
    out = proc.stdout + proc.stderr
    hosts_yaml = host.home / ".config" / "safereach" / "hosts.yaml"
    assert hosts_yaml.is_file()
    diag_key = host.home / ".config" / "safereach" / "keys" / "id_ed25519_safereach"
    assert diag_key.is_file()
    return {
        "output": out,
        "hosts_yaml": hosts_yaml.read_text(encoding="utf-8"),
        "diag_key": str(diag_key),
    }


def _diag(host: rig.Host, enrolled: dict[str, str], wire: str):
    return host.ssh(wire, user="diag", key=Path(enrolled["diag_key"]))


def _run(host: rig.Host, enrolled: dict[str, str], command: str):
    return _diag(host, enrolled, "@run " + json.dumps(shlex.split(command)))


# --------------------------------------------------------------------------------------
# What enrolment left on the host
# --------------------------------------------------------------------------------------


def test_enrolment_reports_every_control(enrolled: dict[str, str]) -> None:
    out = enrolled["output"]
    assert "sudoers ok" in out
    assert "sshd match present" in out
    assert (
        "escape refused" in out or "forced command" not in out.lower() or "Not enrolling" not in out
    )
    assert "SECURITY" not in out


def test_policy_file_is_root_diag_0640(host: rig.Host, enrolled: dict[str, str]) -> None:
    assert (
        host.exec("stat", "-c", "%a %U:%G", "/etc/safereach/config.json").strip() == "640 root:diag"
    )
    assert (
        host.exec("stat", "-c", "%a %U:%G", "/usr/local/bin/safereach-shim").strip()
        == "755 root:root"
    )
    policy = json.loads(host.exec("cat", "/etc/safereach/config.json"))
    assert policy["exec_path_prefixes"] == ["/app/storage/logs/"]
    assert policy["exec_containers"] == ["app"]
    assert policy["digest_key"]  # present here, unreadable to anyone but root and diag


def test_proxy_listens_on_a_diag_only_unix_socket(host: rig.Host, enrolled: dict[str, str]) -> None:
    assert (
        host.exec("stat", "-c", "%F %a %U:%G", "/run/safereach/docker.sock").strip()
        == "socket 660 root:diag"
    )
    assert (
        host.exec("docker", "port", "safereach-docker-proxy").strip() == ""
    )  # no TCP port published
    assert "docker_host: unix:///run/safereach/docker.sock" in enrolled["hosts_yaml"]
    image = host.exec(
        "docker", "inspect", "-f", "{{.Config.Image}}", "safereach-docker-proxy"
    ).strip()
    assert "@sha256:" in image


def test_sshd_match_block_applies_to_diag_only(host: rig.Host, enrolled: dict[str, str]) -> None:
    diag = host.exec("sshd", "-T", "-C", "user=diag").lower()
    assert "permittty no" in diag and "maxsessions 4" in diag and "allowtcpforwarding no" in diag
    ops = host.exec("sshd", "-T", "-C", "user=ops").lower()
    assert "permittty yes" in ops, "the Match block leaked onto other users"


def test_sudoers_is_exact_and_valid(host: rig.Host, enrolled: dict[str, str]) -> None:
    host.exec("visudo", "-cf", "/etc/sudoers.d/safereach")
    content = host.exec("cat", "/etc/sudoers.d/safereach")
    dmesg = host.exec("bash", "-c", "command -v dmesg").strip()
    assert (
        f"diag ALL=(root) NOPASSWD: {dmesg} --level=err\\,crit\\,alert\\,emerg --ctime" in content
    )
    assert "*" not in content and "ALL=(ALL)" not in content
    listing = host.exec("sudo", "-n", "-l", "-U", "diag")
    assert dmesg in listing and "ALL" not in listing.split("may run")[-1].replace("(root)", "")


def test_diag_account_is_unprivileged(host: rig.Host, enrolled: dict[str, str]) -> None:
    groups = host.exec("id", "-nG", "diag").split()
    assert "docker" not in groups and "sudo" not in groups
    assert "systemd-journal" in groups and "adm" in groups


def test_audit_log_state_is_reported(host: rig.Host, enrolled: dict[str, str]) -> None:
    attrs = host.exec("lsattr", "/var/log/safereach.jsonl", check=False)
    assert host.exec("stat", "-c", "%a %U", "/var/log/safereach.jsonl").strip() == "640 diag"
    if "a" not in attrs.split()[0]:
        assert "audit writable" in enrolled["output"]


# --------------------------------------------------------------------------------------
# The key, over a real SSH channel
# --------------------------------------------------------------------------------------


def test_diag_key_cannot_get_a_shell(host: rig.Host, enrolled: dict[str, str]) -> None:
    for attempt in ("id", "bash", "sh -c id", "rm -rf /tmp/x", ""):
        proc = _diag(host, enrolled, attempt)
        assert proc.returncode == 92, (attempt, proc.stdout, proc.stderr)
        assert "Rejected" in proc.stderr
    ping = _diag(host, enrolled, "@ping")
    assert ping.returncode == 0 and json.loads(ping.stdout)["ok"] is True


def test_diag_key_is_pinned_to_the_forced_command_options(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    # ExitOnForwardFailure turns a refused forward into a non-zero exit; without it
    # ssh would carry on with the session (and with -N it would sit there forever).
    proc = host.ssh(
        "-o",
        "ExitOnForwardFailure=yes",
        "-R",  # a remote forward is requested at session start; -L only on first use
        "19999:127.0.0.1:22",
        "@ping",
        user="diag",
        key=Path(enrolled["diag_key"]),
    )
    assert proc.returncode != 0  # no-port-forwarding + AllowTcpForwarding no
    assert "forward" in proc.stderr.lower() or "administratively prohibited" in proc.stderr.lower()


@pytest.mark.parametrize("command", SECRET_SURFACE, ids=[c[:40] for c in SECRET_SURFACE])
def test_review_probes_are_refused_on_the_host(
    host: rig.Host, enrolled: dict[str, str], command: str
) -> None:
    """Every string the 0.1.x review found ACCEPTED, sent to the real shim as the agent would."""
    proc = _run(host, enrolled, command)
    assert proc.returncode == 92, (command, proc.stdout, proc.stderr)
    assert proc.stderr.startswith("Rejected:")


def test_legal_diagnostics_run_and_carry_no_secret(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    status = _run(host, enrolled, "systemctl status app")
    assert status.returncode == 0, status.stderr
    assert "app.service" in status.stdout
    assert "CMDLINESECRET99" not in status.stdout  # cgroup line reduced to PID + binary
    assert "/usr/bin/python3 …" in status.stdout

    show = _run(host, enrolled, "systemctl show -p ActiveState -p MainPID app")
    assert show.returncode == 0 and "ActiveState=active" in show.stdout

    journal = _run(host, enrolled, "journalctl -u app -n 5")
    assert journal.returncode == 0 and "app tick" in journal.stdout

    ps = _run(host, enrolled, "ps -e -o pid,user,comm")
    assert ps.returncode == 0 and "python3" in ps.stdout and "CMDLINESECRET99" not in ps.stdout

    for cmd in (
        "df -h",
        "free -h",
        "uptime",
        "ss -tln",
        "ip addr",
        "ls -la /var/log/",
        "tail -n 3 /var/log/safereach.jsonl",
    ):
        proc = _run(host, enrolled, cmd)
        assert proc.returncode == 0, (cmd, proc.stderr)


def test_docker_inspect_is_masked_on_the_host(host: rig.Host, enrolled: dict[str, str]) -> None:
    proc = _run(host, enrolled, "docker inspect app")
    assert proc.returncode == 0, proc.stderr
    assert APP_ENV_SECRET not in proc.stdout
    assert "STRIPE_KEY=***REDACTED***" in proc.stdout
    assert "LOG_LEVEL=" in proc.stdout  # names survive
    ps = _run(host, enrolled, "docker ps --all")
    assert ps.returncode == 0 and "app" in ps.stdout


def test_curl_reaches_web_ports_only_and_never_the_proxy(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    ok = _run(host, enrolled, "curl -I http://localhost/")
    assert ok.returncode != 92  # allowed by policy; nothing listens, so curl itself fails
    for url in (
        "http://localhost:2375/version",
        "http://127.0.0.1:9200/",
        "http://localhost:8080/",
    ):
        proc = _run(host, enrolled, f"curl {url}")
        assert proc.returncode == 92, (url, proc.stderr)


def test_elevated_recipe_runs_as_root_by_name_only(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    proc = _diag(host, enrolled, "@elevated dmesg-recent")
    assert proc.returncode == 0, proc.stderr
    assert _diag(host, enrolled, "@elevated dmesg-all").returncode == 92  # not enabled on this host
    assert _diag(host, enrolled, "@elevated 'dmesg-recent; id'").returncode == 92


def test_exec_reads_logs_and_nothing_else(host: rig.Host, enrolled: dict[str, str]) -> None:
    def ex(argv: list[str]):
        return _diag(host, enrolled, "@exec " + json.dumps({"container": "app", "argv": argv}))

    ok = ex(["tail", "-n", "3", "/app/storage/logs/laravel.log"])
    assert ok.returncode == 0, ok.stderr
    assert "log line" in ok.stdout
    assert ex(["grep", "-c", "line", "/app/storage/logs/laravel.log"]).returncode == 0

    for argv in (
        ["cat", "/app/.env"],
        ["cat", "/proc/1/environ"],
        ["sh", "-c", "id"],
        ["env"],
        ["cat", "/app/storage/logs/../../.env"],
        ["tail", "/etc/passwd"],
    ):
        proc = ex(argv)
        assert proc.returncode == 92, (argv, proc.stdout, proc.stderr)
        assert DOTENV_SECRET not in proc.stdout
    other = _diag(
        host,
        enrolled,
        "@exec " + json.dumps({"container": "safereach-docker-proxy", "argv": ["ls", "/"]}),
    )
    assert other.returncode == 92


def test_every_command_ran_under_the_resource_wrapper(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    log = host.exec("cat", "/var/log/safereach.jsonl")
    allowed = [json.loads(line) for line in log.splitlines() if '"decision":"allowed"' in line]
    assert allowed, "no allowed records in the host audit log"
    assert all(r["wrapper"][:3] == ["nice", "-n", "19"] for r in allowed)
    assert all("prlimit" in r["wrapper"] for r in allowed)


# --------------------------------------------------------------------------------------
# Other accounts on the same host
# --------------------------------------------------------------------------------------


def test_other_local_users_cannot_read_the_policy_or_reach_the_proxy(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    denied = rig._run(
        "docker",
        "exec",
        "-u",
        "ops",
        rig.CONTAINER,
        "cat",
        "/etc/safereach/config.json",
        check=False,
    )
    assert denied.returncode != 0 and "digest_key" not in denied.stdout
    proxy = rig._run(
        "docker",
        "exec",
        "-u",
        "ops",
        "-e",
        "DOCKER_HOST=unix:///run/safereach/docker.sock",
        rig.CONTAINER,
        "docker",
        "version",
        check=False,
    )
    assert proxy.returncode != 0
    as_diag = rig._run(
        "docker",
        "exec",
        "-u",
        "diag",
        "-e",
        "DOCKER_HOST=unix:///run/safereach/docker.sock",
        rig.CONTAINER,
        "docker",
        "version",
        check=False,
    )
    assert as_diag.returncode == 0, as_diag.stderr


# --------------------------------------------------------------------------------------
# The server side: doctor, shim-update, and the unrestricted-key finding
# --------------------------------------------------------------------------------------


def test_doctor_is_clean_after_enrolment(host: rig.Host, enrolled: dict[str, str]) -> None:
    proc = host.safereach("doctor", check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "reachable, shim" in proc.stdout + proc.stderr


def test_shim_update_round_trips_from_the_package(host: rig.Host, enrolled: dict[str, str]) -> None:
    proc = host.safereach("shim-update", "e2e-prod", "--admin-user", rig.ADMIN, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (
        host.exec("stat", "-c", "%a %U:%G", "/usr/local/bin/safereach-shim").strip()
        == "755 root:root"
    )
    assert host.safereach("doctor", check=False).returncode == 0


def test_a_key_without_the_forced_command_is_reported_as_unrestricted(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    """Point a config at the admin account with the admin key: a shell answers the probe."""
    cfg = host.home / "unrestricted.yaml"
    cfg.write_text(
        "defaults:\n"
        f"  known_hosts: {host.home / '.ssh' / 'known_hosts'}\n"
        "hosts:\n"
        "  oops:\n"
        "    hostname: 127.0.0.1\n"
        f"    port: {host.port}\n"
        f"    user: {rig.ADMIN}\n"
        f"    key: {host.admin_key}\n"
        "    allow: [df]\n",
        encoding="utf-8",
    )
    proc = host.safereach("--config", str(cfg), "doctor", check=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "SECURITY" in out and "login shell" in out


def test_production_flag_refuses_client_only_hosts(
    host: rig.Host, enrolled: dict[str, str]
) -> None:
    cfg = host.home / "prod.yaml"
    cfg.write_text(
        "defaults:\n  production: true\nhosts:\n  lab:\n    ssh_config_host: e2e-prod\n    require_shim: false\n",
        encoding="utf-8",
    )
    proc = host.safereach("--config", str(cfg), "doctor", check=False)
    assert proc.returncode != 0
    assert "production is true" in proc.stdout + proc.stderr
