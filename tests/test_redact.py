"""Output redaction.

Defence in depth rather than a primary control — but `docker inspect` is a command the
agent will call constantly, and `Config.Env` is exactly where container secrets live, so
the structural masking is load-bearing in practice.
"""

from __future__ import annotations

import json

import pytest

from safereach.redact import MASK, redact_docker_inspect, redact_text


def test_password_assignments_masked() -> None:
    out = redact_text("DB_PASSWORD=hunter2\npassword: swordfish")
    assert "hunter2" not in out
    assert "swordfish" not in out
    assert MASK in out


def test_connection_string_keeps_shape_drops_credential() -> None:
    out = redact_text("postgres://appuser:s3cr3t@db.internal:5432/app")
    assert "s3cr3t" not in out
    # Host and user stay visible — the point is a diagnosable string, not a blank.
    assert "db.internal" in out
    assert "appuser" in out


def test_private_key_block_removed() -> None:
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----"
    out = redact_text(text)
    assert "abc123" not in out
    assert "private key" in out


def test_known_token_shapes() -> None:
    for secret in (
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz01",
        "xoxb-1234567890-abcdefghij",
    ):
        assert secret not in redact_text(f"token is {secret} here")


def test_authorization_header_masked() -> None:
    assert "Bearer abc.def.ghi" not in redact_text("Authorization: Bearer abc.def.ghi")


def test_clean_text_untouched() -> None:
    text = "Filesystem      Size  Used Avail Use%\n/dev/sda2      1007G   50G  907G   6%"
    assert redact_text(text) == text


# --------------------------------------------------------------------------------------
# docker inspect
# --------------------------------------------------------------------------------------

INSPECT = json.dumps(
    [
        {
            "Id": "abc123",
            "State": {"Status": "running", "OOMKilled": False},
            "Config": {
                "Image": "nginx:latest",
                "Env": [
                    "PATH=/usr/local/bin",
                    "NODE_ENV=production",
                    "DATABASE_URL=postgres://u:p@db/app",
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
                ],
            },
        }
    ]
)


def test_env_values_masked_but_names_kept() -> None:
    """Names stay visible so the agent can still reason about what is configured."""
    out = redact_docker_inspect(INSPECT, env_allowlist=["NODE_ENV"])
    data = json.loads(out)
    env = data[0]["Config"]["Env"]

    assert "NODE_ENV=production" in env, "allowlisted names must come through in the clear"
    assert f"DATABASE_URL={MASK}" in env
    assert f"AWS_SECRET_ACCESS_KEY={MASK}" in env
    assert "wJalrXUtnFEMI" not in out
    assert "postgres://u:p@db/app" not in out
    # Everything else survives — this is a diagnostic command, it has to stay useful.
    assert data[0]["State"]["Status"] == "running"
    assert data[0]["Config"]["Image"] == "nginx:latest"


def test_empty_allowlist_masks_everything() -> None:
    out = redact_docker_inspect(INSPECT, env_allowlist=[])
    env = json.loads(out)[0]["Config"]["Env"]
    assert all(e.endswith(MASK) for e in env)
    assert all("=" in e for e in env), "names must survive"


def test_non_json_falls_back_to_line_masking() -> None:
    """`docker inspect --format` output is not JSON but can still carry secrets."""
    out = redact_docker_inspect("DATABASE_URL=postgres://u:p@db/app", env_allowlist=[])
    assert "postgres://u:p@db/app" not in out
    assert "DATABASE_URL" in out


def test_nested_env_arrays_are_found() -> None:
    nested = json.dumps({"a": {"b": [{"Config": {"Env": ["SECRET_TOKEN=xyz"]}}]}})
    assert "xyz" not in redact_docker_inspect(nested, env_allowlist=[])


def test_env_masking_keeps_output_diagnosable() -> None:
    """Masking values while keeping names is what makes this usable during an incident.

    A blanket scrub would hide that DATABASE_URL is even set, which is often the answer.
    """
    payload = json.dumps(
        [{"Config": {"Env": ["POSTGRES_PASSWORD=hunter2", "TZ=UTC"], "Image": "postgres:16"}}]
    )
    out = redact_docker_inspect(payload, env_allowlist=["TZ"])
    assert "hunter2" not in out
    assert "POSTGRES_PASSWORD" in out, "the variable name must stay visible"
    assert "TZ=UTC" in out, "allowlisted names come through in the clear"
    assert "postgres:16" in out, "non-env fields must be untouched"


# --------------------------------------------------------------------------------------
# Patterns added after the 0.1.x review: names by convention, argument-style secrets,
# vendor formats
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sample", "secret"),
    [
        ("STRIPE_KEY=sk_test_e2eFAKE0000000000000000", "e2eFAKE0000000000000000"),
        ("PRIVATE_KEY=abcdefgh", "abcdefgh"),
        ("ENCRYPTION_KEY=zz", "zz"),
        ("SIGNING_KEY: k1", "k1"),
        ("DB_PASS=hunter2", "hunter2"),
        ("APP_SALT=saltysalt", "saltysalt"),
        ("SENTRY_DSN=https://abc@o1.ingest.sentry.io/1", "abc@o1"),
        ("app --token=abc123 --port 8080", "abc123"),
        ("app --password hunter2", "hunter2"),
        ("app --api-key=k --verbose", "=k "),
        ("mysql -uroot -pSuperSecret123 -h db", "SuperSecret123"),
        ("mysqldump -u app -ps3cret app", "s3cret"),
        ("redis-cli -a hunter2 ping", "hunter2"),
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("header Bearer zyxwvutsrq123", "zyxwvutsrq123"),
        ("key AIzaSyD-1234567890123456789012345678901 here", "1234567890123456789012345678901"),
        ("sk-ant-api03-abcdefghijklmnop", "abcdefghijklmnop"),
        ("sk-proj-abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("glpat-abcdefghijklmnopqrstuv", "abcdefghijklmnopqrstuv"),
        ("github_pat_abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0123"),
        ("ghs_abcdefghijklmnopqrstuvwxyz01", "abcdefghijklmnopqrstuvwxyz01"),
        ("hvs.CAESIabcdefghijklmnopqrstuvwxyz", "CAESIabcdefghijklmnopqrstuvwxyz"),
        ("SG.abcdefghijklmnopqrst.uvwxyzabcdefghijklmnop", "uvwxyzabcdefghijklmnop"),
        ("dckr_pat_abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("ASIAIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"),
        ("xapp-1-A0123456789-abcdefghij", "A0123456789-abcdefghij"),
    ],
    ids=lambda v: v[:28],
)
def test_review_patterns_mask_the_value(sample: str, secret: str) -> None:
    out = redact_text(sample)
    assert secret not in out, out
    assert MASK in out


@pytest.mark.parametrize(
    "text",
    [
        "tail -n 5 /var/log/syslog",
        "app --port 8080 --workers 4",
        "container 3f2a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a",
        "commit 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e",
        "LOG_LEVEL=info NODE_ENV=production PORT=8080",
        "Sep 11 10:00:01 host sshd[1]: Accepted publickey for diag",
        "mysql -h db -u app app",
    ],
    ids=lambda t: t[:24],
)
def test_review_patterns_leave_diagnostics_alone(text: str) -> None:
    assert redact_text(text) == text


# --------------------------------------------------------------------------------------
# Structural scrubs
# --------------------------------------------------------------------------------------

STATUS = """● app.service - The App
     Loaded: loaded (/etc/systemd/system/app.service; enabled)
     Active: active (running) since Thu 2026-09-10 08:00:00 UTC; 1 day ago
   Main PID: 1234 (app)
      Tasks: 3
     CGroup: /system.slice/app.service
             ├─1234 /usr/bin/app --password hunter2 --port 8080
             ├─1235 mysql -uroot -pSuperSecret123 -h db
             └─1236 /usr/bin/worker

Sep 11 10:00:00 host app[1234]: listening on :8080
"""


def test_cgroup_lines_keep_pid_and_binary_only() -> None:
    from safereach.redact import scrub_cgroup_cmdlines

    out = scrub_cgroup_cmdlines(STATUS)
    assert "hunter2" not in out and "SuperSecret123" not in out and "--port" not in out
    assert "├─1234 /usr/bin/app …" in out
    assert "├─1235 mysql …" in out
    assert "└─1236 /usr/bin/worker" in out
    # everything that is not a process line is untouched
    assert "Active: active (running)" in out
    assert "listening on :8080" in out


DESCRIBE = """Name:         api-0
Containers:
  app:
    Image:      app:1.2
    Environment:
      DB_HOST:      db.internal
      STRIPE_KEY:   sk_live_abc
      TOKEN:        <set to the key 'tok' in secret 'creds'>  Optional: false
    Environment Variables from:
      app-config  ConfigMap  Optional: false
    Mounts:
      /var/run from x
Events:
  Type    Reason   Age  Message
  Normal  Pulled   1m   Successfully pulled image
"""


def test_describe_environment_values_masked_by_indentation() -> None:
    from safereach.redact import scrub_describe_environment

    out = scrub_describe_environment(DESCRIBE)
    assert "db.internal" not in out and "sk_live_abc" not in out
    assert "DB_HOST:      ***REDACTED***" in out
    # a reference to a Secret key names the key, not the value; it stays
    assert "<set to the key 'tok' in secret 'creds'>" in out
    # the ConfigMap reference line and everything outside the block are untouched
    assert "app-config  ConfigMap  Optional: false" in out
    assert "Successfully pulled image" in out
    assert "/var/run from x" in out


def test_inspect_argv_lists_are_masked_in_place() -> None:
    data = [{"Config": {"Cmd": ["app", "--password", "x", "--port", "8080"], "Env": []}}]
    out = json.loads(redact_docker_inspect(json.dumps(data), []))
    assert out[0]["Config"]["Cmd"] == ["app", "--password", MASK, "--port", "8080"]
