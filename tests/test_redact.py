"""Output redaction.

Defence in depth rather than a primary control — but `docker inspect` is a command the
agent will call constantly, and `Config.Env` is exactly where container secrets live, so
the structural masking is load-bearing in practice.
"""

from __future__ import annotations

import json

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
