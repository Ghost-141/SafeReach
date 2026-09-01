"""Keeping .env values away from the agent.

Two independent mechanisms, because either alone has a gap:

* `deny_paths` stops the file being *named* in any command — a hard stop that survives
  someone loosening the command allowlist later.
* `mask_env_keys` stops the values leaking *indirectly*, through `docker inspect`,
  `systemctl show`, `ps`, or an application that logs its own config at startup. The
  path denylist cannot help there, because no .env path is ever mentioned.
"""

from __future__ import annotations

import json

import pytest

from safereach.redact import MASK, mask_env_keys
from safereach.validator import Rejected, validate

DENY = [
    "*.env",
    "*.env.*",
    ".env*",
    "*.envrc",
    "*/secrets/*",
    "*/.ssh/*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_ed25519*",
    "*credentials*",
    "*/.aws/*",
]


@pytest.fixture
def dctx(ctx: dict) -> dict:
    return {**ctx, "deny_paths": DENY}


@pytest.mark.parametrize(
    "command",
    [
        "ls -la /opt/app/.env",
        "stat /opt/app/.env",
        "du -sh /opt/app/.env.production",
        "grep KEY /opt/app/.env",
        "tail -n 5 /opt/app/.env",
        "head /srv/site/.envrc",
        "ls /home/deploy/.ssh/id_rsa",
        "stat /etc/ssl/private/server.key",
        "ls /opt/app/secrets/db",
        "stat /home/deploy/.aws/credentials",
    ],
    ids=lambda c: c[:40],
)
def test_protected_paths_are_never_nameable(command: str, spec: dict, dctx: dict) -> None:
    with pytest.raises(Rejected, match="protected-path list"):
        validate(command, spec, ctx=dctx)


def test_ordinary_paths_still_work(spec: dict, dctx: dict) -> None:
    """A denylist that blocks real diagnostics would just get switched off."""
    validate("ls /opt/app", spec, ctx=dctx)
    validate("tail -n 100 /var/log/syslog", spec, ctx=dctx)
    validate("du -sh /var/log", spec, ctx=dctx)


def test_denial_applies_to_flag_values_too(spec: dict, dctx: dict) -> None:
    """A path can arrive as a flag value, not only as a positional."""
    with pytest.raises(Rejected, match="protected-path list"):
        validate("grep -f /opt/app/.env pattern", spec, ctx=dctx)


def test_basename_matching(spec: dict, dctx: dict) -> None:
    """`*.env` must catch a full path, not just a bare filename."""
    with pytest.raises(Rejected, match="protected-path list"):
        validate("ls /very/deep/nested/path/app/.env", spec, ctx=dctx)


# --------------------------------------------------------------------------------------
# Masking by name — the indirect leak
# --------------------------------------------------------------------------------------

KEYS = ["NEXTAUTH_SECRET", "SALT", "ENCRYPTION_KEY", "SMTP_USER", "CLICKHOUSE_PASSWORD"]


@pytest.mark.parametrize(
    ("sample", "secret"),
    [
        ("NEXTAUTH_SECRET=sup3rs3cret", "sup3rs3cret"),
        ('"Env": ["SALT=abc123", "TZ=UTC"]', "abc123"),
        ('{"ENCRYPTION_KEY": "deadbeef"}', "deadbeef"),
        ("SMTP_USER: mailer@corp.com", "mailer@corp.com"),
        ("Environment=SALT=xyz CLICKHOUSE_PASSWORD=pw", "xyz"),
        ("  ENCRYPTION_KEY = beef", "beef"),
    ],
    ids=["shell", "docker-env", "json", "yaml", "systemd", "ini"],
)
def test_values_masked_in_every_shape(sample: str, secret: str) -> None:
    """Env values surface in all of these, so all of them have to be covered."""
    out = mask_env_keys(sample, KEYS)
    assert secret not in out
    assert MASK in out


def test_names_survive_so_output_stays_useful() -> None:
    out = mask_env_keys("NEXTAUTH_SECRET=hunter2", KEYS)
    assert "NEXTAUTH_SECRET" in out, "the agent must still see which variables are set"


def test_unlisted_variables_untouched() -> None:
    text = "TZ=UTC PATH=/usr/bin NODE_ENV=production"
    assert mask_env_keys(text, KEYS) == text


def test_json_stays_parseable_after_masking() -> None:
    """`docker inspect` output is consumed as JSON; masking must not break it."""
    payload = json.dumps({"Config": {"Env": ["SALT=x"]}, "ENCRYPTION_KEY": "y"})
    assert json.loads(mask_env_keys(payload, KEYS))["ENCRYPTION_KEY"] == MASK


def test_no_keys_is_a_noop() -> None:
    assert mask_env_keys("SALT=x", []) == "SALT=x"
    assert mask_env_keys("SALT=x", None) == "SALT=x"


def test_malformed_key_names_are_ignored_not_crashed() -> None:
    """Key names come from parsing files on a remote host; junk must not raise."""
    assert mask_env_keys("SALT=x", ["", "*", "a" * 500, "SALT"]) == f"SALT={MASK}"
