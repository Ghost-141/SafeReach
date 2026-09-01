"""Canary: plant a known secret, run everything, assert it never appears.

Per-pattern tests prove the patterns work. They cannot prove a secret never escapes,
because they only ever check the shapes someone thought to write down.

This plants a unique high-entropy token in every place a secret realistically lives,
drives the **whole redaction pipeline** exactly as the shim does, and asserts the token
appears nowhere in the output.

The control matters as much as the assertion: each test also checks the canary *is*
present with redaction disabled. Without that, a test that finds nothing proves only that
the input was empty.
"""

from __future__ import annotations

import json

import pytest

from safereach.redact import (
    MASK,
    digest_value,
    mask_by_digest,
    mask_env_keys,
    redact_docker_inspect,
    redact_text,
)

#: High-entropy so it clears the Layer 3 gate, and unmistakable in a diff.
CANARY = "Kx7Qm2Vp9Lz4Rw8Bn3Ty6Hd5Fj1Gc0S"
CANARY_KEY = "SAFEREACH_CANARY_TOKEN"
DIGEST_KEY = "canary-host-key-0123456789abcdef"


def pipeline(text: str, *, keys: list[str], digests: list[str], env_bearing: bool) -> str:
    """The exact redaction order the shim applies in `run_argv`."""
    out = text
    if env_bearing:
        out = redact_docker_inspect(out, [])
    out = mask_env_keys(out, keys)
    out = mask_by_digest(out, digests, DIGEST_KEY)
    return redact_text(out)


@pytest.fixture
def digests() -> list[str]:
    return [digest_value(CANARY, DIGEST_KEY.encode())]


@pytest.fixture
def keys() -> list[str]:
    return [CANARY_KEY, "DATABASE_URL", "NEXTAUTH_SECRET"]


# --------------------------------------------------------------------------------------
# Every realistic carrier
# --------------------------------------------------------------------------------------

CARRIERS = {
    "docker-inspect-env": json.dumps(
        [{"Config": {"Env": [f"{CANARY_KEY}={CANARY}", "TZ=UTC"], "Image": "app:1"}}]
    ),
    "systemctl-show": f"MainPID=421\nEnvironment={CANARY_KEY}={CANARY}\nActiveState=active",
    "shell-env-dump": f"{CANARY_KEY}={CANARY}\nPATH=/usr/bin",
    "yaml-compose": f"services:\n  app:\n    environment:\n      {CANARY_KEY}: {CANARY}",
    "json-config": json.dumps({CANARY_KEY: CANARY, "port": 8080}),
    "connection-string": f"postgres://app:{CANARY}@db.internal:5432/prod",
    "url-query": f"https://api.internal/v1/sync?token={CANARY}&page=2",
    "bare-in-log": f"2026-09-02 18:04:11 ERROR auth failed using {CANARY} from 10.0.0.4",
    "stack-trace": (
        "Traceback (most recent call last):\n"
        '  File "/app/db.py", line 42, in connect\n'
        f"    raise ConnectionError('bad credential {CANARY}')\n"
    ),
    "process-args": f"1234 ?  Ssl  0:03 /usr/bin/node server.js --api-key={CANARY}",
    "quoted-in-json-array": json.dumps({"args": ["--token", CANARY]}),
    "kubectl-describe": f"  Environment:\n    {CANARY_KEY}:  {CANARY}\n  Mounts:  /data",
}


@pytest.mark.parametrize("carrier", sorted(CARRIERS), ids=sorted(CARRIERS))
def test_canary_never_escapes(carrier: str, keys: list[str], digests: list[str]) -> None:
    raw = CARRIERS[carrier]

    # Control: the canary really is in the input. Without this the test is vacuous.
    assert CANARY in raw, "the fixture itself lost the canary"

    scrubbed = pipeline(
        raw,
        keys=keys,
        digests=digests,
        env_bearing=carrier in {"docker-inspect-env"},
    )
    assert CANARY not in scrubbed, f"canary escaped via {carrier}:\n{scrubbed[:400]}"
    assert MASK in scrubbed, "something should have been masked"


@pytest.mark.parametrize("carrier", sorted(CARRIERS), ids=sorted(CARRIERS))
def test_control_canary_is_visible_without_redaction(carrier: str) -> None:
    """The negative control. Proves each carrier actually carries the canary."""
    assert CANARY in CARRIERS[carrier]


def test_canary_caught_with_no_key_names_at_all(digests: list[str]) -> None:
    """Layer 3 alone must catch it — the case Layer 2 structurally cannot see.

    No variable name appears anywhere here, so name-based masking has nothing to match.
    """
    raw = f"connection refused while presenting {CANARY} to upstream"
    out = mask_by_digest(raw, digests, DIGEST_KEY)
    assert CANARY not in out
    assert MASK in out


def test_canary_caught_with_no_digests_at_all(keys: list[str]) -> None:
    """Layer 2 alone must catch the named form — the case Layer 3's gate might skip."""
    raw = f"{CANARY_KEY}={CANARY}"
    out = mask_env_keys(raw, keys)
    assert CANARY not in out


def test_diagnostics_survive_the_pipeline(keys: list[str], digests: list[str]) -> None:
    """A redactor that eats the useful output gets turned off. Check it does not."""
    raw = (
        "CONTAINER   STATUS        PORTS\n"
        "app-1       Up 3 hours    0.0.0.0:8080->80/tcp\n"
        "NODE_ENV=production\n"
        "MemoryCurrent=524288000\n"
        "/dev/sda2  490G  24G  441G  6% /\n"
        "Sep 02 18:04:11 host app[421]: GET /healthz 200 4ms\n"
    )
    out = pipeline(raw, keys=keys, digests=digests, env_bearing=False)
    for fragment in (
        "app-1",
        "Up 3 hours",
        "0.0.0.0:8080->80/tcp",
        "NODE_ENV=production",
        "MemoryCurrent=524288000",
        "490G",
        "6% /",
        "GET /healthz 200 4ms",
    ):
        assert fragment in out, f"redaction destroyed a useful field: {fragment!r}"


def test_low_entropy_values_are_not_digest_masked() -> None:
    """The entropy gate protects readability, and is worth asserting explicitly."""
    weak = "production"
    out = mask_by_digest(f"NODE_ENV={weak}", [digest_value(weak, DIGEST_KEY.encode())], DIGEST_KEY)
    assert weak in out, "masking 'production' everywhere would make output unreadable"
