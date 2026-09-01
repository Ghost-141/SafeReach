"""The adversarial corpus.

Every command here must be refused. A regression in this file means the agent gained a
capability it should not have, so each case is asserted individually rather than in a
loop with one aggregate assertion — the failure output should name the exact bypass.
"""

from __future__ import annotations

import shlex

import pytest
from conftest import ATTACKS

from safereach.validator import Rejected, render, validate


@pytest.mark.parametrize(
    ("category", "command"),
    ATTACKS,
    ids=[f"{cat}:{cmd[:48]}" for cat, cmd in ATTACKS],
)
def test_attack_is_rejected(category: str, command: str, spec: dict, ctx: dict) -> None:
    try:
        result = validate(command, spec, ctx=ctx)
    except Rejected:
        return
    pytest.fail(
        f"{category}: {command!r} was ACCEPTED and would have run as {render(result.argv)!r}"
    )


def test_rejections_explain_themselves(spec: dict, ctx: dict) -> None:
    """A denial the agent cannot act on makes it flail instead of self-correcting."""
    with pytest.raises(Rejected) as excinfo:
        validate("journalctl -u nginx | grep error", spec, ctx=ctx)
    rendered = excinfo.value.render()
    assert "metacharacter" in rendered
    assert "--grep" in rendered, "should point at the server-side filtering alternative"


def test_denied_flag_names_the_reason(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected) as excinfo:
        validate("curl --unix-socket /var/run/docker.sock http://localhost/", spec, ctx=ctx)
    assert "Docker API" in excinfo.value.reason


def test_denied_subcommand_names_the_reason(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected) as excinfo:
        validate("docker exec app id", spec, ctx=ctx)
    assert "code execution" in excinfo.value.reason


def test_host_allowlist_narrows_but_never_widens(spec: dict, ctx: dict) -> None:
    """A host's `allow` list can only ever restrict the global spec."""
    validate("df -h", spec, allow=["df"], ctx=ctx)

    with pytest.raises(Rejected, match="not permitted on this host"):
        validate("journalctl -n 5", spec, allow=["df"], ctx=ctx)

    # Naming a binary that is not in the global spec does not conjure it into existence.
    with pytest.raises(Rejected, match="not an allowlisted command"):
        validate("nmap localhost", spec, allow=["nmap", "df"], ctx=ctx)


def test_curl_targets_default_deny(spec: dict) -> None:
    """An empty curl_targets means curl reaches nothing, not everything."""
    with pytest.raises(Rejected, match="no permitted curl targets"):
        validate("curl http://localhost/", spec, ctx={"curl_targets": []})


def test_traversal_rejected_before_prefix_match(spec: dict, ctx: dict) -> None:
    """`/var/log/../../etc/shadow` satisfies the prefix but must still be refused."""
    with pytest.raises(Rejected, match=r"\.\."):
        validate("tail -n 5 /var/log/../../etc/shadow", spec, ctx=ctx)


def test_flag_value_cannot_swallow_the_next_flag(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected, match="expects a value"):
        validate("journalctl -u -n 5", spec, ctx=ctx)


def test_oversized_input_rejected(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected, match="too long"):
        validate("df -h " + "x" * 5000, spec, ctx=ctx)


def test_int_bounds_enforced(spec: dict, ctx: dict) -> None:
    validate("journalctl -n 2000", spec, ctx=ctx)
    with pytest.raises(Rejected, match="at most 2000"):
        validate("journalctl -n 2001", spec, ctx=ctx)


@pytest.mark.parametrize("command", [c for _, c in ATTACKS if c.strip()])
def test_no_attack_ever_produces_executable_output(command: str, spec: dict, ctx: dict) -> None:
    """Belt and braces: even if something were accepted, it must not gain shell meaning.

    This is the property that makes the design robust to a validator bug. Accepted argv
    is re-quoted with `shlex.quote` before being sent, so a token containing `;` becomes a
    literal argument rather than a command separator.
    """
    try:
        result = validate(command, spec, ctx=ctx)
    except Rejected:
        return
    assert shlex.split(render(result.argv)) == result.argv
