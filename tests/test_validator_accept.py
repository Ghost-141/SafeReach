"""Acceptance cases and the round-trip invariant.

A validator that rejects everything is trivially safe and useless, so these pin the legal
forms to their exact argv — including the force-injected flags, which is where the two
subtlest bugs lived (a stray value left behind by `--tail`, and alias-blind dedup adding a
second `--silent` when `-s` was already present).
"""

from __future__ import annotations

import shlex

import pytest
from conftest import ACCEPTS

from safereach.validator import Rejected, render, spec_summary, validate


@pytest.mark.parametrize(("command", "expected"), ACCEPTS, ids=[c[:48] for c, _ in ACCEPTS])
def test_accepted_with_exact_argv(command: str, expected: list[str], spec: dict, ctx: dict) -> None:
    result = validate(command, spec, ctx=ctx)
    assert result.argv == expected


@pytest.mark.parametrize("command", [c for c, _ in ACCEPTS], ids=[c[:48] for c, _ in ACCEPTS])
def test_round_trip_invariant(command: str, spec: dict, ctx: dict) -> None:
    """`shlex.split(render(argv)) == argv` for everything we accept.

    This is the structural guarantee that the remote shell cannot observe a token
    boundary we did not intend, and it is what lets quoting rather than blocklisting be
    the primary defence against metacharacters.
    """
    result = validate(command, spec, ctx=ctx)
    assert shlex.split(render(result.argv)) == result.argv


def test_force_injection_is_idempotent(spec: dict, ctx: dict) -> None:
    """Running an already-normalised command must not accumulate flags."""
    once = validate("docker stats", spec, ctx=ctx)
    twice = validate(render(once.argv), spec, ctx=ctx)
    assert once.argv == twice.argv


@pytest.mark.parametrize("command", [c for c, _ in ACCEPTS])
def test_all_accepts_are_idempotent(command: str, spec: dict, ctx: dict) -> None:
    first = validate(command, spec, ctx=ctx)
    second = validate(render(first.argv), spec, ctx=ctx)
    assert first.argv == second.argv, "re-validating a rendered command changed it"


def test_alias_dedup_in_force_injection(spec: dict, ctx: dict) -> None:
    """`-s` and `--silent` are the same flag; forcing must notice that."""
    result = validate("curl -s http://localhost/", spec, ctx=ctx)
    assert result.argv.count("-s") == 1
    assert "--silent" not in result.argv


def test_forced_value_flag_not_orphaned(spec: dict, ctx: dict) -> None:
    """`--tail 500` must be injected as a pair, or not at all — never a bare `500`."""
    result = validate("docker logs --tail 200 app", spec, ctx=ctx)
    assert "500" not in result.argv
    assert result.argv == ["docker", "logs", "--tail", "200", "app"]


def test_long_and_short_forms_equivalent(spec: dict, ctx: dict) -> None:
    short = validate("journalctl -u nginx -n 5", spec, ctx=ctx)
    long = validate("journalctl --unit nginx --lines 5", spec, ctx=ctx)
    assert short.argv[1:3] == ["-u", "nginx"]
    assert long.argv[1:3] == ["--unit", "nginx"]
    assert len(short.argv) == len(long.argv)


def test_inline_and_separated_values_both_work(spec: dict, ctx: dict) -> None:
    for form in ("journalctl -n 5", "journalctl -n5", "journalctl --lines=5"):
        result = validate(form, spec, ctx=ctx)
        assert "5" in result.argv


def test_repeatable_flag_allowed_twice(spec: dict, ctx: dict) -> None:
    result = validate("journalctl -u nginx -u redis", spec, ctx=ctx)
    assert result.argv.count("-u") == 2


def test_non_repeatable_flag_refused_twice(spec: dict, ctx: dict) -> None:
    with pytest.raises(Rejected, match="more than once"):
        validate("journalctl -n 5 -n 10", spec, ctx=ctx)


def test_docker_subcommand_paths_resolve_longest_first(spec: dict, ctx: dict) -> None:
    nested = validate("docker container ls", spec, ctx=ctx)
    assert nested.subcommand == ("container", "ls")
    flat = validate("docker ps", spec, ctx=ctx)
    assert flat.subcommand == ("ps",)


def test_spec_summary_is_actionable(spec: dict) -> None:
    """`describe_commands` output is what stops the agent guessing."""
    summary = spec_summary(spec)
    assert "journalctl" in summary
    assert "-u" in summary["journalctl"]["flags"]
    assert "status" in summary["systemctl"]["subcommands"]
    assert "exec" in summary["docker"]["never_permitted"]
    assert summary["docker"]["note"].startswith("long flags only")
    assert summary["tail"]["paths_limited_to"] == ["/var/log/"]

    narrowed = spec_summary(spec, allow=["df"])
    assert set(narrowed) == {"df"}
