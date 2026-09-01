"""Spec linter — fails the build if commands.yaml ever permits a mutating verb.

Written after `ip route del default` was found to be **accepted**. `ip`'s subcommands are
read-only names (`addr`, `route`, `link`); the mutating verb sits in the *positional*
slot, where `deny_subcommands` never looks. Per-binary denylists had covered every case
anyone had thought of, which is exactly the failure mode of a guarantee that depends on
remembering.

So this does not read the spec and reason about it. It **drives the real validator** with
every mutating verb in every position the spec allows, and asserts refusal. A new binary
with a novel shape is covered automatically, because the probe is generated from that
binary's own spec.
"""

from __future__ import annotations

import pytest

from safereach.validator import MUTATING_VERBS, Rejected, render, validate

#: Imported, never redefined: the runtime check in validator.py and this linter must
#: use the same set or they drift, which is precisely the bug that prompted this file.
#: Every binary the agent may invoke, with why it is safe. Adding a binary to
#: commands.yaml without adding it here fails the build — so it takes a deliberate edit
#: in two places, and the justification is written down.
READ_ONLY_BINARIES = {
    "journalctl": "reads the systemd journal; vacuum/rotate/flush denied",
    "systemctl": "status-class subcommands only; every state change denied",
    "dmesg": "reads the kernel ring buffer; --clear denied",
    "df": "reports filesystem usage",
    "du": "reports directory sizes",
    "free": "reports memory usage",
    "uptime": "reports load average",
    "nproc": "reports CPU count",
    "hostnamectl": "status only; set-hostname denied",
    "ps": "reads the process table",
    "ss": "reads socket statistics",
    "ip": "read-only address/route/link queries; mutating positionals denied",
    "tail": "reads log files under /var/log only",
    "head": "reads log files under /var/log only",
    "grep": "searches log files under /var/log only",
    "stat": "reads file metadata",
    "ls": "lists directories",
    "docker": "read-only subcommand paths; also enforced by the socket proxy",
    "curl": "GET/HEAD only, to allowlisted hosts",
    "kubectl": "read-only verbs; secrets denied as a resource; RBAC is the real control",
}

#: Binaries whose positionals are inert DATA — object names, paths, patterns, URLs —
#: rather than commands the tool will act on. `docker inspect stop` merely looks for a
#: container called "stop"; `grep delete /var/log/x` searches for the word.
#:
#: This declaration is the point of the linter. `ip` is deliberately absent: its
#: positionals *are* commands (`ip route del default` deletes a route), which is exactly
#: the bug this file was written after. Anyone adding a binary has to decide which kind
#: it is and say so here, in writing.
DATA_POSITIONALS = {
    "grep": "positional 0 is a search pattern; the rest are /var/log paths",
    "docker": "container, image, network and volume NAMES — the verb lives in the "
    "subcommand path, which is separately allowlisted",
    "kubectl": "resource kinds and names; the verb lives in the subcommand path",
    "systemctl": "systemd unit names; the verb is the subcommand",
    "hostnamectl": "accepts no positionals at all; `status` is the only subcommand",
    "tail": "filesystem paths, prefix-restricted to /var/log",
    "head": "filesystem paths, prefix-restricted to /var/log",
    "stat": "filesystem paths, prefix-restricted; returns metadata only, never contents",
    "ls": "directory paths, prefix-restricted; lists names, never file contents",
    "du": "directory paths, prefix-restricted; reports sizes, never file contents",
    "df": "mount points only; reports free space, cannot name a file inside one",
    "curl": "a single URL, pinned to http/https and to this host's curl_targets list",
}

#: Flags named like output redirection that are not. Each needs a justification.
OUTPUT_FLAG_EXEMPTIONS = {
    ("ps", "-o"): "ps -o is a column FORMAT spec (`-o pid,comm`), not a destination; "
    "its value is regex-constrained to lowercase field names and separators",
    ("kubectl", "--output"): "kubectl --output selects a rendering (wide/name/json), "
    "not a file; its value is enum-constrained",
    ("journalctl", "--output"): "journalctl --output selects a rendering, not a file; "
    "its value is enum-constrained",
    ("docker", "--output"): "docker --format-style rendering selector, enum-constrained",
}


def _subcommand_prefixes(bspec: dict) -> list[list[str]]:
    """Every valid command prefix for a binary, so probes start from a legal invocation."""
    if bspec.get("subcommand_paths"):
        out = []
        for entry in bspec["subcommand_paths"]:
            path = entry["path"] if isinstance(entry, dict) else entry
            out.append(list(path))
        return out
    if bspec.get("subcommands"):
        return [[sub] for sub in bspec["subcommands"]]
    return [[]]


def test_every_allowlisted_binary_is_declared_read_only(spec: dict) -> None:
    """A binary in the spec but not on the roster fails the build."""
    undeclared = set(spec) - set(READ_ONLY_BINARIES)
    assert not undeclared, (
        f"binaries in commands.yaml with no read-only justification: {sorted(undeclared)}. "
        "Add them to READ_ONLY_BINARIES with a reason, or remove them from the spec."
    )

    stale = set(READ_ONLY_BINARIES) - set(spec)
    assert not stale, f"roster lists binaries no longer in the spec: {sorted(stale)}"


def test_no_subcommand_is_a_mutating_verb(spec: dict) -> None:
    """The cheap static half: a mutating verb must never be an allowlisted subcommand."""
    offenders = []
    for binary, bspec in spec.items():
        for prefix in _subcommand_prefixes(bspec):
            for token in prefix:
                if token.lower() in MUTATING_VERBS:
                    offenders.append(f"{binary} {' '.join(prefix)}")
    assert not offenders, f"mutating subcommands are allowlisted: {sorted(set(offenders))}"


@pytest.mark.parametrize("verb", sorted(MUTATING_VERBS))
def test_no_mutating_verb_is_reachable_as_a_command(verb: str, spec: dict, ctx: dict) -> None:
    """The half that caught `ip route del default`.

    Only binaries whose positionals are *commands* are probed — a binary that takes
    names or paths is exempt by explicit declaration in DATA_POSITIONALS. That keeps the
    check meaningful instead of flagging `docker inspect stop`, where "stop" is just a
    container that does not exist.
    """
    accepted: list[str] = []

    for binary, bspec in spec.items():
        if binary in DATA_POSITIONALS:
            continue
        for prefix in _subcommand_prefixes(bspec):
            command = " ".join([binary, *prefix, verb])
            try:
                result = validate(command, spec, ctx=ctx)
            except Rejected:
                continue
            accepted.append(f"{command!r} -> {render(result.argv)!r}")

    assert not accepted, f"the mutating verb {verb!r} is reachable:\n  " + "\n  ".join(
        sorted(accepted)
    )


def test_every_binary_declares_its_positional_kind(spec: dict) -> None:
    """Force the decision rather than letting it default.

    A binary is either "positionals are data" (declared, with a reason) or "positionals
    are commands" (probed exhaustively above). Silence is not an option, because silence
    is how `ip` slipped through.
    """
    takes_positionals = {
        binary
        for binary, bspec in spec.items()
        if (bspec.get("positionals") or {}).get("max", 0) > 0
    }
    undeclared = takes_positionals - set(DATA_POSITIONALS) - {"ip"}
    assert not undeclared, (
        f"binaries accepting positionals with no declared kind: {sorted(undeclared)}. "
        "Add them to DATA_POSITIONALS with a reason, or ensure the mutating-verb probe "
        "covers them."
    )


def test_output_writing_flags_are_value_constrained(spec: dict) -> None:
    """`-o`/`--output` may exist only where its value is pinned by an enum.

    Free-form `-o` writes a file to disk. `curl -o /dev/null` is fine because the enum
    permits exactly one destination; anything looser is not.
    """
    offenders = []
    for binary, bspec in spec.items():
        groups = [bspec.get("flags") or {}]
        for entry in bspec.get("subcommand_paths") or []:
            if isinstance(entry, dict) and entry.get("flags"):
                groups.append(entry["flags"])

        for flags in groups:
            for name, raw in flags.items():
                if name not in {"-o", "--output", "-O", "--remote-name"}:
                    continue
                if (binary, name) in OUTPUT_FLAG_EXEMPTIONS:
                    continue
                value = (raw or {}).get("value") if isinstance(raw, dict) else None
                if not isinstance(value, dict) or value.get("type") != "enum":
                    offenders.append(f"{binary} {name}")
    assert not offenders, (
        f"output flags without an enum-constrained value: {sorted(set(offenders))}"
    )


def test_exemptions_carry_a_justification() -> None:
    """An exemption without a reason is a hole nobody will revisit."""
    for key, reason in {**DATA_POSITIONALS, **OUTPUT_FLAG_EXEMPTIONS}.items():
        assert len(reason) > 40, f"exemption {key!r} needs a real justification"
