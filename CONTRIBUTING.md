# Contributing

SafeReach is a security boundary that people point at production. That shapes what a good
contribution looks like: small, tested at the layer where the guarantee lives, and honest
about what it does not cover. This document is the whole bar; there is nothing unwritten.

## Development setup

```bash
git clone https://github.com/Ghost-141/SafeReach && cd SafeReach
uv venv && uv pip install -e ".[dev]"
uv run pytest -q                      # ~1 minute
uv run ruff check . && uv run ruff format --check .
```

Python 3.11+, `uv`, OpenSSH, and Docker for the end-to-end suite.

## Where a change belongs

The validator runs on both sides of the SSH connection, and only one side is a control.

| Layer | Files | Runs where | Counts as a control? |
|---|---|---|---|
| Shim | `src/safereach/validator.py`, `redact.py`, `config/commands.yaml`, `shim/shim_main.py` | On the host, as a forced command, from the root-owned bundle | **Yes** |
| Host state | The scripts in `cli.py` (`HARDENED_SCRIPT`, `DOCKER_PROXY_SCRIPT`, `SSHD_MATCH_SNIPPET`, `_sudoers_block`) | On the host, as root, at enrolment | **Yes** |
| Server | `server.py`, `ssh.py`, `config.py`, the rest of `cli.py` | On the operator's machine, inside the agent's reach | No — parity and error messages |

A security fix that lives only in the server layer is not a fix. Put it in the shim or
the host state, then mirror it in the server so the agent gets the same rejection message
without a round trip.

`validator.py` and `redact.py` are **stdlib-only** and are inlined into the shim. Do not
import anything else there. `tests/test_shim.py` will fail if you do.

## The three test layers, and which one your change needs

1. **Unit and differential** (`uv run pytest`). Always. The differential test runs every
   attack and acceptance string through the built shim and the in-process validator and
   requires them to agree, so a change to either side is checked against the other.
2. **Spec lint** (`tests/test_spec_lint.py`). Runs with the suite; it *drives* the
   validator with every mutating verb in every position the spec allows, and encodes each
   capability removed after the security review. If you are adding a capability back,
   you will be deleting a test that says why it was removed — do that deliberately, in
   the PR description.
3. **End to end** (`SAFEREACH_E2E=1 uv run pytest tests/e2e`). Required for any change
   to the remote scripts, the SSH layer, the spec, or the shim. It enrols a disposable
   production-like host (systemd, sshd, sudo, nested dockerd) as root and replays the
   review's probes against the real shim. CI runs it on every push; run it locally first
   because it is faster to iterate on. `python -m tests.e2e.rig up` keeps a host running
   to poke at by hand.

The canary suite (`tests/test_canary.py`) plants a known secret in every carrier and
asserts it never escapes. If your change touches redaction, add the carrier you are
worried about there, with a negative control that shows the canary *is* present before
redaction.

## Adding a binary to the allowlist

Read the [Extending the allowlist](README.md#extending-the-allowlist) section first. Then:

1. Enumerate the **safe flags**, not the dangerous ones. Default-deny does the rest.
2. Decide whether its positionals are **data** (paths, names, patterns) or **commands**
   (`ip route del`), and declare it in `DATA_POSITIONALS` in `test_spec_lint.py` with a
   sentence saying why. The linter refuses silence.
3. Add it to `READ_ONLY_BINARIES` with the reason it is read-only.
4. Add attack strings to `ATTACKS` in `tests/conftest.py` for every way you thought of
   to misuse it, and one legal form to `ACCEPTS` with its exact argv.
5. If it can print another process's arguments or environment, it does not go in.
6. If it needs privilege, add an **elevated recipe** in `cli.py`, never `sudo` to the spec.

## Adding a redaction pattern

Patterns are the last layer, not a control. Add the pattern to `_PATTERNS` in
`redact.py`, a positive case (the secret is masked) and a negative case (a container ID,
a git SHA, `production`, a path is untouched) to `tests/test_redact.py`. Vendor formats
should anchor on the vendor's documented prefix. Do not put a real-looking key in a test:
GitHub's push protection blocks `sk_live_…` shapes regardless of the value; use the
vendor's test prefix or a clearly fake shape.

## Pull requests

- One concern per PR. A security fix and a refactor are two PRs.
- The description says **which layer** the change lives in and **why that layer**.
- If the shim fingerprint changes (any edit to `validator.py`, `redact.py`,
  `commands.yaml`, `shim_main.py`), say so: every deployed host will be refused until
  `shim-update --all` runs, and the changelog entry must tell users that.
- If root-owned host state changes (the scripts), say so: users must re-enrol.
- Commit messages explain the problem before the change. The repository history is the
  design record; write for the person reading `git log` in a year.
- `ci-ok` must be green. It requires the matrix on 3.11–3.13 and the end-to-end suite.

## Releasing

Maintainers only. Bump `version` in `pyproject.toml` and add the changelog entry in the
same PR; merging publishes. See [Releasing](README.md#releasing) for how the gate works
and why it is the version number, not the merge, that triggers it.

## Reporting a security issue

Not on the issue tracker. See [SECURITY.md](SECURITY.md).
