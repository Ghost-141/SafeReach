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

## The test suites

```bash
uv run pytest              # the unit and differential suites, about a minute
uv run ruff check .
uv run python shim/build.py
```

| Suite | What it covers |
|---|---|
| `test_validator_attacks` | Adversarial corpus — injection, traversal, escape-hatch binaries |
| `test_spec_lint` | Fails the build if any mutating verb is reachable, or any removed capability returns |
| `test_canary` | Plants a known secret in 12 carriers; asserts it never escapes |
| `test_shim` | Differential — bundled shim must agree with the in-process validator |
| `test_secrets` | Protected paths and name-based masking |
| `test_kubernetes` | Read-only kubectl; secrets denied in every spelling |
| `test_stdio_clean` | stdout carries JSON-RPC and nothing else |
| `test_enroll` | The remote script never clobbers existing `authorized_keys` |
| `test_naming`, `test_rename` | Alias validation, stable ids, rewriting `hosts.yaml` in place |
| `test_exec_inner` | The in-container allowlist: prefixes from host policy, `/proc` denied |
| `test_host_state` | The remote scripts: policy mode, sudoers, sshd drop-in, digest key never on argv |
| `test_ssh_auth` | The SSH agent is pinned to the enrolled key |
| `test_wheel` | The built wheel, in a clean venv, can produce a working shim |
| `e2e/` | All of the above executed on a real host |

The canary suite is the strongest evidence available: per-pattern tests prove the patterns
work, but only a canary suggests nothing escapes. Each case has a **negative control**
asserting the canary *is* present without redaction — otherwise a test that finds nothing
proves only that the input was empty.

### End to end, against a real host

Everything above runs in-process. The controls that matter most — the hardened enrolment
as root, the sshd `Match` block, the sudoers file, the proxy's unix socket, the forced
command over a real SSH channel — are exercised for real against a disposable
production-like host: Ubuntu 24.04 with systemd, sshd, sudo, journald and its own Docker
daemon, in a privileged container on your machine.

```bash
SAFEREACH_E2E=1 uv run pytest tests/e2e -v      # needs Docker; ~40 s once the image exists
python -m tests.e2e.rig up                        # or keep one running to poke at
python -m tests.e2e.rig destroy
```

It enrols the host with `--hardened --allow-exec`, then asserts on the host itself
(policy `0640 root:diag`, socket `0660`, `sshd -T -C user=diag`, `visudo -c`), replays
every reproduction string from the security review through the real shim, checks the
legal diagnostics come back with their secrets scrubbed, and confirms another local
account can read neither the policy nor the socket.

CI runs it on **every push and pull request**, and the `ci-ok` check requires it. The
publish workflow runs it again on the exact tree being released, before the wheel is
built, so nothing reaches PyPI that has not been enrolled onto a real host in the same
run.

## Extending the allowlist

`config/commands.yaml` is data. Adding a binary means enumerating its **safe flags**:

```yaml
mytool:
  description: What it does
  flags:
    "-n": { alias: "--lines", value: { type: int, min: 1, max: 2000 } }
  positionals:
    max: 2
    pattern: '/var/log/[A-Za-z0-9._/\-]{1,200}'
    path_prefixes: ["/var/log/"]
  deny_flags:
    "-o": "writes a file to disk"
```

Check it against these before adding:

- Can it **spawn a child process**? (`-exec`, `--to-command`, `!` escapes) → don't add it
- Can it **write a file**? → deny those flags explicitly
- Can it **read an arbitrary path**? → constrain `path_prefixes`
- Can it **print another process's arguments or environment**? (`ps -f`, `systemctl cat`,
  a `--format` template) → don't add the flag; argv and environments are where passwords live
- Can it **stream forever**? (`-f`, `--follow`) → deny; the timeout is a backstop, not a control
- Can it **read options from a file**? (`curl -K`) → deny; it bypasses the allowlist
- Can it **follow a redirect or reach a port**? → pin `host:port`, deny `-L`

For a privileged read, add an **elevated recipe** rather than widening the parser. Never
put `sudo` in `commands.yaml` — if the agent can pass arguments to `sudo`, the allowlist is
decorative.

Then, step by step:

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

Maintainers only. Publishing is automatic, and triggered by the **version number**, not by
merging:

```bash
git switch -c release-0.4.0
sed -i 's/^version = .*/version = "0.4.0"/' pyproject.toml   # plus the CHANGELOG entry
gh pr create --fill        # merge through review as usual
```

When that PR merges, the publish workflow sees `pyproject.toml` changed, compares the
version against the previous commit, confirms it is not already on PyPI, then runs the
spec linter, the full suite, lint, format check, the end-to-end suite against a real
host, the build, a README render check, and a clean-environment install of the built wheel
that must produce a working shim — and only then uploads. The GitHub release is tagged
afterwards, so a tag always names something that is actually installable.

Merging anything that does not change the version is silently a no-op.

**Why gate on the version rather than publish on every merge:** PyPI versions are
immutable. The first merge that did not bump the version would fail with "file already
exists", and CI would stay red from then on.

Uploads use **Trusted Publishing** (OIDC) with PEP 740 attestations — no API token is
stored anywhere, and each artifact is cryptographically bound to the commit and workflow
that produced it. That matters for a package people install and then point at their own
production servers; the attestation is shown on the PyPI project page.

`Actions → Publish → Run workflow` still allows a manual run, including to TestPyPI.

**Stacked branches:** merge them in order, oldest first. A later branch squash-merged
first carries the earlier ones with it, and only the last version number gets published.

## Reporting a security issue

Not on the issue tracker. See [SECURITY.md](SECURITY.md).
