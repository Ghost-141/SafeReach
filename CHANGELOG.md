# Changelog

All notable changes, newest first. Versions are PyPI releases; each is tagged `vX.Y.Z`.
Every entry says what a user has to do on upgrade, because a shim fingerprint change
refuses every host until `safereach shim-update --all` runs.

## Unreleased

- New `safereach unenroll <host>`: takes a host out. Removes our key line, the shim and
  policy, and in hardened mode the sshd drop-in, sudoers entry, Docker proxy and the diag
  account's key, then **proves the enrolled key no longer authenticates** before dropping
  the host from `hosts.yaml`. The diag account and the host's audit log are kept unless
  `--remove-user` / `--purge-log` say otherwise. `--local-only` drops the entry for a host
  that no longer exists. Exercised end to end: the suite unenrols the rig host last and
  checks nothing is left.
- New `safereach hosts`: every configured host as a table — alias, address, user, port,
  mode (`enrolled`, `ssh-config`, `client-only`) and description. Reads `hosts.yaml`
  only, so it is instant and works offline. `--json` prints the same list on stdout for
  scripting. The MCP tool `list_hosts` still hides addresses from the agent; this is the
  operator's view.

## 0.3.0 — host state: policy file, proxy socket, sshd, sudoers, key pinning

**This is the first release after 0.1.1.** The 0.1.3 and 0.2.0 entries below were never
published on their own; their changes shipped here. Upgrading from 0.1.1 therefore needs
all three steps, in this order:

```bash
uvx safereach@0.3.0 install         # repoint the agents
safereach shim-update --all         # the 0.2.0 fingerprint change; hosts are refused until this runs
safereach enroll <host> --hardened  # the 0.3.0 host-state changes; idempotent, one per host
```

- `/etc/safereach/config.json` is installed `0640 root:diag` instead of `0644`. It holds
  the HMAC key for the secret digests; world-readable, any local user could brute-force
  weak values offline.
- The digest key is delivered inside the enrolment script on stdin, never as a sudo
  argument — sudo logs its argv to the journal, which the diag account reads.
- The Docker proxy is pinned by image digest and listens on a unix socket readable by
  the diag group only, not on a loopback TCP port every local user could reach. Falls
  back to uid-filtered TCP where the socket bind is not possible, and says which.
- An sshd `Match User diag` drop-in duplicates the key-line restrictions at the daemon
  level and caps sessions at 4. Written only where sshd includes `sshd_config.d`,
  validated with `sshd -t` and `sshd -T -C user=diag`, removed if either fails.
- `provision` writes the same sudoers block and recipe table as `enroll --hardened`;
  recipes use bare binary names and the sudoers line carries the path `command -v`
  finds on that host, so the two cannot disagree.
- Uploads go to a `mktemp -d` directory on the host, not fixed names under `/tmp`.
- The server pins the SSH agent to the enrolled key's identity. asyncssh otherwise tries
  every agent key first, and on a plain-enrol host the operator's own key is authorised
  for the same account — without the forced command.
- `check_connectivity` and `doctor` now report `unrestricted` when a login shell, not
  the shim, answers the version probe on a host that requires one: that is a key with
  shell access, not a missing package, and the message says so.

## 0.2.0 — closes the secret-leak paths found in review

*Not published separately; shipped in 0.3.0.*

Every deployed shim is refused until `safereach shim-update --all` runs: the fingerprint
changed, and a host on the old rules is refused rather than quietly served. Upgrade with
`uvx safereach@0.3.0 install`, then `safereach shim-update --all`.

**Removed capabilities (Layer 0)** — each was reproduced returning secrets:
- `curl_targets` entries are now `host:port`; a bare host covers 80 and 443 only. It used
  to cover every port on the box, which put the Docker API, Elasticsearch, Consul and
  anything else on loopback one GET away. The host's own Docker API port is refused
  before the allowlist is consulted, however it is listed. `-L`/`--location` are denied.
- `docker inspect` has no `--format`: a Go template reaches `Config.Env` in text form,
  past the JSON mask. `docker history` is denied (`ENV`/`ARG` build layers).
- `systemctl cat` is denied (prints `Environment=` verbatim). `ps` loses every full-format
  flag; `-o` is an enumerated column alphabet without `args`/`cmd`/`command`.
- `run_in_container`: `cat`/`tail`/`head`/`grep` may only read under `--exec-path`
  prefixes written into the host policy, and refuse everything when none are set.
  `--allow-exec` now requires `--exec-container` and `--exec-path`. `/proc/*`, `/sys/*`
  and shell history files join the compiled-in deny list, as do this tool's own policy
  file and binary.
- `du` loses `/home/` and is capped at depth 3. `kubectl describe configmap` is denied,
  and resource abbreviations (`sa`, `cm`) are canonicalised before any deny is checked.

**Structural scrubs** — by shape, not by keyword: `systemctl status` CGroup lines are
reduced to PID and executable; values under `Environment:` in `kubectl describe` are
masked; `Cmd`/`Entrypoint`/`Args` in `docker inspect` JSON go through the argument
patterns in place.

**Redaction (last layer)** — identifiers ending in `_KEY`, `_SALT`, `_DSN`, `_PASS`,
`PASSPHRASE`; `--password x` / `--token=x` style arguments; `mysql -pX`, `redis-cli -a X`;
Stripe, Google, Anthropic, OpenAI, GitLab, GitHub fine-grained, Slack app, SendGrid, Vault,
Docker Hub, npm, PyPI and AWS STS token formats.

**Host-side cost bound** — every command runs under `nice -n 19`, `ionice -c 3` and
`prlimit --cpu` where present.

**`defaults.production: true`** — the server refuses to start with any client-only or
`~/.ssh/config` host, so the weaker modes are a startup error.

**Enforcement** — the spec linter now fails the build if any of the above is added back,
if the protected-path list shrinks below a frozen floor, or if any path prefix could reach
the policy file or the shim. The reproduction strings from the review are in the attack
corpus and run through the built shim as well as the in-process validator.

## 0.1.3

*Not published separately; shipped in 0.3.0.*

- **The published wheel could not enrol a host.** 0.1.0 and 0.1.1 packaged
  `shim_main.py` but not the builder that assembles it, so `enroll`, `provision`,
  `shim-update` and `doctor --fix` all failed from a `uvx` install with
  "cannot locate shim/build.py or a packaged safereach-shim". Only source checkouts
  worked, and every test ran from one.
- The bundler now lives inside the package (`safereach.shimbuild`) and builds the shim
  at runtime from the installed `validator.py`, `redact.py`, `commands.yaml` and
  `shim_main.py`. There is no pre-built artifact to go stale, and the fingerprint the
  shim reports matches the one the server expects by construction.
- New `safereach shim-build [--out PATH | --print-version]` for hand-configured hosts
  and for checking an install can produce a shim at all.
- The release smoke test now builds a shim from the installed wheel, runs it, and
  compares its fingerprint with the server's. A new test does the same in the suite.

## 0.1.2

- `--version` reported `0.1.0` from the 0.1.1 package. `__version__` was a hard-coded
  literal alongside the one in `pyproject.toml`, and the two drifted.
- That mattered beyond the banner: `install` pins agents to `__version__`, so installing
  0.1.1 would have written `uvx safereach@0.1.0` into every agent's config — wiring them
  to the previous release.
- `__version__` is now read from installed package metadata, so it cannot disagree with
  the wheel it came from. Two tests hold it: one comparing against `pyproject.toml`, one
  asserting the registration pins the running version.

## 0.1.1

**Terminal output**
- `--help`, `doctor`, `discover` and `install --list` render as tables with a shared
  colour vocabulary, so a status means the same thing in every command
- the console is bound to **stderr**, never stdout — stdout carries JSON-RPC in server
  mode, and one styled byte there corrupts the stream for every agent. Five tests hold
  that line, including one asserting the bundled shim still imports no `rich`
- colour is dropped when piped and when `NO_COLOR` is set

**Help**
- commands are grouped by task with a quick start on top, rather than listed
  alphabetically — the generated list said which commands existed, not which to run first
- every subcommand gained a description; `help=` only ever fed the parent's listing, so
  `safereach enroll --help` had been flags and nothing else
- `safereach` with no arguments on a terminal now shows help instead of starting a silent
  server and appearing to hang. Agents launch it over a pipe, so the two cases are
  distinguishable
- added `--version`

**Release automation**
- publishing is triggered by a version change rather than by merging. PyPI versions are
  immutable, so publishing on every merge would fail on the first merge that did not bump
- PEP 740 attestations bind each artifact to the commit and workflow that built it
- the GitHub release is tagged only after a successful upload, so a tag always names
  something installable

## 0.1.0 — initial release

**Core**
- MCP server (SDK v2, stdio) exposing eight read-only diagnostic tools
- Two-sided validation: client-side for error quality, remote shim as the real boundary
- Structured argv over the wire — no tokenisation on the remote side, so the two
  validators cannot disagree about quoting
- Connection pooling, per-command timeouts, output caps, concurrent fan-out

**Security**
- SSH forced command; enrolment verifies the restriction and refuses the host if an escape
  succeeds
- Hardened mode: unprivileged account, root-owned shim and policy, read-only Docker proxy,
  exact-match sudoers, append-only audit log
- Four-layer secret protection (structural · paths · names · digests), applied on the host
- Spec linter enforcing non-destructiveness at build time
- Shim fingerprinting: a drifted host is refused, not warned about

**Allowlist** — `journalctl`, `systemctl`, `dmesg`, `df`, `du`, `free`, `uptime`, `nproc`,
`hostnamectl`, `ps`, `ss`, `ip`, `tail`, `head`, `grep`, `stat`, `ls`, `docker`, `curl`,
`kubectl`

**Known limits**
- Masking is best-effort for unstructured text; Layers 0–1 are structural, 2–3 are not
- The `diag` account is in `adm`, so it can read `/var/log` — inherent to being useful
- Kubernetes RBAC is not automated; the allowlist is not a substitute for a read-only Role
- ~900 lines of security-critical code with no external audit yet

---
