# Security

SafeReach exists to be pointed at production hosts by an untrusted agent. This document
is the full statement of what it defends against, how, and what it does not defend
against — followed by how to report a way around any of it.

The short version is in the README's [threat model](README.md#threat-model): the agent and
everything in its context are hostile; root on the host and the operator at enrolment are
trusted; the controls that count are root-owned on the host and read nothing from the wire.

## What holds, by construction

- **No state change** on a host, in Docker, or in Kubernetes. Every allowlisted binary is
  read-only; the spec linter probes every mutating verb in every position and fails the
  build if one is reachable.
- **No shell, no pipes, no subshells, no file writes, no arbitrary path reads**, no
  outbound requests except to `host:port` pairs the operator listed.
- **No secret file can be named**, in any argument, in any container.
- **No command can print another process's argv or environment.**
- **Docker is reached only through a read-only proxy** on a diag-only socket; the agent's
  account is not in the `docker` group and has no sudo beyond named recipes.
- **A host running an older allowlist is refused**, not served.

## What does not hold, and cannot

- **Secrets your application writes to its own logs.** A connection string in a stack
  trace, a token in a request URL. Redaction catches the shapes it knows; the fix is on
  the application side.
- **Names.** Variable names, file names under `/opt`, container names are visible. That
  is deliberate — it is what lets the agent reason about configuration.
- **Client-only mode** (`discover`, or `require_shim: false`). There is no host-side
  control at all. `defaults.production: true` refuses to start with it.

## Defence in depth

<p align="center"><img src="https://raw.githubusercontent.com/Ghost-141/SafeReach/main/diagram/defence-in-depth.png" alt="Defence in depth: client validator, SSH forced command, root-owned shim validator, Docker socket proxy, unprivileged diag account" width="100%"></p>

**No single failure is catastrophic.** A parser bug lands on the shim. A shim bug lands on
the socket proxy. A proxy bug lands on an account that cannot do much anyway.

## Secret protection — four layers

<p align="center"><img src="https://raw.githubusercontent.com/Ghost-141/SafeReach/main/diagram/secret-protection.png" alt="Secret protection in four layers: structural removal, protected paths, masking by name, masking by digest" width="100%"></p>

**Layer 0 — remove the capability.** A control that deletes a field always beats one that
filters it. `systemctl show` requires `--property` from a safe enum, so `Environment=` is
unrequestable, and `systemctl cat` is denied (it prints the unit file, `Environment=` and
all). `docker inspect` has no `--format` — a Go template reaches `Config.Env` in text form,
past the JSON mask — and `docker history` is denied (`ENV` build layers). `ps` has no
full-format flags and its `-o` columns are an enum with no `args`/`cmd`/`command`, so
`mysql -pSECRET` in a process list cannot be printed. `docker compose config` is denied
(it renders every resolved secret and has no flag to suppress them); `--services` is a
separate permitted path. `kubectl get` loses `-o yaml|json`, where inline `env:` lives,
and `kubectl describe configmap` is denied. `curl` targets are `host:port` — a bare host
means 80 and 443, never every service on loopback — and the host's own Docker API port is
refused before the allowlist is consulted, so the raw API cannot be read around the mask.

**Layer 1 — protected paths.** `*.env`, `*.pem`, `*.key`, `id_rsa*`, `*/.ssh/*`,
`*/.aws/*`, `/etc/shadow`, `/proc/*`, `/sys/*`, `*_history`, this tool's own policy and
binary, and ~40 more, checked against **every argument token** — a path can arrive as a
flag value. The list is **compiled into the shim**: a host policy may add patterns, never
remove them.

**Structural scrubs.** Two outputs carry secrets in a *shape* rather than under a
keyword, so they are rewritten by shape: every process line in a `systemctl status`
CGroup tree is reduced to PID and executable, and every value under an `Environment:`
heading in `kubectl describe` is masked. Neither depends on guessing what a secret looks
like.

**Layer 2 — masking by name.** Enrolment reads the *variable names* from the host's `.env`
files and masks their values in four shapes (`KEY=v`, `KEY: v`, `"KEY": "v"`, `KEY = v`).
Names only — `cut -d= -f1` truncates before any value can escape.

**Layer 3 — masking by digest.** Catches a value appearing with **no variable name** — a
token in a stack trace, a password in a log line. Enrolment computes `HMAC-SHA256` of each
value *as root, on the host*, and stores **only digests**. Gated on length ≥ 12 and entropy
≥ 3.0 bits/char, so `production` and `localhost` stay readable.

All masking happens **on the host, before anything crosses the wire** — so it holds even
against someone using the enrolled key directly.

## Non-destructive by construction

The agent cannot delete, remove, stop, restart, prune, kill or scale anything.

That guarantee used to depend on remembering to deny each verb per binary — until
`ip route del default` was found to be **accepted**, because `ip`'s mutating verb sits in
the *positional* slot where subcommand denylists never look.

So it is now enforced by the build:

- `MUTATING_VERBS` (75 verbs) lives in `validator.py` — one source of truth, checked at
  runtime on both sides
- a **spec linter** drives the real validator with every verb against every legal command
  prefix in the spec, and **fails the build** if any is reachable
- every binary must declare whether its positionals are **commands** or **data**, with a
  written justification. Silence is not an option — silence is how `ip` slipped through

## What hardened enrolment leaves on the host

`enroll --hardened` needs sudo on the target once and writes root-owned state. Each item
exists for a specific reason:

- **An unprivileged `diag` account** — no sudo, not in the `docker` group. A shim bug
  lands on an account that cannot do much.
- **The shim at `/usr/local/bin/safereach-shim` and its policy at
  `/etc/safereach/config.json`, both root-owned.** The account cannot rewrite what it is
  allowed to run. The policy is `0640 root:diag`: it holds the HMAC key for the secret
  digests, and no other local account can read it.
- **A read-only Docker socket proxy** (`POST=0 EXEC=0`), pinned by image digest, on a
  **unix socket** (`/run/safereach/docker.sock`, mode `0660`, diag group) rather than a
  TCP port — reachable by `docker` running as `diag` and by nothing else. Where the socket
  bind is not possible it falls back to loopback TCP limited to the diag uid by
  `iptables`, and the shim refuses `curl` to that port however `curl_targets` is written.
- **An exact-match sudoers entry** for enabled recipes only — never `sudo` itself — with
  the binary path resolved on that host, so `/bin/dmesg` and `/usr/bin/dmesg` hosts both
  match.
- **An sshd `Match User diag` drop-in** (`MaxSessions 4`, no forwarding, no TTY),
  duplicating the key-line restrictions at the daemon level so a mistake on the key line
  cannot reopen them. Validated with `sshd -t` before it is kept; sshd is reloaded only if
  it validates.
- **An append-only audit log** (`chattr +a` on `/var/log/safereach.jsonl`), so the account
  cannot erase its trail.
- **Every command runs under `nice -n 19`, `ionice -c 3` and a `prlimit` CPU cap** where
  those exist, so a diagnostic loses every scheduling contest with the workload it is
  diagnosing.

On the operator's side, the server offers **only the enrolled key** to the host: the SSH
agent is asked for that identity and no other, so a personal key that is also authorised
there can never win the handshake and land in an account without the forced command.

## Container inspection, and what keeps it safe

`run_in_container` is off by default and default-deny on both axes: `--allow-exec`
requires at least one `--exec-container` and at least one absolute `--exec-path`, both
written into the host's root-owned policy. Neither can be supplied over the wire.

The inner command is validated by **the same validator**, against a narrow in-container
allowlist (`cat`, `tail`, `head`, `ls`, `stat`, `ps`, `df`, `grep`).
`docker exec app sh -c '…'` fails because `sh` is not allowlisted — not through a special
case. The content-reading commands may only name paths under an `--exec-path` prefix;
`ls`, `stat`, `df` and `ps` return names and numbers. The protected-path list still
applies, so `cat /app/.env` and `cat /proc/1/environ` are refused inside the container
too. No TTY, no stdin, no interactive session.

**The tradeoff, stated plainly:** `--allow-exec` requires `POST` on the Docker proxy, which
also permits container create/start at the API level. The command allowlist remains the
control; the proxy no longer is. Leave it off unless you need it.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:

https://github.com/Ghost-141/SafeReach/security/advisories/new

Include the command or input that demonstrates the problem, the mode the host was
enrolled in (`enroll`, `enroll --hardened`, `discover`), and the shim fingerprint from
`safereach doctor`. A reproduction against the end-to-end rig (`tests/e2e`) is ideal, but
a clear description is enough.

You will get an acknowledgement within a few days. Fixes ship as a new PyPI release with
a changelog entry that says what to run on each host; the advisory is published after
the release is available.

### What counts

In scope, in rough order of severity:

1. Any way to change state on a managed host, in Docker, or in Kubernetes through an
   allowlisted command.
2. Any way to read a protected path (`.env`, keys, credentials, `/proc/*/environ`, this
   tool's own policy) or to get a shell.
3. Any command whose output carries a secret past the structural controls (not merely
   past the regex layer).
4. A way to reach a host or a network endpoint the operator did not list.
5. A way for the diag account to widen its own policy, or for the MCP server to widen a
   host's policy over the wire.
6. A way to authenticate with a key that is not bound to the forced command.

Out of scope, as documented above under *what does not hold*: secrets an application
writes into its own logs, anything that requires root on the host or a compromised
operator machine at enrolment, and client-only mode.

### Supported versions

Only the latest release on PyPI receives fixes. Every fix that changes the allowlist
changes the shim fingerprint, and hosts on the previous fingerprint are refused rather
than served, so there is no supported way to stay on an older validator.
