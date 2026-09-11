# Security policy

SafeReach exists to be pointed at production hosts by an untrusted agent. A bypass of the
allowlist, a secret that reaches the agent, or a way to change state on a host is a
security issue, and it is the most important kind of report this project can receive.

## Reporting

**Do not open a public issue.** Use GitHub's private vulnerability reporting:

https://github.com/Ghost-141/SafeReach/security/advisories/new

Include the command or input that demonstrates the problem, the mode the host was
enrolled in (`enroll`, `enroll --hardened`, `discover`), and the shim fingerprint from
`safereach doctor`. A reproduction against the end-to-end rig (`tests/e2e`) is ideal, but
a clear description is enough.

You will get an acknowledgement within a few days. Fixes ship as a new PyPI release with
a changelog entry that says what to run on each host; the advisory is published after
the release is available.

## What counts

In scope, in rough order of severity:

1. Any way to change state on a managed host, in Docker, or in Kubernetes through an
   allowlisted command.
2. Any way to read a protected path (`.env`, keys, credentials, `/proc/*/environ`, this
   tool's own policy) or to get a shell.
3. Any command whose output carries a secret past the structural controls (not merely
   past the regex layer — see below).
4. A way to reach a host or a network endpoint the operator did not list.
5. A way for the diag account to widen its own policy, or for the MCP server to widen a
   host's policy over the wire.
6. A way to authenticate with a key that is not bound to the forced command.

Out of scope, documented as known limits in the README's threat model:

- Secrets an application writes into its own logs or journal. Redaction is best-effort
  by design; the structural controls are the guarantee.
- Anything that requires root on the host, or a compromised operator machine at the
  moment of enrolment.
- Client-only mode (`discover`, `require_shim: false`), which has no host-side control.

## Supported versions

Only the latest release on PyPI receives fixes. Every fix that changes the allowlist
changes the shim fingerprint, and hosts on the previous fingerprint are refused rather
than served, so there is no supported way to stay on an older validator.
