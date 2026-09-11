# Architecture

The README's [Architecture](../README.md#architecture) section states the central
decision: the validator runs twice, and only the copy on the host is a control. These two
diagrams show what that means for one request, and what stands between the agent and a
destructive command.

## Request lifecycle

<p align="center"><img src="https://raw.githubusercontent.com/Ghost-141/SafeReach/main/diagram/request-lifecycle.png" alt="Request lifecycle: agent → MCP server (client-side validation) → sshd forced command → shim (independent validation) → command → redaction → audit → masked result" width="100%"></p>

The wire format matters more than it looks. After client-side validation the argv goes
over SSH as a **JSON array**, never a shell string, so the host never re-tokenises text
the agent influenced. The shim validates that array from scratch against its own embedded
spec, executes it with no shell and no PTY, redacts the output on the host, writes its own
audit line, and only then returns anything.

## Defence in depth

<p align="center"><img src="https://raw.githubusercontent.com/Ghost-141/SafeReach/main/diagram/defence-in-depth.png" alt="Defence in depth: client validator, SSH forced command, root-owned shim validator, Docker socket proxy, unprivileged diag account" width="100%"></p>

**No single failure is catastrophic.** A parser bug lands on the shim. A shim bug lands on
the socket proxy. A proxy bug lands on an account that cannot do much anyway. Which layer
each guarantee rests on, and what each layer cannot cover, is in
[SECURITY.md](../SECURITY.md).
