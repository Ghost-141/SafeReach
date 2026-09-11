# Troubleshooting

Start with `doctor`. It checks the config, key permissions, host reachability, and whether
each host's shim matches this version.

```bash
safereach hosts           # what is configured, with addresses — no network
safereach doctor          # config, keys, connectivity, shim versions
safereach doctor --fix    # re-push a drifted shim
safereach validate "journalctl -u nginx -n 200" --host myserver
```

`hosts` answers "which machine is `prod-web`, and is it enrolled at all" without touching
the network; `doctor` answers whether each one is reachable and hardened.

## Symptoms

| Symptom | Cause, and what to do |
|---|---|
| `no safereach-shim installed` | Run `safereach enroll <host>` |
| `shim <x> != expected <y>` | The allowlist changed with this release; run `doctor --fix` or `shim-update --all`. Hosts are refused until you do — see [Upgrading](../README.md#upgrading) |
| `SECURITY: the login shell … answered` | The key that connected has no forced command. Either no shim is installed, or ssh authenticated with a different key than the enrolled one. Re-enrol `--hardened` and check `doctor` |
| `is the Docker API on this host` | `curl` never reaches the Docker proxy, however `curl_targets` is written; use `docker` |
| `is not a permitted curl target` | `curl_targets` entries are `host:port`; a bare host means ports 80 and 443 only |
| `no permitted paths configured` | `--allow-exec` needs at least one `--exec-path` at enrolment |
| `production is true, but:` | A client-only or `~/.ssh/config` host in a config with `defaults.production: true` |
| `the enrolled key STILL authenticates` (from `unenroll`) | Cleanup ran but the key line is still in an `authorized_keys` somewhere — an account other than the one enrolment used, or a `~/.ssh/authorized_keys2`. Remove it by hand; the host stays in `hosts.yaml` until the probe fails |
| `no passwordless sudo via this route` (from `unenroll`) | The user-level cleanup ran, but hardened state needs root. Re-run with `--via <admin alias>` or `--admin-user` |
| `Permission denied (publickey)` | Remote `~/.ssh` must be `700`, `authorized_keys` `600` |
| `Too many authentication failures` | Add `IdentitiesOnly yes` to `~/.ssh/config` |
| Agent reports a parse error | Something wrote to stdout, which carries JSON-RPC; check stderr |

## Using an ssh config kept elsewhere

`SAFEREACH_SSH_CONFIG=/path/to/ssh_config` makes every `ssh` and `scp` safereach runs use
that file instead of `~/.ssh/config`. OpenSSH resolves `~` from the passwd entry, not
`$HOME`, so this is the only way to point enrolment at a config kept elsewhere. The
end-to-end test rig relies on it to stay away from your real config.

## Reading the audit logs

Two logs, and the one on the host is authoritative.

- **Host:** `/var/log/safereach.jsonl` (hardened) or `~/.safereach-shim.jsonl` (plain
  enrol). One JSON line per request as the shim received it: decision, argv, exit code,
  the wrapper it ran under, and for refusals the reason. Append-only in hardened mode.
- **Operator's machine:** `~/.local/state/safereach/audit.jsonl`. What the server believes
  it sent, including client-side refusals that never reached a host.

A refusal in the host log with no matching entry on the operator's side means something
other than this server used the key. That is what the log is for.
