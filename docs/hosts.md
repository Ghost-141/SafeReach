# Managing hosts

Listing what is configured, how hosts are named, what the three enrolment modes give
you, and how to read logs that an application writes to a file inside a container.
Setting hosts up in the first place is covered in the README's
[Setting up hosts](../README.md#setting-up-hosts).

## Listing your hosts

```bash
safereach hosts           # a table on the terminal
safereach hosts --json    # the same rows on stdout, for scripts
```

```
Hosts (3) — ~/.config/safereach/hosts.yaml
Alias           Address            User   Port   Mode          Description
──────────────────────────────────────────────────────────────────────────
prod-web        10.0.1.5           diag   2222   enrolled      diag@10.0.1.5 (hardened)
langfuse-prod   203.0.113.7        diag   22     enrolled      primary postgres
lab             ~/.ssh/config:            22     client-only   throwaway
                lab-box
```

It reads `hosts.yaml` and nothing else — no network, works offline. **Mode** is what the
file alone can prove: `enrolled` (explicit key, remote validator required), `ssh-config`
(resolves through `~/.ssh/config`, so it connects as your own account), or `client-only`
(`require_shim: false`, no host-side control at all). Whether an enrolled host is
actually *hardened* is decided on the far end; `safereach doctor` reports that.

The address is shown here on purpose. The MCP tool `list_hosts` hides it from the agent,
which never needs to know where a host is; you wrote the file, and this is your view of it.

## Naming your hosts

The alias is what the agent types, what `list_hosts` shows, and what every audit record is
keyed on — so enrolment asks:

```
Choose a name for each host (Enter accepts the suggestion):

  deploy@10.0.1.5         [web-01]          > prod-web
  bdren@203.96.189.202    [203.96.189.202]  > langfuse-prod
```

Suggestions come from the `~/.ssh/config` `Host` entry, then the first DNS label
(`db.eu.internal` → `db`), then the raw address. Prompting is TTY-gated, so scripted and
CI enrolment take the suggestion and never block.

```bash
safereach enroll web-01 --name prod-web        # name a single host
safereach enroll --all --names names.yaml      # from a file
safereach enroll --all --no-prompt             # take the suggestions
```

Rename at any time — **local only, no re-enrolment**, because the remote host never knew
the name:

```bash
safereach rename 203.96.189.202 langfuse-prod
safereach rename --interactive
safereach rename --write-names names.yaml      # dump for editing
safereach rename --from names.yaml             # apply
```

A names file may be written either way round; the direction is resolved against the hosts
actually known, falling back to which side parses as an address. When neither settles it
the entry is **refused** rather than guessed — a mapping read backwards points the agent
at the wrong machine.

Every host also carries a stable `id`, derived from `hostname:port` and recorded in each
audit entry alongside the name. Renaming therefore does not sever a host's history —
which matters, because a rename usually happens exactly when something has gone wrong and
you want that history.

## Mode comparison

| | `discover` | `enroll` | `enroll --hardened` |
|---|---|---|---|
| Remote validator behind a forced command | ✗ | ✓ | ✓ |
| Agent's key can get a shell | yes | **no** | **no** |
| Unprivileged dedicated account | ✗ | ✗ | ✓ |
| Docker via read-only proxy | ✗ | ✗ | ✓ |
| Shim rewritable by the account | — | yes | **no** |
| Append-only audit log | ✗ | ✗ | ✓ |
| Needs sudo | no | no | once |

`list_hosts` reports each host's mode, so the agent — and you — can see it.
`defaults.production: true` in `hosts.yaml` refuses to start with any `discover`-mode
host, so the left column cannot reach a production fleet by accident.

**The insight behind `enroll`:** `command=` is a per-key option in a user-owned file. It
needs no root. The forced command — the actual security boundary — costs nothing to
install, so there is no reason to run without it.

## Container inspection

`docker logs` covers apps logging to stdout. When a framework writes to a file instead
(`/app/storage/logs/laravel.log`), `run_in_container` runs a read-only command inside:

```
run_in_container("app-1", "tail -n 200 /app/storage/logs/laravel.log")
```

Enable it at enrolment, naming the container and the directory the agent may read:

```bash
safereach enroll myserver --hardened --allow-exec \
    --exec-container app-1 --exec-path /app/storage/logs/
```

**Off by default.** Both lists land in the host's root-owned policy; nothing on the wire
can widen them, and with no `--exec-path` the content-reading commands refuse everything.
Inside the container the agent gets `cat`, `tail`, `head` and `grep` under the listed
prefixes, and `ls`, `stat`, `df` and `ps` for names and numbers. No shell, no TTY, no
stdin.

What keeps that safe, and the tradeoff it carries on the Docker proxy, is in
[SECURITY.md](../SECURITY.md#container-inspection-and-what-keeps-it-safe).
