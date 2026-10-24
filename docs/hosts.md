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

## Removing a host

```bash
safereach unenroll myserver --yes                         # host cleaned, entry dropped
safereach unenroll myserver --yes --remove-user --purge-log
safereach unenroll myserver --yes --local-only            # the host no longer exists
safereach unenroll myserver --dry-run                     # show the scripts, run nothing
```

`unenroll` reverses enrolment in the order that keeps every intermediate state safe, then
**proves the enrolled key no longer authenticates** before it drops the host from
`hosts.yaml`. A host that still answers the key stays in the file, marked as a problem,
so nothing is forgotten while it can still be reached.

What comes out, as the connecting account: our line in `authorized_keys`, the user-local
shim and policy. As root, when passwordless sudo works over the same route enrolment
used: the sshd drop-in (removed, then `sshd -t`, then reload — never a reload of an
invalid config), the sudoers entry, the Docker proxy with its socket, tmpfiles entry and
TCP-fallback firewall rule, `/usr/local/bin/safereach-shim`, `/etc/safereach`, and the
diag account's key line.

Two things are **kept by default**, because removal is exactly when someone may want
them: the diag account (`--remove-user` deletes it) and the host's append-only audit log
(`--purge-log` deletes it; otherwise its append-only flag is cleared and it stays at
`/var/log/safereach.jsonl`). The local key under `~/.config/safereach/keys` is shared by
every host and is never removed.

Reaching the host uses your own access, never the enrolled key — the enrolled key can
only invoke the shim. `--via <ssh alias>` names the route explicitly; without it the
command tries the host's own alias in `~/.ssh/config`, then `--admin-user@hostname`.

## Log sources

Enrolment looks for where each server's logs actually are and asks which ones the agent
should read:

```
web-1 — log sources found
   1 [x] syslog    file    /var/log/syslog*                 written 1m ago  48.0 MB
   2 [x] shop-api  file    /opt/shop/api/logs/*.log*        node (pm2-app.service)  written 2m ago  1.2 GB
   3 [x] pm2-app   file    /home/app/.pm2/logs/*.log*       pm2  written 2m ago  3.1 MB
   4 [ ] pm2-app   journal pm2-app.service                  empty — this service logs to files, not journald
   5 [x] nginx     file    /var/log/nginx/*.log*            written 1m ago  210.4 MB
   6 [ ] api       docker  container api                    docker logs
      skipped: /opt/: log path '/opt/' is too broad — it would expose far more than logs
Toggle with numbers (e.g. `2 5`), add a directory with `a /path/to/logs/ [name]`, `n` to tick nothing, Enter to accept.
```

The scan runs on the host over your own SSH access (under `sudo` for `--hardened`). It
combines a catalogue of well-known locations with what the host is doing right now: files
running processes hold open, PM2's log directories, services whose journal is empty, and
containers. It reports names, sizes and timestamps only — no file is opened for reading,
no command line or environment is read, and `pm2` itself is never run. Anything written
in the last 24 hours is pre-ticked.

The ticked sources are written into the host's own policy and into `hosts.yaml` as
`log_sources`. The agent reads them by name — `read_logs(source="shop-api",
grep="timeout|ECONNRESET", since="2h")` — and the host resolves the name to files, a
container or a unit; the agent never sends a path. A file source's directory is also
readable with `tail` and `grep`. On `--hardened` hosts the diag group is granted read
access to each chosen directory with POSIX ACLs (default ACLs too, so rotated files stay
readable); `unenroll` and `logs remove` take the grants back.

```bash
safereach enroll web-1 --accept-detected          # take everything the scan finds
safereach enroll web-1 --no-discover              # skip the scan
safereach enroll web-1 --log-source api=/opt/shop/api/logs/:*.log* \
                       --log-source worker=docker:worker

safereach logs web-1 --check                      # list sources; read one line from each
safereach logs scan web-1                         # rescan; new candidates, same checklist
safereach logs add web-1 billing=journal:billing.service
safereach logs remove web-1 billing
```

`safereach doctor` points out hosts with no log sources.

## Application log directories

`tail`, `head`, `grep`, `zgrep`, `ls` and `stat` read under `/var/log/` everywhere. An
app run by PM2, supervisor or a plain `node app.js >> logs/app.log` writes somewhere
else, and its systemd unit's journal is empty (`-- No entries --`). Name the directory at
enrolment and the agent can read it too:

```bash
safereach enroll myserver --log-path /opt/app/logs/ --log-path /home/app/.pm2/logs/
```

The directories go into the host's own policy and into `hosts.yaml` as `log_paths`;
re-enrolling keeps them, so `--log-path` only ever adds. The agent sees them in
`describe_commands` as `application_log_paths`.

Each directory must be a leaf where logs live. Broad roots (`/`, `/opt/`, `/srv/`,
`/home/<user>/`, `/var/lib/`), anything under `/etc`, `/proc`, `/sys` or container storage,
and anything on the protected-path list are refused, by the CLI and again by the shim
reading its own policy. The protected-path list still applies inside the directory, so a
`.env` that sits next to the logs stays unreadable. On the host every path is also
checked after resolving symlinks: `logs/x.log -> ../.env` is refused.

The account still needs read permission on the files. In plain mode it is your own
account, which usually owns the app's logs already; in hardened mode grant the diag
group read access to the directory.

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
