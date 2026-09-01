#!/usr/bin/env bash
#
# Provision one host for safereach. Run AS ROOT ON THE TARGET HOST.
#
# `safereach provision <host>` does all of this for you over SSH; this script exists
# for hosts you configure by hand, or through a configuration-management system that
# wants a single idempotent command.
#
#   sudo ./install.sh --pubkey ~/agent-diag.pub --shim ./safereach-shim
#
# What it does, and why:
#
#   * Creates an unprivileged `diag` user with no sudo. The validator is the primary
#     control; this account is the backstop for when the validator is wrong.
#
#   * Adds it to `systemd-journal` and `adm`. These two groups are what make the host
#     legible at all — without systemd-journal, journalctl returns only this user's own
#     entries, which is effectively nothing, and `adm` covers /var/log/syslog, auth.log
#     and nginx logs.
#
#   * Does NOT add it to `docker`. That group is equivalent to root on the host
#     (`docker run -v /:/host` mounts the filesystem), which is the entire reason Docker
#     is reached through a read-only socket proxy instead. See --docker-host.
#
#   * Pins the key to a forced command in authorized_keys, so it can invoke nothing but
#     the shim whatever string is sent.
#
set -euo pipefail

DIAG_USER="diag"
SHIM_SRC=""
PUBKEY_FILE=""
CONF_FILE=""
DOCKER_HOST_VALUE=""
CURL_TARGETS='["localhost","127.0.0.1"]'

SHIM=/usr/local/bin/safereach-shim
CONF_DIR=/etc/safereach
LOG=/var/log/safereach.jsonl

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \?//'
    cat <<'EOF'

Options:
  --pubkey FILE       Public key to authorise (required)
  --shim FILE         Built safereach-shim to install (required; see shim/build.py)
  --user NAME         Diagnostic account name (default: diag)
  --config FILE       Pre-built /etc/safereach/config.json
  --docker-host URL   e.g. tcp://127.0.0.1:2375 — a READ-ONLY socket proxy
  --curl-targets JSON JSON array of permitted curl hosts (default: localhost only)
  -h, --help          This message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pubkey)        PUBKEY_FILE="$2"; shift 2 ;;
        --shim)          SHIM_SRC="$2"; shift 2 ;;
        --user)          DIAG_USER="$2"; shift 2 ;;
        --config)        CONF_FILE="$2"; shift 2 ;;
        --docker-host)   DOCKER_HOST_VALUE="$2"; shift 2 ;;
        --curl-targets)  CURL_TARGETS="$2"; shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -n "$PUBKEY_FILE" && -f "$PUBKEY_FILE" ]] || { echo "--pubkey is required and must exist" >&2; exit 2; }
[[ -n "$SHIM_SRC"   && -f "$SHIM_SRC"   ]] || { echo "--shim is required and must exist" >&2; exit 2; }

command -v python3 >/dev/null || { echo "python3 is required on the target host" >&2; exit 1; }

# --- account ------------------------------------------------------------------------

if ! id -u "$DIAG_USER" >/dev/null 2>&1; then
    useradd -r -m -s /bin/bash "$DIAG_USER"
    echo "created user $DIAG_USER"
else
    echo "user $DIAG_USER already exists"
fi

for grp in systemd-journal adm; do
    if getent group "$grp" >/dev/null 2>&1; then
        usermod -aG "$grp" "$DIAG_USER"
        echo "added $DIAG_USER to $grp"
    else
        echo "WARNING: group $grp does not exist on this host; some logs will be unreadable" >&2
    fi
done

# --- shim ---------------------------------------------------------------------------

install -m 0755 -o root -g root "$SHIM_SRC" "$SHIM"
echo "installed $SHIM ($("$SHIM" --version))"

mkdir -p "$CONF_DIR"
if [[ -n "$CONF_FILE" ]]; then
    install -m 0644 -o root -g root "$CONF_FILE" "$CONF_DIR/config.json"
else
    # The host owns its own policy. What the MCP server believes about this host is
    # irrelevant to what this host permits, so a compromised server cannot widen the
    # allowlist by sending a different config — it never sends one.
    tmp=$(mktemp)
    {
        printf '{\n'
        printf '  "curl_targets": %s,\n' "$CURL_TARGETS"
        [[ -n "$DOCKER_HOST_VALUE" ]] && printf '  "docker_host": "%s",\n' "$DOCKER_HOST_VALUE"
        printf '  "command_timeout": 30,\n'
        printf '  "max_output_bytes": 65536,\n'
        printf '  "elevated": {}\n'
        printf '}\n'
    } > "$tmp"
    install -m 0644 -o root -g root "$tmp" "$CONF_DIR/config.json"
    rm -f "$tmp"
fi
echo "wrote $CONF_DIR/config.json"

# --- authorized_keys ----------------------------------------------------------------

HOME_DIR=$(getent passwd "$DIAG_USER" | cut -d: -f6)
AUTH="$HOME_DIR/.ssh/authorized_keys"
OPTS='command="/usr/local/bin/safereach-shim",no-port-forwarding,no-agent-forwarding,no-pty,no-X11-forwarding,no-user-rc'

mkdir -p "$HOME_DIR/.ssh"
touch "$AUTH"
# Replace any previous safereach-shim entry rather than appending a duplicate, so re-running
# this script is idempotent.
grep -v 'safereach-shim' "$AUTH" > "$AUTH.new" 2>/dev/null || true
printf '%s %s\n' "$OPTS" "$(cat "$PUBKEY_FILE")" >> "$AUTH.new"
mv "$AUTH.new" "$AUTH"

chown -R "$DIAG_USER":"$DIAG_USER" "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"
chmod 600 "$AUTH"
echo "pinned key to forced command in $AUTH"

# --- audit log ----------------------------------------------------------------------

touch "$LOG"
chown "$DIAG_USER" "$LOG"
chmod 0640 "$LOG"

cat <<EOF

Done. $DIAG_USER groups: $(id -nG "$DIAG_USER")

Verify from your workstation:
  safereach doctor

And confirm the boundary holds — this must be REFUSED:
  ssh $DIAG_USER@<host> "rm -rf /tmp/x"

Optional but strongly recommended for any host that matters — a read-only Docker socket
proxy, so a validator bug cannot become host root:

  docker run -d --name dsp --restart unless-stopped -p 127.0.0.1:2375:2375 \\
    -e CONTAINERS=1 -e IMAGES=1 -e NETWORKS=1 -e VOLUMES=1 -e POST=0 -e EXEC=0 \\
    -v /var/run/docker.sock:/var/run/docker.sock:ro tecnativa/docker-socket-proxy

  then re-run with --docker-host tcp://127.0.0.1:2375
EOF
