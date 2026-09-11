"""The root-owned state enrolment leaves on a host, and how it gets there.

These are the 0.3.0 controls: file modes that keep the policy's HMAC key away from other
local users, an HMAC key that never appears on a command line, a Docker proxy that is not
on a TCP port, an sshd Match block that duplicates the key-line restrictions, and a sudoers
file whose binary paths are resolved on the host it is written to.

The remote scripts cannot run here (they need root and sshd), so what is tested is the
text that is sent: the lines that carry the guarantee, and the absence of the ones that
used to undermine it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from safereach import cli
from safereach.cli import (
    DOCKER_PROXY_IMAGE,
    DOCKER_PROXY_SCRIPT,
    ELEVATED_RECIPES,
    HARDENED_SCRIPT,
    REMOTE_SETUP,
    SSHD_MATCH_SNIPPET,
    _shim_config,
    _sudoers_block,
)


def _hardened(**kw: str) -> str:
    base = dict(
        diag_user="diag",
        strip="",
        authkey="command=x ssh-ed25519 AAAA test",
        sudoers_block=_sudoers_block(["dmesg-recent"]),
        sshd_match=SSHD_MATCH_SNIPPET,
        upload_dir="/tmp/safereach.abc123",
    )
    base.update(kw)
    return HARDENED_SCRIPT.format(**base)


def _provision() -> str:
    return REMOTE_SETUP.format(
        user="diag",
        authkey="command=x ssh-ed25519 AAAA test",
        upload_dir="/tmp/safereach.abc123",
        sudoers_block=_sudoers_block(["dmesg-recent"]),
        sshd_match=SSHD_MATCH_SNIPPET,
    )


@pytest.mark.parametrize("script", [_hardened(), _provision()], ids=["hardened", "provision"])
def test_policy_file_is_group_readable_only(script: str) -> None:
    """The policy holds the HMAC key for the secret digests. 0644 let any local user
    brute-force weak values offline; 0640 root:diag lets the shim read it and nobody else."""
    assert '-g "$DIAG_USER" -m 0640' in script
    assert "config.json" in script.split("-m 0640")[1].splitlines()[0]
    assert "-m 0644" not in script.split("config.json")[0].splitlines()[-1]


@pytest.mark.parametrize("script", [_hardened(), _provision()], ids=["hardened", "provision"])
def test_uploads_come_from_a_private_temp_dir_not_fixed_tmp_names(script: str) -> None:
    assert "/tmp/.safereach-shim.upload" not in script
    assert "/tmp/safereach-shim.upload" not in script
    assert 'UPLOAD_DIR="/tmp/safereach.abc123"' in script
    assert 'rm -rf "$UPLOAD_DIR"' in script


@pytest.mark.parametrize("script", [_hardened(), _provision()], ids=["hardened", "provision"])
def test_sshd_match_block_is_validated_before_it_is_kept(script: str) -> None:
    """A broken sshd config on a production host is worse than a missing hardening."""
    assert "Match User $DIAG_USER" in script
    for directive in (
        "MaxSessions 4",
        "AllowTcpForwarding no",
        "AllowAgentForwarding no",
        "PermitTTY no",
    ):
        assert directive in script
    assert "sshd -t" in script
    assert 'sshd -T -C "user=$DIAG_USER"' in script
    # the failure branch removes the file rather than leaving sshd unable to restart
    assert "rm -f /etc/ssh/sshd_config.d/zz-safereach-diag.conf" in script
    # and the drop-in is only written where sshd actually includes the directory
    assert "grep -qsE '^\\s*Include\\s+/etc/ssh/sshd_config\\.d/'" in script


def test_sudoers_resolves_binaries_on_the_host() -> None:
    """Hosts disagree about /bin/dmesg vs /usr/bin/dmesg; sudoers needs the real one."""
    block = _sudoers_block(["dmesg-recent", "dmesg-all"])
    assert 'BIN_0="$(command -v dmesg || true)"' in block
    assert "SUDOERS=missing-dmesg" in block  # a host without the binary fails loudly
    assert "{BIN:dmesg}" in block and 'sed "s|{BIN:dmesg}|$BIN_0|"' in block
    assert "NOPASSWD: {BIN:dmesg} --level=err\\,crit\\,alert\\,emerg --ctime" in block
    assert "NOPASSWD: {BIN:dmesg} --ctime" in block
    assert "visudo -cf" in block
    assert "*" not in block.split("printf")[1].split("visudo")[0].replace("'%s\\n'", "")


def test_sudoers_none_when_no_recipes() -> None:
    assert _sudoers_block([]) == 'echo "SUDOERS=none"'


def test_recipes_use_bare_names_the_shim_resolves() -> None:
    """Absolute paths in the recipe and the sudoers line can disagree; bare names cannot."""
    for argv in ELEVATED_RECIPES.values():
        assert argv[:2] == ["sudo", "-n"]
        assert not argv[2].startswith("/"), argv


def test_provision_policy_uses_the_same_recipe_table(tmp_path: Path) -> None:
    from safereach.config import HostConfig, Settings

    host = HostConfig(
        alias="h", hostname="h", user="diag", key="k", elevated=["dmesg-recent", "nope"]
    )
    conf = _shim_config(host, Settings())
    assert conf["elevated"] == {"dmesg-recent": ELEVATED_RECIPES["dmesg-recent"]}


def test_digest_key_never_appears_on_a_command_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """sudo logs its argv to the journal, and the diag account reads the journal."""
    seen: dict[str, object] = {}

    def fake_run(cmd, **kw):  # noqa: ANN001
        seen["cmd"] = cmd
        seen["input"] = kw.get("input")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    key = "deadbeef" * 8
    cli._discover_env_digests("host", key)
    assert key not in " ".join(seen["cmd"])  # type: ignore[arg-type]
    assert f'KEY="{key}"' in seen["input"]  # type: ignore[operator]


def test_docker_proxy_is_pinned_by_digest_and_prefers_a_unix_socket() -> None:
    script = DOCKER_PROXY_SCRIPT.format(
        proxy_port=2375,
        post=0,
        exec_flag=0,
        diag_user="diag",
        image=DOCKER_PROXY_IMAGE,
        socket="/run/safereach/docker.sock",
    )
    assert "@sha256:" in DOCKER_PROXY_IMAGE and ":latest" not in DOCKER_PROXY_IMAGE
    assert "tecnativa/docker-socket-proxy >/dev/null" not in script  # no unpinned pull
    assert "bind unix@$SOCK mode 660 uid 0 gid $DIAG_GID" in script
    assert 'DOCKER_HOST="unix://$SOCK" docker version' in script  # verified before use
    assert "printf 'd %s 0750 root %s -\\n'" in script  # survives reboot
    # the TCP fallback is still owner-filtered where iptables exists
    assert '-m owner ! --uid-owner "$DIAG_USER" -j REJECT' in script
    assert "PROXY_MODE=$MODE" in script and "DOCKER_HOST=unix://$SOCK" in script


def test_hardened_script_reports_what_it_did() -> None:
    script = _hardened()
    for marker in ("SUDOERS=", "SSHD_MATCH=", "AUDIT=", "SHIM=", "GROUPS="):
        assert marker in script
