"""Enrolment: the remote half, executed locally against a throwaway HOME.

`enroll` appends to a real `~/.ssh/authorized_keys` on a real server. Getting that wrong
would lock someone out of their own machine, so the script is run here for real — with
`HOME` pointed at a temp directory — rather than asserted about in the abstract.

What is *not* covered here is sshd actually honouring the `command=` restriction. That is
sshd's behaviour, not ours, and verifying it needs a live server; `enroll` therefore
checks it at run time and refuses to record a host where an escape attempt succeeds.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from safereach.cli import ENROLL_SCRIPT, KEY_COMMENT, LEGACY_KEY_COMMENTS, _strip_markers_sh

EXISTING_KEYS = """\
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExistingLaptopKey me@laptop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQColdkey backup@ops
command="/usr/bin/borg serve",restrict ssh-ed25519 AAAAC3NzaBorgKey borg@backup
"""

AUTHKEY_LINE = (
    'command="{home}/.local/bin/safereach-shim",no-pty,no-port-forwarding,'
    "no-agent-forwarding,no-X11-forwarding,no-user-rc "
    f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAADiagKey {KEY_COMMENT}"
)


@pytest.fixture
def fake_home(tmp_path: Path, shim_path: Path) -> Path:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(EXISTING_KEYS, encoding="utf-8")

    shutil.copy(shim_path, Path("/tmp/.safereach-shim.upload"))
    Path("/tmp/.safereach-shim.conf.upload").write_text(
        json.dumps({"curl_targets": ["localhost"]}), encoding="utf-8"
    )
    return home


def run_enroll_script(home: Path) -> subprocess.CompletedProcess:
    script = ENROLL_SCRIPT.format(
        strip=_strip_markers_sh('"$HOME/.ssh/.ak.new"'),
        authkey=AUTHKEY_LINE.format(home=home),
    )
    return subprocess.run(
        ["bash", "-s"],
        input=script,
        capture_output=True,
        text=True,
        env={"HOME": str(home), "PATH": f"/usr/bin:/bin:{Path(sys.executable).parent}"},
        check=False,
    )


def test_enrolment_installs_without_root(fake_home: Path) -> None:
    proc = run_enroll_script(fake_home)
    assert proc.returncode == 0, proc.stderr

    shim = fake_home / ".local" / "bin" / "safereach-shim"
    assert shim.is_file()
    assert shim.stat().st_mode & 0o111, "shim must be executable"
    assert (fake_home / ".config" / "safereach-shim" / "config.json").is_file()
    assert "SHIM=" in proc.stdout and "HOME=" in proc.stdout


def test_existing_authorized_keys_survive(fake_home: Path) -> None:
    """The regression that would matter most: never break someone's own SSH access."""
    run_enroll_script(fake_home)
    content = (fake_home / ".ssh" / "authorized_keys").read_text(encoding="utf-8")

    for line in EXISTING_KEYS.strip().splitlines():
        assert line in content, f"pre-existing key was lost: {line[:50]}"
    assert KEY_COMMENT in content, "our key was not added"


def test_reenrolment_replaces_rather_than_appends(fake_home: Path) -> None:
    run_enroll_script(fake_home)
    run_enroll_script(fake_home)
    run_enroll_script(fake_home)

    content = (fake_home / ".ssh" / "authorized_keys").read_text(encoding="utf-8")
    assert content.count(KEY_COMMENT) == 1, "re-enrolling duplicated the key entry"
    for line in EXISTING_KEYS.strip().splitlines():
        assert line in content


def test_permissions_are_tightened(fake_home: Path) -> None:
    run_enroll_script(fake_home)
    assert (fake_home / ".ssh").stat().st_mode & 0o777 == 0o700
    assert (fake_home / ".ssh" / "authorized_keys").stat().st_mode & 0o777 == 0o600
    assert (
        fake_home / ".config" / "safereach-shim" / "config.json"
    ).stat().st_mode & 0o777 == 0o600


def test_installed_shim_reads_its_user_local_config(fake_home: Path) -> None:
    """The shim must find config under ~/.config — that path is what needs no root."""
    run_enroll_script(fake_home)
    shim = fake_home / ".local" / "bin" / "safereach-shim"

    proc = subprocess.run(
        [sys.executable, str(shim)],
        capture_output=True,
        text=True,
        env={
            "HOME": str(fake_home),
            "PATH": "/usr/bin:/bin",
            "SSH_ORIGINAL_COMMAND": '@run ["curl","http://localhost/"]',
        },
        check=False,
    )
    # localhost is in the config written above, so this must get past the target check
    # and fail on the connection instead of on policy.
    assert "not a permitted curl target" not in proc.stderr

    proc = subprocess.run(
        [sys.executable, str(shim)],
        capture_output=True,
        text=True,
        env={
            "HOME": str(fake_home),
            "PATH": "/usr/bin:/bin",
            "SSH_ORIGINAL_COMMAND": '@run ["curl","http://evil.example/"]',
        },
        check=False,
    )
    assert proc.returncode != 0
    assert "not a permitted curl target" in proc.stderr


def test_forced_command_uses_an_absolute_path(fake_home: Path) -> None:
    """`command=` is not shell-expanded, so `~` would silently never match."""
    entry = AUTHKEY_LINE.format(home=fake_home)
    assert entry.startswith('command="/')
    assert "~" not in entry.split(" ")[0]


def test_restriction_options_are_present() -> None:
    entry = AUTHKEY_LINE.format(home="/home/x")
    for option in (
        "no-pty",  # blocks interactive escapes
        "no-port-forwarding",  # blocks using the host as a network pivot
        "no-agent-forwarding",  # stops the key reaching further hosts
        "no-X11-forwarding",
    ):
        assert option in entry, f"missing restriction: {option}"


# --------------------------------------------------------------------------------------
# How enrolment records a host
# --------------------------------------------------------------------------------------


def test_user_at_host_is_not_used_as_an_alias() -> None:
    """`user@host` works for the ssh CLI but not as an addressable alias.

    asyncssh takes the connect target literally, so `user@host` would be looked up as a
    DNS name and fail. The user part has to move into its own field.
    """
    from safereach.cli import _yaml_key

    assert _yaml_key("deploy@myserver.com") == "myserver.com"
    assert _yaml_key("root@10.0.1.5") == "10.0.1.5"
    assert _yaml_key("web-01") == "web-01"


def test_explicit_host_config_round_trips(tmp_path: Path) -> None:
    """What enroll writes for a non-ssh_config host must load and be connectable."""
    from safereach.config import load_settings

    path = tmp_path / "hosts.yaml"
    path.write_text(
        "hosts:\n"
        "  myserver.com:\n"
        "    hostname: myserver.com\n"
        "    user: deploy\n"
        "    port: 2222\n"
        f"    key: {tmp_path / 'k'}\n"
        "    allow: [df]\n",
        encoding="utf-8",
    )
    host = load_settings(path).host("myserver.com")
    assert host.hostname == "myserver.com"
    assert host.user == "deploy"
    assert not host.uses_ssh_config
    assert host.ssh_port(load_settings(path).defaults) == 2222


# --------------------------------------------------------------------------------------
# Identifying our own entry
# --------------------------------------------------------------------------------------


def test_a_legacy_comment_entry_is_replaced_not_duplicated(fake_home: Path) -> None:
    """The bug this guards against shipped, and it is the worst kind: silent.

    Our entry used to be found by its comment. The comment is baked into the keypair at
    generation time, so after the project was renamed a key generated earlier still
    carried the old comment — `grep -v safereach-enrolled` matched nothing. Re-enrolment
    appended a duplicate, and a revoke would have found nothing to remove and reported
    success. Matching on the key material instead cannot drift that way.
    """
    auth = fake_home / ".ssh" / "authorized_keys"
    legacy = (
        'command="/x/diag-shim",no-pty ssh-ed25519 '
        "AAAAC3NzaC1lZDI1NTE5AAAADiagKey " + LEGACY_KEY_COMMENTS[0]
    )
    auth.write_text(EXISTING_KEYS + legacy + "\n", encoding="utf-8")

    run_enroll_script(fake_home)
    content = auth.read_text(encoding="utf-8")

    ours = [
        line
        for line in content.splitlines()
        if KEY_COMMENT in line or any(c in line for c in LEGACY_KEY_COMMENTS)
    ]
    assert len(ours) == 1, f"expected one entry of ours, got {len(ours)}:\n{content}"
    for line in EXISTING_KEYS.strip().splitlines():
        assert line in content, "an unrelated key was lost"


def test_markers_prefer_key_material_over_the_comment() -> None:
    """The key material is the identity of the grant; a comment is a label."""
    from safereach.cli import _authorized_key_markers

    markers = _authorized_key_markers()
    assert markers, "no markers produced"
    assert markers[0].startswith("AAAA"), "the base64 key blob must be tried first"
    assert KEY_COMMENT in markers
    assert all(c in markers for c in LEGACY_KEY_COMMENTS)
