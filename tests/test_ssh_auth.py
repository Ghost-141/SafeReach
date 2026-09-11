"""Which key the server actually offers.

asyncssh tries every agent identity BEFORE `client_keys`. On a plain-enrol host the
operator's own key is authorised for the same account, so the agent's copy of it wins —
and that key has no forced command. Pinning `agent_identities` to the enrolled key is
what keeps "the key in hosts.yaml" and "the key that logged in" the same thing.
"""

from __future__ import annotations

from pathlib import Path

import asyncssh
import pytest

from safereach.config import Defaults, HostConfig
from safereach.ssh import SSHPool, _public_identity


@pytest.fixture
def keypair(tmp_path: Path) -> Path:
    key = asyncssh.generate_private_key("ssh-ed25519")
    priv = tmp_path / "id_ed25519_safereach"
    key.write_private_key(str(priv))
    key.write_public_key(str(priv) + ".pub")
    priv.chmod(0o600)
    return priv


def test_explicit_key_pins_the_agent_to_that_identity(keypair: Path) -> None:
    host = HostConfig(alias="h", hostname="10.0.0.1", user="diag", key=str(keypair))
    options = SSHPool(Defaults())._auth_options(host)
    assert options["client_keys"] == [str(keypair)]
    identities = options["agent_identities"]
    assert len(identities) == 1
    expected = asyncssh.read_public_key(str(keypair) + ".pub")
    assert identities[0].public_data == expected.public_data


def test_identity_is_derived_when_the_pub_file_is_missing(keypair: Path) -> None:
    Path(str(keypair) + ".pub").unlink()
    identity = _public_identity(keypair)
    assert identity is not None
    assert (
        identity.public_data
        == asyncssh.read_private_key(str(keypair)).convert_to_public().public_data
    )


def test_no_agent_means_no_identities_and_no_agent_path(keypair: Path) -> None:
    host = HostConfig(
        alias="h", hostname="10.0.0.1", user="diag", key=str(keypair), use_agent=False
    )
    options = SSHPool(Defaults())._auth_options(host)
    assert options["agent_path"] is None
    assert "agent_identities" not in options


def test_ssh_config_mode_without_a_key_stays_unpinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """That mode is 'whatever `ssh alias` uses', by design; nothing to pin to."""
    cfg = tmp_path / "config"
    cfg.write_text("Host lab\n  HostName 10.0.0.2\n", encoding="utf-8")
    monkeypatch.setattr(
        Path, "expanduser", lambda self: cfg if str(self) == "~/.ssh/config" else self
    )
    host = HostConfig(alias="lab", ssh_config_host="lab")
    options = SSHPool(Defaults())._auth_options(host)
    assert "agent_identities" not in options
    assert "client_keys" not in options
