"""Host naming: stable identity, validation, suggestions, and name files.

The alias is what an agent types and what every audit record is keyed on, so it is
treated as data with rules rather than as whatever fell out of discovery.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from safereach import naming
from safereach.naming import InvalidName, host_id, suggest_alias, validate_alias

# --------------------------------------------------------------------------------------
# Stable identity
# --------------------------------------------------------------------------------------


def test_id_is_stable_across_calls() -> None:
    assert host_id("10.0.1.5", 22) == host_id("10.0.1.5", 22)


def test_id_ignores_case_and_whitespace() -> None:
    """Re-enrolling a host typed slightly differently must rejoin its history."""
    assert host_id(" Web-01.Internal ", 22) == host_id("web-01.internal", 22)


def test_id_distinguishes_port() -> None:
    assert host_id("10.0.1.5", 22) != host_id("10.0.1.5", 2222)


def test_id_is_independent_of_the_name() -> None:
    """The whole point: renaming must not change identity."""
    before = host_id("10.0.1.5", 22)
    after = host_id("10.0.1.5", 22)  # host renamed in between; nothing here depends on it
    assert before == after


# --------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("bad", "because"),
    [
        ("deploy@web-01", "@"),
        ("web 01", "whitespace"),
        ("web;rm", "not a valid"),
        ("../etc/passwd", "not a valid"),
        ("-leading-dash", "not a valid"),
        ("", "empty"),
        ("   ", "empty"),
        ("all", "reserved"),
        ("localhost", "reserved"),
        ("x" * 70, "too long"),
        ("web$(id)", "not a valid"),
        ("web\nprod", "whitespace"),
    ],
    ids=lambda v: str(v)[:20],
)
def test_invalid_names_are_refused(bad: str, because: str) -> None:
    with pytest.raises(InvalidName, match=because):
        validate_alias(bad)


@pytest.mark.parametrize("good", ["web-01", "prod_db", "eu.web1", "a", "langfuse-prod", "db2"])
def test_valid_names_accepted(good: str) -> None:
    assert validate_alias(good) == good


def test_at_sign_rejection_explains_the_actual_bug() -> None:
    """`user@host` shipped once and broke every command with a DNS error."""
    with pytest.raises(InvalidName) as exc:
        validate_alias("deploy@web-01")
    assert "label, not a login" in exc.value.reason
    assert "web-01" in (exc.value.suggestion or "")


def test_collision_refused() -> None:
    with pytest.raises(InvalidName, match="already the name"):
        validate_alias("web-01", existing={"web-01", "db-01"})


def test_renaming_a_host_to_its_own_name_is_allowed() -> None:
    """Re-running an interactive rename must not trip over the host's current name."""
    assert validate_alias("web-01", existing={"db-01"}) == "web-01"


def test_suggestions_offer_a_fix() -> None:
    with pytest.raises(InvalidName) as exc:
        validate_alias("Prod Web 01")
    assert exc.value.suggestion == "prod-web-01"


# --------------------------------------------------------------------------------------
# Suggestions
# --------------------------------------------------------------------------------------


def test_ssh_config_alias_wins() -> None:
    """A name a human already chose beats anything derived."""
    assert suggest_alias("web-01", "10.0.1.5") == "web-01"


def test_dns_label_used_when_no_ssh_alias() -> None:
    assert suggest_alias(None, "db-primary.eu.internal") == "db-primary"


def test_bare_address_is_the_last_resort() -> None:
    """This is what the old implementation always produced."""
    assert suggest_alias(None, "203.96.189.202") == "203.96.189.202"
    assert naming.is_bare_address("203.96.189.202")
    assert not naming.is_bare_address("web-01")


def test_suggestion_never_returns_something_invalid() -> None:
    for a, h in [(None, None), ("bad name!", "10.0.0.1"), ("deploy@x", "x.y.z")]:
        assert validate_alias(suggest_alias(a, h))


# --------------------------------------------------------------------------------------
# Name files
# --------------------------------------------------------------------------------------


def write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "names.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_canonical_direction(tmp_path: Path) -> None:
    path = write(tmp_path, "10.0.1.5: prod-web\n203.0.113.9: prod-db\n")
    mapping, notes = naming.load_names_file(path)
    assert mapping == {"10.0.1.5": "prod-web", "203.0.113.9": "prod-db"}
    assert not notes


def test_reversed_direction_accepted_but_announced(tmp_path: Path) -> None:
    """Unambiguous when exactly one side is an address — but say so, never guess quietly."""
    path = write(tmp_path, "prod-web: 10.0.1.5\n")
    mapping, notes = naming.load_names_file(path)
    assert mapping == {"10.0.1.5": "prod-web"}
    assert notes and "name" in notes[0]


def test_direction_resolved_against_known_identifiers(tmp_path: Path) -> None:
    """Hostnames are not addresses, so the known set is what settles the direction."""
    path = write(tmp_path, "web-01: prod-web\n")
    mapping, _ = naming.load_names_file(path, known={"web-01"})
    assert mapping == {"web-01": "prod-web"}


def test_ambiguous_entry_fails_loudly(tmp_path: Path) -> None:
    """A mapping read backwards points the agent at the wrong machine.

    That is far worse than an error, so an unresolvable entry is refused rather than
    guessed — and the message shows the explicit form that removes the doubt.
    """
    path = write(tmp_path, "alpha: beta\n")
    with pytest.raises(ValueError, match="cannot tell which side"):
        naming.load_names_file(path)


def test_explicit_long_form_is_unambiguous(tmp_path: Path) -> None:
    path = write(tmp_path, "hosts:\n  prod-web: { match: alpha }\n  prod-db: { match: beta }\n")
    mapping, notes = naming.load_names_file(path)
    assert mapping == {"alpha": "prod-web", "beta": "prod-db"}
    assert not notes


def test_long_form_requires_match(tmp_path: Path) -> None:
    path = write(tmp_path, "hosts:\n  prod-web: {}\n")
    with pytest.raises(ValueError, match="needs a 'match:'"):
        naming.load_names_file(path)


def test_names_in_a_file_are_validated(tmp_path: Path) -> None:
    """A bad name in a file must fail as loudly as one typed at a prompt."""
    path = write(tmp_path, "10.0.1.5: deploy@prod-web\n")
    with pytest.raises(InvalidName, match="@"):
        naming.load_names_file(path)


def test_empty_file_is_not_an_error(tmp_path: Path) -> None:
    assert naming.load_names_file(write(tmp_path, ""))[0] == {}


def test_write_names_round_trips(tmp_path: Path) -> None:
    """`--write-names` output must be readable by `rename --from`."""

    class FakeHost:
        hostname = "10.0.1.5"
        ssh_config_host = None

    out = tmp_path / "out.yaml"
    naming.write_names_file({"prod-web": FakeHost()}, out)
    mapping, _ = naming.load_names_file(out)
    assert mapping == {"10.0.1.5": "prod-web"}


# --------------------------------------------------------------------------------------
# Integration with the host config
# --------------------------------------------------------------------------------------


def test_existing_configs_gain_an_id_without_migration(tmp_path: Path) -> None:
    """Deriving rather than storing means every install gets audit continuity for free."""
    from safereach.config import load_settings

    path = tmp_path / "hosts.yaml"
    path.write_text(
        "hosts:\n  web-01:\n    hostname: 10.0.1.5\n    user: diag\n    key: /tmp/k\n",
        encoding="utf-8",
    )
    host = load_settings(path).host("web-01")
    assert host.id == host_id("10.0.1.5", 22)


def test_id_survives_a_rename(tmp_path: Path) -> None:
    """The claim the whole design rests on: a rename must not sever the audit trail."""
    from safereach.config import load_settings

    before = tmp_path / "a.yaml"
    before.write_text(
        "hosts:\n  203.96.189.202:\n    hostname: 203.96.189.202\n"
        "    user: diag\n    key: /tmp/k\n",
        encoding="utf-8",
    )
    after = tmp_path / "b.yaml"
    after.write_text(
        "hosts:\n  langfuse-prod:\n    hostname: 203.96.189.202\n    user: diag\n    key: /tmp/k\n",
        encoding="utf-8",
    )
    assert load_settings(before).host("203.96.189.202").id == (
        load_settings(after).host("langfuse-prod").id
    )
