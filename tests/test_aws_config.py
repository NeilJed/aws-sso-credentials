"""Tests for awssso.aws_config."""

from configparser import ConfigParser

import pytest

from awssso.aws_config import resolve_profile_options


def make_config(sections):
    config = ConfigParser()
    for section, options in sections.items():
        config.add_section(section)
        for key, value in options.items():
            config.set(section, key, value)
    return config


def test_legacy_profile_returned_unchanged():
    config = make_config(
        {"profile dev": {"sso_start_url": "https://legacy.awsapps.com/start", "sso_region": "eu-west-1"}}
    )

    opts = resolve_profile_options(config, "profile dev")

    assert opts == {"sso_start_url": "https://legacy.awsapps.com/start", "sso_region": "eu-west-1"}


def test_sso_session_fills_in_start_url_and_region():
    config = make_config(
        {
            "profile dev": {"sso_session": "my-sso", "sso_role_name": "AdminRole"},
            "sso-session my-sso": {
                "sso_start_url": "https://example.awsapps.com/start",
                "sso_region": "eu-west-1",
                "sso_registration_scopes": "sso:account:access",
            },
        }
    )

    opts = resolve_profile_options(config, "profile dev")

    assert opts["sso_start_url"] == "https://example.awsapps.com/start"
    assert opts["sso_region"] == "eu-west-1"
    assert "sso_registration_scopes" not in opts


def test_profile_value_takes_precedence_over_sso_session():
    config = make_config(
        {
            "profile dev": {"sso_session": "my-sso", "sso_start_url": "https://override.awsapps.com/start"},
            "sso-session my-sso": {"sso_start_url": "https://example.awsapps.com/start", "sso_region": "eu-west-1"},
        }
    )

    opts = resolve_profile_options(config, "profile dev")

    assert opts["sso_start_url"] == "https://override.awsapps.com/start"
    assert opts["sso_region"] == "eu-west-1"


def test_missing_sso_session_section_raises():
    config = make_config({"profile dev": {"sso_session": "my-sso"}})

    with pytest.raises(ValueError, match="my-sso"):
        resolve_profile_options(config, "profile dev")


def test_source_profile_fills_in_missing_options():
    config = make_config(
        {
            "profile dev": {"source_profile": "base", "sso_role_name": "AdminRole"},
            "profile base": {
                "sso_start_url": "https://example.awsapps.com/start",
                "sso_region": "eu-west-1",
                "sso_account_id": "111111111111",
            },
        }
    )

    opts = resolve_profile_options(config, "profile dev")

    assert opts["sso_start_url"] == "https://example.awsapps.com/start"
    assert opts["sso_region"] == "eu-west-1"
    assert opts["sso_account_id"] == "111111111111"
    assert opts["sso_role_name"] == "AdminRole"


def test_profile_value_takes_precedence_over_source_profile():
    config = make_config(
        {
            "profile dev": {"source_profile": "base", "sso_region": "eu-north-1"},
            "profile base": {"sso_region": "eu-west-1"},
        }
    )

    opts = resolve_profile_options(config, "profile dev")

    assert opts["sso_region"] == "eu-north-1"


def test_source_profile_chain_and_sso_session_combine():
    config = make_config(
        {
            "profile dev": {"source_profile": "base"},
            "profile base": {"sso_session": "my-sso", "sso_account_id": "111111111111"},
            "sso-session my-sso": {
                "sso_start_url": "https://example.awsapps.com/start",
                "sso_region": "eu-west-1",
            },
        }
    )

    opts = resolve_profile_options(config, "profile dev")

    assert opts["sso_start_url"] == "https://example.awsapps.com/start"
    assert opts["sso_region"] == "eu-west-1"
    assert opts["sso_account_id"] == "111111111111"


def test_missing_source_profile_section_raises():
    config = make_config({"profile dev": {"source_profile": "missing"}})

    with pytest.raises(ValueError, match="missing"):
        resolve_profile_options(config, "profile dev")


def test_circular_source_profile_raises():
    config = make_config(
        {
            "profile a": {"source_profile": "b"},
            "profile b": {"source_profile": "a"},
        }
    )

    with pytest.raises(ValueError, match="circular"):
        resolve_profile_options(config, "profile a")


def test_default_profile_as_source_profile():
    config = make_config(
        {
            "profile dev": {"source_profile": "default"},
            "default": {"sso_region": "eu-west-1"},
        }
    )

    opts = resolve_profile_options(config, "profile dev")

    assert opts["sso_region"] == "eu-west-1"
