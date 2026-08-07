"""Tests for awssso.cli.

boto3 calls are mocked with unittest.mock rather than moto: moto has no
implementation for the `sso` / `sso-oidc` operations this tool uses
(register_client, start_device_authorization, create_token,
get_role_credentials all return HTTP 404 "not yet implemented" under
moto's mock_aws), so a hand-rolled mock is the only option here.
"""

import json
from configparser import ConfigParser
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from awssso import cli


@pytest.fixture(autouse=True)
def aws_paths(tmp_path, monkeypatch):
    """Redirect the module's AWS file-path constants into a temp directory."""
    monkeypatch.setattr(cli, "AWS_CONFIG_PATH", tmp_path / "config")
    monkeypatch.setattr(cli, "AWS_CREDENTIAL_PATH", tmp_path / "credentials")
    monkeypatch.setattr(cli, "AWS_SSO_CACHE_PATH", tmp_path / "sso" / "cache")
    return tmp_path


def write_config(path, sections):
    """Write an ini file at path from {section_name: {key: value}}."""
    config = ConfigParser()
    for section, options in sections.items():
        config.add_section(section)
        for key, value in options.items():
            config.set(section, key, value)
    with open(path, "w") as f:
        config.write(f)


def make_profile(**overrides):
    defaults = {
        "sso_start_url": "https://example.awsapps.com/start",
        "sso_region": "eu-west-1",
        "sso_role_name": "AdminRole",
        "sso_account_id": "123456789012",
        "region": "eu-west-1",
    }
    return cli.SsoProfile(**{**defaults, **overrides})


def test_set_profile_credentials_retries_on_unauthorized_cached_token(aws_paths):
    from botocore.exceptions import ClientError

    write_config(cli.AWS_CONFIG_PATH, {
        "profile dev": {
            "sso_start_url": "https://example.awsapps.com/start",
            "sso_region": "eu-west-1",
            "sso_role_name": "AdminRole",
            "sso_account_id": "123456789012",
        },
    })

    unauthorized = ClientError({"Error": {"Code": "UnauthorizedException", "Message": "Token invalid"}},
                                "GetRoleCredentials")
    credentials = cli.SsoCredentials("AKIA", "secret", "token")
    stale_login = {"accessToken": "stale-token"}
    fresh_login = {"accessToken": "fresh-token"}

    with (
        patch("awssso.cli._get_sso_cached_login", side_effect=[stale_login, fresh_login]) as mock_cached_login,
        patch("awssso.cli._get_sso_role_credentials", side_effect=[unauthorized, credentials]) as mock_role_creds,
    ):
        cli._set_profile_credentials("dev")

    assert mock_cached_login.call_count == 2
    assert mock_cached_login.call_args_list[1].kwargs["force_login"] is True
    assert mock_role_creds.call_count == 2

    config = ConfigParser()
    config.read(cli.AWS_CREDENTIAL_PATH)
    assert config.get("dev", "aws_access_key_id") == "AKIA"


def test_set_profile_credentials_reraises_other_client_errors(aws_paths):
    from botocore.exceptions import ClientError

    write_config(cli.AWS_CONFIG_PATH, {
        "profile dev": {
            "sso_start_url": "https://example.awsapps.com/start",
            "sso_region": "eu-west-1",
            "sso_role_name": "AdminRole",
            "sso_account_id": "123456789012",
        },
    })

    throttled = ClientError({"Error": {"Code": "TooManyRequestsException", "Message": "Slow down"}},
                             "GetRoleCredentials")

    with (
        patch("awssso.cli._get_sso_cached_login", return_value={"accessToken": "token"}),
        patch("awssso.cli._get_sso_role_credentials", side_effect=throttled),
        pytest.raises(ClientError),
    ):
        cli._set_profile_credentials("dev")


def test_main_reports_client_error_instead_of_raising(aws_paths):
    from botocore.exceptions import ClientError

    error = ClientError({"Error": {"Code": "InvalidGrantException", "Message": "Invalid token provided"}}, "CreateToken")

    with (
        patch("awssso.cli._select_profiles", return_value=["dev"]),
        patch("awssso.cli._set_profile_credentials", side_effect=error),
        patch("sys.argv", ["awssso"]),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1


def test_main_reports_missing_profile_option_instead_of_raising(aws_paths):
    with (
        patch("awssso.cli._select_profiles", return_value=["dev"]),
        patch("awssso.cli._set_profile_credentials", side_effect=KeyError("sso_start_url")),
        patch("sys.argv", ["awssso"]),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1


def test_main_fetches_multiple_profiles(aws_paths):
    with (
        patch("awssso.cli._set_profile_credentials") as mock_set_credentials,
        patch("sys.argv", ["awssso", "dev", "prod"]),
    ):
        cli.main()

    assert mock_set_credentials.call_count == 2
    assert mock_set_credentials.call_args_list[0].args[0] == "dev"
    assert mock_set_credentials.call_args_list[1].args[0] == "prod"


def test_main_ignores_use_default_with_multiple_profiles(aws_paths):
    with (
        patch("awssso.cli._set_profile_credentials") as mock_set_credentials,
        patch("awssso.cli._print_warn") as mock_warn,
        patch("sys.argv", ["awssso", "dev", "prod", "--use-default"]),
    ):
        cli.main()

    assert mock_set_credentials.call_args_list[0].args[1] is False
    assert mock_set_credentials.call_args_list[1].args[1] is False
    mock_warn.assert_any_call('--use-default is ignored when multiple profiles are given.')


def test_main_skips_failed_profile_and_continues(aws_paths):
    from botocore.exceptions import ClientError

    error = ClientError({"Error": {"Code": "InvalidGrantException", "Message": "Invalid token provided"}}, "CreateToken")

    with (
        patch("awssso.cli._set_profile_credentials", side_effect=[error, None]) as mock_set_credentials,
        patch("sys.argv", ["awssso", "dev", "prod"]),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert mock_set_credentials.call_count == 2
    assert exc.value.code == 1


def test_profile_section():
    assert cli.profile_section("dev") == "profile dev"
    assert cli.profile_section("default") == "default"


def test_get_aws_profile_reads_config(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {
        "profile dev": {
            "sso_start_url": "https://example.awsapps.com/start",
            "sso_region": "eu-west-1",
            "sso_role_name": "AdminRole",
            "sso_account_id": "123456789012",
            "region": "eu-central-1",
        },
    })

    profile = cli._get_aws_profile("dev")

    assert profile == make_profile(region="eu-central-1")


def test_get_aws_profile_resolves_sso_session(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {
        "profile dev": {
            "sso_session": "my-sso",
            "sso_role_name": "AdminRole",
            "sso_account_id": "123456789012",
            "region": "eu-central-1",
        },
        "sso-session my-sso": {
            "sso_start_url": "https://example.awsapps.com/start",
            "sso_region": "eu-west-1",
            "sso_registration_scopes": "sso:account:access",
        },
    })

    profile = cli._get_aws_profile("dev")

    assert profile == make_profile(region="eu-central-1")


def test_get_aws_profile_missing_sso_session_section_raises(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {
        "profile dev": {
            "sso_session": "my-sso",
            "sso_role_name": "AdminRole",
            "sso_account_id": "123456789012",
        },
    })

    with pytest.raises(ValueError, match="my-sso"):
        cli._get_aws_profile("dev")


def test_get_aws_profile_missing_region_uses_default(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {
        "profile dev": {
            "sso_start_url": "https://example.awsapps.com/start",
            "sso_region": "eu-west-1",
            "sso_role_name": "AdminRole",
            "sso_account_id": "123456789012",
        },
    })

    profile = cli._get_aws_profile("dev")

    assert profile.region == cli.AWS_DEFAULT_REGION


def test_load_json_valid(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text(json.dumps({"a": 1}))

    assert cli._load_json(str(path)) == {"a": 1}


def test_load_json_corrupt(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("not json")

    assert cli._load_json(str(path)) is None


def test_store_aws_credentials_writes_section(aws_paths):
    profile = make_profile()
    credentials = cli.SsoCredentials("AKIA", "secret", "token")

    cli._store_aws_credentials("dev", profile, credentials)

    config = ConfigParser()
    config.read(cli.AWS_CREDENTIAL_PATH)
    assert dict(config.items("dev")) == {
        "region": "eu-west-1",
        "aws_access_key_id": "AKIA",
        "aws_secret_access_key": "secret",
        "aws_session_token": "token",
    }


def test_store_aws_credentials_overwrites_existing_section(aws_paths):
    write_config(cli.AWS_CREDENTIAL_PATH, {"dev": {"aws_access_key_id": "STALE"}})
    profile = make_profile()
    credentials = cli.SsoCredentials("FRESH", "secret", "token")

    cli._store_aws_credentials("dev", profile, credentials)

    config = ConfigParser()
    config.read(cli.AWS_CREDENTIAL_PATH)
    assert config.get("dev", "aws_access_key_id") == "FRESH"


def test_copy_to_default_profile(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {
        "profile dev": {"sso_start_url": "https://example.awsapps.com/start", "region": "eu-west-1"},
        "default": {"sso_start_url": "https://stale.awsapps.com/start", "region": "us-east-1"},
    })

    cli._copy_to_default_profile("dev")

    config = ConfigParser()
    config.read(cli.AWS_CONFIG_PATH)
    assert dict(config.items("default")) == dict(config.items("profile dev"))


def test_select_profiles_returns_chosen_names(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {"profile dev": {}, "profile prod": {}, "default": {}})

    with patch("awssso.cli.questionary.checkbox") as checkbox:
        checkbox.return_value.ask.return_value = ["dev", "prod"]
        assert cli._select_profiles() == ["dev", "prod"]


def test_select_profiles_excludes_sso_session_and_default(aws_paths):
    write_config(
        cli.AWS_CONFIG_PATH,
        {"sso-session my-sso": {}, "default": {}, "profile dev": {}},
    )

    with patch("awssso.cli.questionary.checkbox") as checkbox:
        checkbox.return_value.ask.return_value = ["dev"]
        cli._select_profiles()

    choices = checkbox.call_args.kwargs["choices"]
    assert [choice.value for choice in choices] == ["dev"]


def test_select_profiles_cancelled_exits(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {"profile dev": {}})

    with (
        patch("awssso.cli.questionary.checkbox") as checkbox,
        pytest.raises(SystemExit) as exc,
    ):
        checkbox.return_value.ask.return_value = None
        cli._select_profiles()

    assert exc.value.code == 1


def test_select_profiles_none_selected_exits(aws_paths):
    write_config(cli.AWS_CONFIG_PATH, {"profile dev": {}})

    with (
        patch("awssso.cli.questionary.checkbox") as checkbox,
        pytest.raises(SystemExit) as exc,
    ):
        checkbox.return_value.ask.return_value = []
        cli._select_profiles()

    assert exc.value.code == 1


def test_get_sso_role_credentials():
    profile = make_profile()
    login = {"accessToken": "the-token"}
    expiration_ms = (datetime.now(UTC) + timedelta(hours=1)).timestamp() * 1000
    mock_client = MagicMock()
    mock_client.get_role_credentials.return_value = {
        "roleCredentials": {
            "accessKeyId": "AKIA",
            "secretAccessKey": "secret",
            "sessionToken": "token",
            "expiration": expiration_ms,
        },
    }

    with patch("awssso.cli.boto3.client", return_value=mock_client) as mock_boto_client:
        credentials = cli._get_sso_role_credentials(profile, login)

    mock_boto_client.assert_called_once_with("sso", region_name="eu-west-1")
    mock_client.get_role_credentials.assert_called_once_with(
        roleName="AdminRole", accountId="123456789012", accessToken="the-token",
    )
    assert credentials == cli.SsoCredentials("AKIA", "secret", "token")


def test_get_sso_cached_login_reuses_valid_cache(aws_paths):
    profile = make_profile()
    login = {
        "startUrl": profile.sso_start_url,
        "region": profile.sso_region,
        "accessToken": "cached-token",
        "expiresAt": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    cache_dir = cli.AWS_SSO_CACHE_PATH
    cache_dir.mkdir(parents=True)
    import hashlib
    cache_hash = hashlib.sha1(profile.sso_start_url.encode("utf-8")).hexdigest()
    (cache_dir / f"{cache_hash}.json").write_text(json.dumps(login))

    with patch("awssso.cli._sso_device_login") as mock_login:
        result = cli._get_sso_cached_login(profile)

    mock_login.assert_not_called()
    assert result == login


def test_get_sso_cached_login_expired_falls_back_to_device_login(aws_paths):
    profile = make_profile()
    cache_dir = cli.AWS_SSO_CACHE_PATH
    cache_dir.mkdir(parents=True)
    import hashlib
    cache_hash = hashlib.sha1(profile.sso_start_url.encode("utf-8")).hexdigest()
    expired_login = {
        "region": profile.sso_region,
        "expiresAt": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
    }
    (cache_dir / f"{cache_hash}.json").write_text(json.dumps(expired_login))
    fresh_login = {"accessToken": "fresh-token"}

    with patch("awssso.cli._sso_device_login", return_value=fresh_login) as mock_login:
        result = cli._get_sso_cached_login(profile)

    mock_login.assert_called_once()
    assert result == fresh_login


def test_get_sso_cached_login_region_mismatch_falls_back_to_device_login(aws_paths):
    profile = make_profile()
    cache_dir = cli.AWS_SSO_CACHE_PATH
    cache_dir.mkdir(parents=True)
    import hashlib
    cache_hash = hashlib.sha1(profile.sso_start_url.encode("utf-8")).hexdigest()
    mismatched_login = {
        "region": "us-east-1",
        "expiresAt": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    (cache_dir / f"{cache_hash}.json").write_text(json.dumps(mismatched_login))
    fresh_login = {"accessToken": "fresh-token"}

    with patch("awssso.cli._sso_device_login", return_value=fresh_login) as mock_login:
        result = cli._get_sso_cached_login(profile)

    mock_login.assert_called_once()
    assert result == fresh_login


def test_get_sso_cached_login_force_login_ignores_valid_cache(aws_paths):
    profile = make_profile()
    cache_dir = cli.AWS_SSO_CACHE_PATH
    cache_dir.mkdir(parents=True)
    import hashlib
    cache_hash = hashlib.sha1(profile.sso_start_url.encode("utf-8")).hexdigest()
    valid_login = {
        "region": profile.sso_region,
        "expiresAt": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    (cache_dir / f"{cache_hash}.json").write_text(json.dumps(valid_login))
    fresh_login = {"accessToken": "fresh-token"}

    with patch("awssso.cli._sso_device_login", return_value=fresh_login) as mock_login:
        result = cli._get_sso_cached_login(profile, force_login=True)

    mock_login.assert_called_once()
    assert result == fresh_login


def test_sso_device_login_polls_until_authorized(aws_paths):
    profile = make_profile()
    cache_file = str(aws_paths / "sso" / "cache" / "hash.json")

    class AuthorizationPendingException(Exception):
        pass

    mock_oidc = MagicMock()
    mock_oidc.exceptions.AuthorizationPendingException = AuthorizationPendingException
    mock_oidc.exceptions.SlowDownException = type("SlowDownException", (Exception,), {})
    mock_oidc.register_client.return_value = {"clientId": "id", "clientSecret": "secret"}
    mock_oidc.start_device_authorization.return_value = {
        "verificationUriComplete": "https://example.com/verify",
        "userCode": "ABCD-EFGH",
        "deviceCode": "device-code",
        "expiresIn": 60,
        "interval": 0,
    }
    mock_oidc.create_token.side_effect = [
        AuthorizationPendingException(),
        {"accessToken": "the-token", "expiresIn": 3600},
    ]

    with (
        patch("awssso.cli.boto3.client", return_value=mock_oidc),
        patch("awssso.cli.webbrowser.open") as mock_open,
        patch("awssso.cli.time.sleep"),
    ):
        result = cli._sso_device_login(profile, cache_file)

    mock_open.assert_called_once_with("https://example.com/verify")
    assert result["accessToken"] == "the-token"
    with open(cache_file) as f:
        assert json.load(f)["accessToken"] == "the-token"


def test_sso_device_login_times_out(aws_paths):
    profile = make_profile()
    cache_file = str(aws_paths / "sso" / "cache" / "hash.json")

    mock_oidc = MagicMock()
    mock_oidc.exceptions.AuthorizationPendingException = type("AuthorizationPendingException", (Exception,), {})
    mock_oidc.exceptions.SlowDownException = type("SlowDownException", (Exception,), {})
    mock_oidc.register_client.return_value = {"clientId": "id", "clientSecret": "secret"}
    mock_oidc.start_device_authorization.return_value = {
        "verificationUriComplete": "https://example.com/verify",
        "userCode": "ABCD-EFGH",
        "deviceCode": "device-code",
        "expiresIn": -1,
    }

    with (
        patch("awssso.cli.boto3.client", return_value=mock_oidc),
        patch("awssso.cli.webbrowser.open"),
        pytest.raises(SystemExit) as exc,
    ):
        cli._sso_device_login(profile, cache_file)

    assert exc.value.code == 1
