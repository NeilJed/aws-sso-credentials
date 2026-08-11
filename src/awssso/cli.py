"""CLI that retrieves AWS credentials from SSO for use with the AWS CLI/Boto3."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import webbrowser
from configparser import ConfigParser
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qs, urlencode, urlparse

import boto3
import questionary
from botocore.exceptions import ClientError

from awssso.aws_config import profile_section, resolve_profile_options

__version__ = version('aws-sso-credentials')

AWS_CONFIG_PATH = Path.home() / '.aws' / 'config'
AWS_CREDENTIAL_PATH = Path.home() / '.aws' / 'credentials'
AWS_SSO_CACHE_PATH = Path.home() / '.aws' / 'sso' / 'cache'
AWS_DEFAULT_REGION = 'eu-west-1'
PKCE_LOGIN_TIMEOUT_SECONDS = 300

_CHECKBOX_STYLE = questionary.Style([
    ('qmark', 'fg:#00b894 bold'),
    ('question', 'bold'),
    ('answer', 'fg:#00b894 bold'),
    ('pointer', 'fg:#00b894 bold'),
    ('highlighted', 'fg:#00b894 bold'),
    ('selected', 'fg:#00b894'),
    ('instruction', 'fg:#888888 italic'),
])


@dataclass(frozen=True)
class SsoProfile:
    sso_start_url: str
    sso_region: str
    sso_role_name: str
    sso_account_id: str
    region: str
    sso_session: str | None = None


@dataclass(frozen=True)
class SsoCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str


def main() -> None:
    """Parse CLI args, resolve a profile, and populate AWS credentials from SSO."""
    parser = argparse.ArgumentParser(description='Retrieves AWS credentials from SSO for use with CLI/Boto3 apps.')

    parser.add_argument('profiles',
                        action='store',
                        nargs='*',
                        help='Space separated list of AWS Profiles to get credentials for.')

    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Show verbose output, messages, etc. Also shows role/region in the profile picker.')

    parser.add_argument('--use-default', '-d',
                        action='store_true',
                        help='Clones selected profile and credentials into the default profile.')

    parser.add_argument('--login',
                        action='store_true',
                        help='Perform an SSO login by default, not just when SSO credentials have expired')

    parser.add_argument('--legacy',
                        action='store_true',
                        help='Force device-code SSO login instead of PKCE for sso_session profiles.')

    parser.add_argument('--version', '-V',
                        action='version',
                        version=f'%(prog)s {__version__}')

    args = parser.parse_args()

    _print_msg(f'awssso {__version__}', args.verbose)

    profiles = args.profiles if args.profiles else _select_profiles(show_info=args.verbose)

    use_default = args.use_default
    if use_default and len(profiles) > 1:
        _print_warn('--use-default is ignored when multiple profiles are given.')
        use_default = False

    announced_sessions: set[str] = set()
    failed = []
    for profile in profiles:
        try:
            _set_profile_credentials(profile, use_default if profile != 'default' else False,
                                      force_login=args.login, verbose=args.verbose,
                                      announced_sessions=announced_sessions, legacy=args.legacy)
        except ClientError as error:
            error_details = error.response.get('Error', {})
            _print_warn(f"[{profile}] AWS request failed ({error_details.get('Code', 'Unknown')}): "
                        f"{error_details.get('Message', str(error))}")
            failed.append(profile)
        except KeyError as error:
            _print_warn(f"[{profile}] Profile is missing required option {error}")
            failed.append(profile)
        except ValueError as error:
            _print_warn(f"[{profile}] {error}")
            failed.append(profile)

    if failed:
        _print_error(f"Failed to fetch credentials for: {', '.join(failed)}")


def _set_profile_credentials(profile_name: str, use_default: bool = False, force_login: bool = False,
                              verbose: bool = False, announced_sessions: set[str] | None = None,
                              legacy: bool = False) -> None:
    if announced_sessions is None:
        announced_sessions = set()

    profile_opts = _get_aws_profile(profile_name, verbose)
    cache_login = _get_sso_cached_login(profile_opts, force_login=force_login, verbose=verbose,
                                         announced_sessions=announced_sessions, legacy=legacy)

    try:
        credentials = _get_sso_role_credentials(profile_opts, cache_login, verbose)
    except ClientError as error:
        if error.response.get('Error', {}).get('Code') != 'UnauthorizedException':
            raise
        _print_warn('Cached SSO credentials were rejected by AWS. Retrying with a fresh login...')
        cache_login = _get_sso_cached_login(profile_opts, force_login=True, verbose=verbose,
                                             announced_sessions=announced_sessions, legacy=legacy)
        credentials = _get_sso_role_credentials(profile_opts, cache_login, verbose)

    _store_aws_credentials(profile_name, profile_opts, credentials, verbose)
    if use_default:
        _store_aws_credentials('default', profile_opts, credentials, verbose)
        _copy_to_default_profile(profile_name, verbose)


def _get_aws_profile(profile_name: str, verbose: bool = False) -> SsoProfile:
    _print_msg(f'\nReading profile: [{profile_name}]', verbose)
    config = _read_config(AWS_CONFIG_PATH)
    opts = resolve_profile_options(config, profile_section(profile_name))
    return SsoProfile(
        sso_start_url=opts['sso_start_url'],
        sso_region=opts['sso_region'],
        sso_role_name=opts['sso_role_name'],
        sso_account_id=opts['sso_account_id'],
        region=opts.get('region', AWS_DEFAULT_REGION),
        sso_session=opts.get('sso_session'),
    )


def _get_sso_cached_login(profile: SsoProfile, force_login: bool = False, verbose: bool = False,
                           announced_sessions: set[str] | None = None, legacy: bool = False) -> dict[str, Any]:
    """Reuse a valid cached SSO login for profile, or fall back to a fresh device login."""
    if announced_sessions is None:
        announced_sessions = set()

    # botocore keys the SSO token cache by sha1(sso_session name) for profiles that use the
    # newer [sso-session ...] format, and by sha1(sso_start_url) for legacy profiles. Using
    # start_url unconditionally here wrote tokens under a key the AWS CLI never looks up for
    # sso-session profiles, so `aws` reported the token as missing even though we'd just cached it.
    cache_key = profile.sso_session if profile.sso_session else profile.sso_start_url
    already_announced = cache_key in announced_sessions

    if not already_announced:
        _print_msg('\nChecking for SSO credentials...', verbose)

    cache = hashlib.sha1(cache_key.encode("utf-8")).hexdigest()
    sso_cache_file = f'{AWS_SSO_CACHE_PATH}/{cache}.json'

    # Only force a fresh login once per sso-session/start_url per run: profiles sharing a
    # session already got a fresh login from an earlier profile, so honour that cached result
    # instead of triggering a duplicate browser/device login for every selected profile.
    force_login = force_login and not already_announced

    data = None if force_login else _load_json(sso_cache_file) if Path(sso_cache_file).is_file() else None

    if data:
        now = datetime.now().astimezone(UTC)
        expires_at = datetime.fromisoformat(data['expiresAt']).astimezone(UTC)

        if data.get('region') != profile.sso_region:
            _print_warn('SSO authentication region in cache does not match region defined in profile')
            data = None
        elif now > expires_at:
            _print_warn('SSO credentials have expired.')
            data = None
        elif (now + timedelta(minutes=15)) >= expires_at:
            _print_warn('Your current SSO credentials will expire in less than 15 minutes!')

    if not data:
        use_pkce = bool(profile.sso_session) and not legacy
        data = (_sso_pkce_login(profile, sso_cache_file, verbose) if use_pkce
                else _sso_device_login(profile, sso_cache_file, verbose))
    else:
        expires_at = datetime.fromisoformat(data['expiresAt']).astimezone(UTC)
        if not already_announced:
            _print_success(f'Found credentials. Valid until {_format_local(expires_at)}', verbose)

    announced_sessions.add(cache_key)
    return data


def _get_sso_role_credentials(profile: SsoProfile, login: dict[str, Any], verbose: bool = False) -> SsoCredentials:
    _print_msg('\nFetching short-term CLI/Boto3 session token...', verbose)

    client = boto3.client('sso', region_name=profile.sso_region)
    response = client.get_role_credentials(
        roleName=profile.sso_role_name,
        accountId=profile.sso_account_id,
        accessToken=login['accessToken'],
    )

    role_credentials = response['roleCredentials']
    expires = datetime.fromtimestamp(role_credentials['expiration'] / 1000.0, tz=UTC)
    _print_success(f'Got session token. Valid until {_format_local(expires)}', verbose)

    return SsoCredentials(
        access_key_id=role_credentials['accessKeyId'],
        secret_access_key=role_credentials['secretAccessKey'],
        session_token=role_credentials['sessionToken'],
    )


def _store_aws_credentials(profile_name: str, profile: SsoProfile, credentials: SsoCredentials,
                            verbose: bool = False) -> None:
    _print_msg(f'Adding to credential files under [{profile_name}]', verbose)

    config = _read_config(AWS_CREDENTIAL_PATH)

    if config.has_section(profile_name):
        config.remove_section(profile_name)

    config.add_section(profile_name)
    config.set(profile_name, "region", profile.region)
    config.set(profile_name, "aws_access_key_id", credentials.access_key_id)
    config.set(profile_name, "aws_secret_access_key", credentials.secret_access_key)
    config.set(profile_name, "aws_session_token", credentials.session_token)

    _write_config(AWS_CREDENTIAL_PATH, config)


def _copy_to_default_profile(profile_name: str, verbose: bool = False) -> None:
    _print_msg(f'Copying profile [{profile_name}] to [default]', verbose)

    config = _read_config(AWS_CONFIG_PATH)

    if config.has_section('default'):
        config.remove_section('default')

    config.add_section('default')

    for key, value in config.items(profile_section(profile_name)):
        config.set('default', key, value)

    _write_config(AWS_CONFIG_PATH, config)


def _profile_display_label(config: ConfigParser, section: str, name: str, name_width: int) -> str:
    """Build the picker label, appending a role/region suffix when the profile is SSO-based."""
    try:
        opts = resolve_profile_options(config, section)
    except ValueError:
        return name

    role_name = opts.get('sso_role_name')
    if not role_name:
        return name

    region = opts.get('region', AWS_DEFAULT_REGION)
    return f'{name:<{name_width}} {role_name} | {region}'


def _select_profiles(show_info: bool = False) -> list[str]:
    config = _read_config(AWS_CONFIG_PATH)

    sections = [section for section in config.sections() if str(section).startswith("profile ")]
    names = [re.sub(r"^profile ", "", str(section)) for section in sections]
    name_width = max((len(name) for name in names), default=0)

    choices = []
    for section, name in zip(sections, names, strict=True):
        title = _profile_display_label(config, section, name, name_width) if show_info else name
        choices.append((title, name))
    choices.sort(key=lambda choice: choice[1])

    answer = questionary.checkbox(
        'Please select AWS profiles to authenticate',
        choices=[questionary.Choice(title, value=name) for title, name in choices],
        use_search_filter=True,
        use_jk_keys=False,
        validate=lambda a: (
            True if len(a) > 0 else "You must select at least one profile!"
        ),
        style=_CHECKBOX_STYLE,
    ).ask()

    if not answer:
        sys.exit(1)

    return answer


def _sso_device_login(profile: SsoProfile, sso_cache_file: str, verbose: bool = False) -> dict[str, Any]:
    """Run the SSO device-code flow: open the auth page, then poll until the user approves or it times out."""
    start_url = profile.sso_start_url
    sso_region = profile.sso_region

    oidc = boto3.client('sso-oidc', region_name=sso_region)
    client = oidc.register_client(clientName='awssso', clientType='public')
    authorization = oidc.start_device_authorization(
        clientId=client['clientId'],
        clientSecret=client['clientSecret'],
        startUrl=start_url,
    )

    verification_uri = authorization['verificationUriComplete']
    _print_msg(
        '\nAttempting to automatically open the SSO authorization page in your default browser.\n'
        'If the browser does not open or you wish to use a different device to authorize this request,\n'
        f'open the following URL:\n\n{verification_uri}\n\n'
        f"Then enter the code:\n\n{authorization['userCode']}",
        verbose)
    webbrowser.open(verification_uri)

    interval = authorization.get('interval', 5)
    deadline = time.time() + authorization['expiresIn']

    while time.time() < deadline:
        try:
            token = oidc.create_token(
                clientId=client['clientId'],
                clientSecret=client['clientSecret'],
                grantType='urn:ietf:params:oauth:grant-type:device_code',
                deviceCode=authorization['deviceCode'],
            )
            break
        except oidc.exceptions.AuthorizationPendingException:
            time.sleep(interval)
        except oidc.exceptions.SlowDownException:
            interval += 5
            time.sleep(interval)
    else:
        _print_error('SSO login timed out.')
        sys.exit(1)

    return _finish_login(start_url, sso_region, token, sso_cache_file, verbose)


def _make_pkce_callback_handler(result: list[dict[str, str | None]]) -> type[BaseHTTPRequestHandler]:
    """Build a request handler that appends the `code`/`state` query params from the SSO
    OIDC authorize redirect to result, so the caller can read them without subclassing
    HTTPServer to carry state."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            query = parse_qs(urlparse(self.path).query)
            result.append({
                'code': query.get('code', [None])[0],
                'state': query.get('state', [None])[0],
            })

            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body>Login complete. You can close this tab.</body></html>')

        def log_message(self, format: str, *args: Any) -> None:
            pass

    return Handler


def _generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) per RFC 7636's S256 transform."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge


def _sso_pkce_login(profile: SsoProfile, sso_cache_file: str, verbose: bool = False) -> dict[str, Any]:
    """Run the SSO PKCE authorization-code flow: browser redirects straight to a local
    loopback listener, with no device code to type."""
    start_url = profile.sso_start_url
    sso_region = profile.sso_region

    code_verifier, code_challenge = _generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    result: list[dict[str, str | None]] = []
    server = HTTPServer(('127.0.0.1', 0), _make_pkce_callback_handler(result))
    redirect_uri = f'http://127.0.0.1:{server.server_port}/oauth/callback'

    oidc = boto3.client('sso-oidc', region_name=sso_region)
    client = oidc.register_client(
        clientName='awssso',
        clientType='public',
        grantTypes=['authorization_code'],
        redirectUris=[redirect_uri],
        scopes=['sso:account:access'],
        issuerUrl=start_url,
    )

    authorize_url = f'https://oidc.{sso_region}.amazonaws.com/authorize?' + urlencode({
        'response_type': 'code',
        'client_id': client['clientId'],
        'redirect_uri': redirect_uri,
        'scopes': 'sso:account:access',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    })

    _print_msg(
        '\nAttempting to automatically open the SSO authorization page in your default browser.\n'
        'If the browser does not open, open the following URL:\n\n'
        f'{authorize_url}',
        verbose)
    webbrowser.open(authorize_url)

    server.timeout = 1
    deadline = time.time() + PKCE_LOGIN_TIMEOUT_SECONDS
    while time.time() < deadline and not result:
        server.handle_request()
    server.server_close()

    if not result:
        _print_error('SSO login timed out.')
    callback = result[0]
    if callback['state'] != state:
        _print_error('SSO login failed: redirect state did not match.')

    token = oidc.create_token(
        clientId=client['clientId'],
        clientSecret=client['clientSecret'],
        grantType='authorization_code',
        code=callback['code'],
        redirectUri=redirect_uri,
        codeVerifier=code_verifier,
        scope=['sso:account:access'],
    )

    return _finish_login(start_url, sso_region, token, sso_cache_file, verbose)


def _finish_login(start_url: str, sso_region: str, token: dict[str, Any], sso_cache_file: str,
                   verbose: bool) -> dict[str, Any]:
    """Build the cache entry from a token response, write it to disk, and report success."""
    expires_at = (datetime.now(UTC) + timedelta(seconds=token['expiresIn'])).isoformat()
    data = {
        'startUrl': start_url,
        'region': sso_region,
        'accessToken': token['accessToken'],
        'expiresAt': expires_at,
    }

    Path(AWS_SSO_CACHE_PATH).mkdir(parents=True, exist_ok=True)
    with open(sso_cache_file, 'w') as f:
        json.dump(data, f)

    _print_success(f'Successfully logged into Start URL: {start_url}', verbose)
    return data


def _print_colour(style: str, message: str, verbose: bool = False, always: bool = False) -> None:
    if always or verbose:
        if os.environ.get('CLI_NO_COLOR') or not sys.stdout.isatty():
            print(message)
        else:
            questionary.print(message, style=style)


def _print_error(message: str) -> NoReturn:
    _print_colour('fg:#e74c3c', message, always=True)
    sys.exit(1)


def _print_warn(message: str) -> None:
    _print_colour('fg:#f1c40f', message, always=True)


def _print_msg(message: str, verbose: bool = False) -> None:
    _print_colour('fg:#3498db', message, verbose=verbose)


def _print_success(message: str, verbose: bool = False) -> None:
    _print_colour('fg:#00b894', message, verbose=verbose)


def _format_local(dt: datetime) -> str:
    return f"{dt.astimezone().strftime('%Y-%m-%d %H:%M:%S')} (Local)"


def _read_config(path: Path) -> ConfigParser:
    config = ConfigParser()
    config.read(path)
    return config


def _write_config(path: Path, config: ConfigParser) -> None:
    with open(path, "w") as destination:
        config.write(destination)


def _load_json(path: str) -> dict[str, Any] | None:
    """Read JSON from path, warning and returning None if the file is corrupt."""
    try:
        with open(path) as context:
            return json.load(context)
    except ValueError:
        _print_warn(f'Ignoring corrupt cache file: {path}')
        return None


if __name__ == "__main__":
    main()
