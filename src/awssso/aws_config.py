"""Resolution of AWS config profile options, including the sso-session and
source_profile formats."""

from __future__ import annotations

from configparser import ConfigParser

SSO_SESSION_OPTIONS = ("sso_start_url", "sso_region")


def resolve_profile_options(
    config: ConfigParser, section: str, _visited: set[str] | None = None
) -> dict[str, str]:
    """Return profile options for section, following sso_session and
    source_profile references to fill in any options not set directly on section.

    AWS supports two SSO profile formats: the legacy one, where sso_start_url and
    sso_region are set directly on the profile, and the newer one, where the profile
    sets sso_session and those values live in a separate [sso-session <name>] section.

    Profiles can also chain to another profile via source_profile, inheriting any
    options (SSO or otherwise) that aren't set directly on section.
    """
    opts = dict(config.items(section))
    _apply_sso_session(config, section, opts)

    source_profile = opts.get("source_profile")
    if source_profile is None:
        return opts

    visited = _visited if _visited is not None else {section}
    source_section = profile_section(source_profile)

    if source_section in visited:
        raise ValueError(
            f"Profile [{section}] has a circular source_profile reference "
            f"involving '{source_profile}'."
        )
    if not config.has_section(source_section):
        raise ValueError(
            f"Profile [{section}] references source_profile '{source_profile}', "
            f"but no [{source_section}] section was found."
        )

    visited.add(source_section)
    source_opts = resolve_profile_options(config, source_section, visited)
    for key, value in source_opts.items():
        opts.setdefault(key, value)

    return opts


def _apply_sso_session(config: ConfigParser, section: str, opts: dict[str, str]) -> None:
    """Fill sso_start_url/sso_region in opts from a referenced [sso-session ...]
    section when the profile uses sso_session."""
    session_name = opts.get("sso_session")
    if session_name is None:
        return

    session_section = f"sso-session {session_name}"
    if not config.has_section(session_section):
        raise ValueError(
            f"Profile [{section}] references sso_session '{session_name}', "
            f"but no [{session_section}] section was found."
        )

    session_opts = dict(config.items(session_section))
    for key in SSO_SESSION_OPTIONS:
        if key in session_opts:
            opts.setdefault(key, session_opts[key])


def profile_section(profile_name: str) -> str:
    """Return the config section name for profile_name (e.g. 'profile foo')."""
    return "default" if profile_name == "default" else f"profile {profile_name}"
