from __future__ import annotations

import configparser
from typing import TYPE_CHECKING, Any

from authlib.integrations.httpx_client import OAuth2Client
from joserfc.errors import ExpiredTokenError
from safety_schemas.models import Stage

from safety.auth.constants import (
    CLI_AUTH,
    CLI_AUTH_LOGOUT,
    CLI_CALLBACK,
)
from safety.auth.models import Organization
from safety.auth.oauth2 import Token
from safety.config import AUTH_CONFIG_USER, AuthConfig
from safety.constants import CONFIG
from safety.utils.auth_session import discard_token

if TYPE_CHECKING:
    from safety.auth.models import Auth


def get_authorization_data(
    http_client: OAuth2Client,
    code_verifier: str,
    organization: Organization | None = None,
    sign_up: bool = False,
    ensure_auth: bool = False,
    headless: bool = False,
) -> tuple[str, str]:
    """
    Generate the authorization URL for the authentication process.

    Args:
        http_client: The oauth2 client.
        code_verifier (str): The code verifier for the PKCE flow.
        organization (Optional[Organization]): The organization to authenticate with.
        sign_up (bool): Whether the URL is for sign-up.
        ensure_auth (bool): Whether to ensure authentication.
        headless (bool): Whether to run in headless mode.

    Returns:
        Tuple[str, str]: The authorization URL and initial state.
    """

    kwargs = {
        "sign_up": sign_up,
        "locale": "en",
        "ensure_auth": ensure_auth,
        "headless": headless,
    }
    if organization:
        kwargs["organization"] = organization.id

    return http_client.create_authorization_url(
        CLI_AUTH, code_verifier=code_verifier, **kwargs
    )


def get_logout_url(id_token: str) -> str:
    """
    Generate the logout URL.

    Args:
        id_token (str): The ID token.

    Returns:
        str: The logout URL.
    """
    return f"{CLI_AUTH_LOGOUT}?id_token={id_token}"


def get_redirect_url() -> str:
    """
    Get the redirect URL for the authentication callback.

    Returns:
        str: The redirect URL.
    """
    return CLI_CALLBACK


def get_organization() -> Organization | None:
    """
    Retrieve the organization configuration.

    Returns:
        Optional[Organization]: The organization object, or None if not configured.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG)

    org_conf: dict[str, str] | configparser.SectionProxy = (
        config["organization"] if "organization" in config.sections() else {}
    )
    org_id: str | None = (
        org_conf["id"].replace('"', "") if org_conf.get("id", None) else None
    )
    org_name: str | None = (
        org_conf["name"].replace('"', "") if org_conf.get("name", None) else None
    )

    if not org_id:
        return None

    org = Organization(id=org_id, name=org_name)  # type: ignore

    return org


def get_id_token_claims(jwks: dict[str, Any]) -> dict:
    id_token = None
    if auth_config := AuthConfig.from_storage():
        id_token = auth_config.id_token

    if not id_token:
        raise ValueError("Invalid auth config.")

    decoded = Token.get_claims_for(
        token=id_token,
        token_type="id_token",
        jwks=jwks,
    )

    if decoded is None:
        raise ValueError("Unable to get claims for id_token.")

    return decoded.claims


def get_auth_info(auth: Auth) -> dict | None:
    """
    Retrieve the authentication information.

    Args:
        auth: The authentication object containing authentication data.

    Returns:
        Optional[Dict]: The authentication information, or None if not authenticated.
    """
    from safety.auth.utils import is_email_verified

    info = None
    # Check client type first — this is the authoritative guard.
    # platform.token also checks isinstance internally, but we don't
    # rely on that: the isinstance here gates all OAuth2-specific calls
    # (refresh_token, discard_token) below.
    if isinstance(auth.platform.http_client, OAuth2Client) and auth.platform.token:
        oauth2_client = auth.platform.http_client

        if auth.jwks is None:
            return None

        try:
            info = get_id_token_claims(jwks=auth.jwks)

            verified = is_email_verified(info)
            if not verified:
                user_info = auth.platform.fetch_user_info()
                verified = is_email_verified(user_info)

                if verified:
                    # refresh only if needed
                    raise ExpiredTokenError("exp")

        except ExpiredTokenError:
            # id_token expired. So fire a manually a refresh
            try:
                oauth2_client.refresh_token(
                    auth.platform.get_openid_config().get("token_endpoint"),
                    refresh_token=oauth2_client.token.get("refresh_token"),
                )
                info = get_id_token_claims(jwks=auth.jwks)

            except Exception as _e:  # noqa: BLE001
                discard_token(oauth2_client=oauth2_client)
        except Exception as _g:  # noqa: BLE001
            discard_token(oauth2_client=oauth2_client)

    return info


def get_token(name: str = "access_token") -> str | None:
    """ "
    Retrieve a token from the local authentication configuration.

    This returns tokens saved in the local auth configuration.
    There are two types of tokens: access_token and id_token

    Args:
        name (str): The name of the token to retrieve.

    Returns:
        Optional[str]: The token value, or None if not found.
    """
    config = configparser.ConfigParser()
    config.read(AUTH_CONFIG_USER)

    if "auth" in config.sections() and name in config["auth"]:
        value = config["auth"][name]
        if value:
            return value

    return None


def get_host_config(key_name: str) -> Any | None:
    """
    Retrieve a configuration value from the host configuration.

    Args:
        key_name (str): The name of the configuration key.

    Returns:
        Optional[Any]: The configuration value, or None if not found.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG)

    if not config.has_section("host"):
        return None

    host_section = dict(config.items("host"))

    if key_name in host_section and key_name == "stage":
        # Support old alias in the config.ini
        if host_section[key_name] == "dev":
            host_section[key_name] = "development"
        if host_section[key_name] not in {env.value for env in Stage}:
            return None
        return Stage(host_section[key_name])

    return None


def str_to_bool(s: str) -> bool:
    """
    Convert a string to a boolean value.

    Args:
        s (str): The string to convert.

    Returns:
        bool: The converted boolean value.

    Raises:
        ValueError: If the string cannot be converted.
    """
    if s.lower() == "true" or s == "1":
        return True
    elif s.lower() == "false" or s == "0":
        return False
    else:
        raise ValueError(f"Cannot convert '{s}' to a boolean value.")
