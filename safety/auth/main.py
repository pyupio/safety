import configparser

from typing import Any, Dict, Optional, Tuple, Union

from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from authlib.jose.errors import ExpiredTokenError

from safety.auth.models import Organization
from safety.auth.constants import (
    CLI_AUTH_LOGOUT,
    CLI_CALLBACK,
    AUTH_CONFIG_USER,
    CLI_AUTH,
)
from safety.constants import CONFIG
from safety_schemas.models import Stage
from safety.util import get_proxy_dict


def get_authorization_data(
    client,
    code_verifier: str,
    organization: Optional[Organization] = None,
    sign_up: bool = False,
    ensure_auth: bool = False,
    headless: bool = False,
) -> Tuple[str, str]:
    """
    Generate the authorization URL for the authentication process.

    Args:
        client: The authentication client.
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

    return client.create_authorization_url(
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


def get_organization() -> Optional[Organization]:
    """
    Retrieve the organization configuration.

    Returns:
        Optional[Organization]: The organization object, or None if not configured.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG)

    org_conf: Union[Dict[str, str], configparser.SectionProxy] = (
        config["organization"] if "organization" in config.sections() else {}
    )
    org_id: Optional[str] = (
        org_conf["id"].replace('"', "") if org_conf.get("id", None) else None
    )
    org_name: Optional[str] = (
        org_conf["name"].replace('"', "") if org_conf.get("name", None) else None
    )

    if not org_id:
        return None

    org = Organization(id=org_id, name=org_name)  # type: ignore

    return org


def get_auth_info(ctx) -> Optional[Dict]:
    """
    Retrieve the authentication information.

    Args:
        ctx: The context object containing authentication data.

    Returns:
        Optional[Dict]: The authentication information, or None if not authenticated.
    """
    from safety.auth.utils import is_email_verified

    info = None
    if ctx.obj.auth.client.token:
        try:
            info = get_token_data(get_token(name="id_token"), keys=ctx.obj.auth.keys)  # type: ignore

            verified = is_email_verified(info)  # type: ignore
            if not verified:
                user_info = ctx.obj.auth.client.fetch_user_info()
                verified = is_email_verified(user_info)

                if verified:
                    # refresh only if needed
                    raise ExpiredTokenError

        except ExpiredTokenError:
            # id_token expired. So fire a manually a refresh
            try:
                ctx.obj.auth.client.refresh_token(
                    ctx.obj.auth.client.metadata.get("token_endpoint"),
                    refresh_token=ctx.obj.auth.client.token.get("refresh_token"),
                )
                info = get_token_data(
                    get_token(name="id_token"),  # type: ignore
                    keys=ctx.obj.auth.keys,  # type: ignore
                )
            except Exception as _e:
                clean_session(ctx.obj.auth.client)
        except Exception as _g:
            clean_session(ctx.obj.auth.client)

    return info


def get_token_data(
    token: str, keys: Any, silent_if_expired: bool = False
) -> Optional[Dict]:
    """
    Decode and validate the token data.

    Args:
        token (str): The token to decode.
        keys (Any): The keys to use for decoding.
        silent_if_expired (bool): Whether to silently ignore expired tokens.

    Returns:
        Optional[Dict]: The decoded token data, or None if invalid.
    """
    claims = jwt.decode(token, keys, claims_cls=CodeIDToken)
    try:
        claims.validate()
    except ExpiredTokenError as e:
        if not silent_if_expired:
            raise e

    return claims


def get_token(name: str = "access_token") -> Optional[str]:
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


def get_host_config(key_name: str) -> Optional[Any]:
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

    if key_name in host_section:
        if key_name == "stage":
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


def get_proxy_config() -> Tuple[Optional[Dict[str, str]], Optional[int], bool]:
    """
    Retrieve the proxy configuration.

    Returns:
        Tuple[Optional[Dict[str, str]], Optional[int], bool]: The proxy configuration, timeout, and whether it is required.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG)

    proxy_dictionary = None
    required = False
    timeout = None
    proxy = None

    if config.has_section("proxy"):
        proxy = dict(config.items("proxy"))

    if proxy:
        try:
            proxy_dictionary = get_proxy_dict(
                proxy["protocol"],
                proxy["host"],
                proxy["port"],  # type: ignore
            )
            required = str_to_bool(proxy["required"])
            timeout = proxy["timeout"]
        except Exception:
            pass

    return proxy_dictionary, timeout, required  # type: ignore


def clean_session(client) -> bool:
    """
    Clean the authentication session.

    Args:
        client: The authentication client.

    Returns:
        bool: Always returns True.
    """
    config = configparser.ConfigParser()
    config["auth"] = {"access_token": "", "id_token": "", "refresh_token": ""}

    with open(AUTH_CONFIG_USER, "w") as configfile:
        config.write(configfile)

    client.token = None

    return True


def save_auth_config(
    access_token: Optional[str] = None,
    id_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
) -> None:
    """
    Save the authentication configuration.

    Args:
        access_token (Optional[str]): The access token.
        id_token (Optional[str]): The ID token.
        refresh_token (Optional[str]): The refresh token.
    """
    config = configparser.ConfigParser()
    config.read(AUTH_CONFIG_USER)
    config["auth"] = {  # type: ignore
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
    }

    with open(AUTH_CONFIG_USER, "w") as configfile:
        config.write(configfile)  # type: ignore
