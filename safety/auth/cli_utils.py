import logging
from typing import Dict, Optional, Tuple, Any, Callable

import click

from .main import (
    get_auth_info,
    get_host_config,
    get_organization,
    get_proxy_config,
    get_redirect_url,
    get_token_data,
    save_auth_config,
    get_token,
    clean_session,
)
from authlib.common.security import generate_token
from safety.auth.constants import CLIENT_ID, OPENID_CONFIG_URL

from safety.auth.models import Organization, Auth
from safety.auth.utils import (
    S3PresignedAdapter,
    SafetyAuthSession,
    get_keys,
    is_email_verified,
)
from safety.constants import REQUEST_TIMEOUT
from safety.scan.constants import (
    CLI_KEY_HELP,
    CLI_PROXY_HOST_HELP,
    CLI_PROXY_PORT_HELP,
    CLI_PROXY_PROTOCOL_HELP,
    CLI_STAGE_HELP,
)
from safety.util import DependentOption, SafetyContext, get_proxy_dict
from safety.models import SafetyCLI
from safety_schemas.models import Stage

LOG = logging.getLogger(__name__)


def build_client_session(
    api_key: Optional[str] = None,
    proxies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[SafetyAuthSession, Dict[str, Any]]:
    """
    Builds and configures the client session for authentication.

    Args:
        api_key (Optional[str]): The API key for authentication.
        proxies (Optional[Dict[str, str]]): Proxy configuration.
        headers (Optional[Dict[str, str]]): Additional headers.

    Returns:
        Tuple[SafetyAuthSession, Dict[str, Any]]: The configured client session and OpenID configuration.
    """

    kwargs = {}
    target_proxies = proxies

    # Global proxy defined in the config.ini
    proxy_config, proxy_timeout, proxy_required = get_proxy_config()

    if not proxies:
        target_proxies = proxy_config

    def update_token(tokens, **kwargs):
        save_auth_config(
            access_token=tokens["access_token"],
            id_token=tokens["id_token"],
            refresh_token=tokens["refresh_token"],
        )
        load_auth_session(click_ctx=click.get_current_context(silent=True))  # type: ignore

    client_session = SafetyAuthSession(
        client_id=CLIENT_ID,
        code_challenge_method="S256",
        redirect_uri=get_redirect_url(),
        update_token=update_token,
        scope="openid email profile offline_access",
        **kwargs,
    )

    client_session.mount("https://pyup.io/static-s3/", S3PresignedAdapter())

    client_session.proxy_required = proxy_required
    client_session.proxy_timeout = proxy_timeout
    client_session.proxies = target_proxies  # type: ignore
    client_session.headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        openid_config = client_session.get(
            url=OPENID_CONFIG_URL, timeout=REQUEST_TIMEOUT
        ).json()
    except Exception as e:
        LOG.debug("Unable to load the openID config: %s", e)
        openid_config = {}

    client_session.metadata["token_endpoint"] = openid_config.get(
        "token_endpoint", None
    )

    if api_key:
        client_session.api_key = api_key  # type: ignore
        client_session.headers["X-Api-Key"] = api_key

    if headers:
        client_session.headers.update(headers)

    return client_session, openid_config


def load_auth_session(click_ctx: click.Context) -> None:
    """
    Loads the authentication session from the context.

    Args:
        click_ctx (click.Context): The Click context object.
    """
    if not click_ctx:
        LOG.warning("Click context is needed to be able to load the Auth data.")
        return

    client = click_ctx.obj.auth.client
    keys = click_ctx.obj.auth.keys

    access_token: str = get_token(name="access_token")  # type: ignore
    refresh_token: str = get_token(name="refresh_token")  # type: ignore
    id_token: str = get_token(name="id_token")  # type: ignore

    if access_token and keys:
        try:
            token = get_token_data(access_token, keys, silent_if_expired=True)
            client.token = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "token_type": "bearer",
                "expires_at": token.get("exp", None),  # type: ignore
            }
        except Exception as e:
            print(e)
            clean_session(client)


def proxy_options(func: Callable) -> Callable:
    """
    Decorator that defines proxy options for Click commands.

    Options defined per command, this will override the proxy settings defined in the
    config.ini file.

    Args:
        func (Callable): The Click command function.

    Returns:
        Callable: The wrapped Click command function with proxy options.
    """
    func = click.option(
        "--proxy-protocol",
        type=click.Choice(["http", "https"]),
        default="https",
        cls=DependentOption,
        required_options=["proxy_host"],
        help=CLI_PROXY_PROTOCOL_HELP,
    )(func)
    func = click.option(
        "--proxy-port",
        multiple=False,
        type=int,
        default=80,
        cls=DependentOption,
        required_options=["proxy_host"],
        help=CLI_PROXY_PORT_HELP,
    )(func)
    func = click.option(
        "--proxy-host", multiple=False, type=str, default=None, help=CLI_PROXY_HOST_HELP
    )(func)

    return func


def auth_options(stage: bool = True) -> Callable:
    """
    Decorator that defines authentication options for Click commands.

    Args:
        stage (bool): Whether to include the stage option.

    Returns:
        Callable: The decorator function.
    """

    def decorator(func: Callable) -> Callable:
        func = click.option(
            "--key", default=None, envvar="SAFETY_API_KEY", help=CLI_KEY_HELP
        )(func)

        if stage:
            func = click.option(
                "--stage", default=None, envvar="SAFETY_STAGE", help=CLI_STAGE_HELP
            )(func)

        return func

    return decorator


def inject_session(
    ctx: click.Context,
    proxy_protocol: Optional[str] = None,
    proxy_host: Optional[str] = None,
    proxy_port: Optional[str] = None,
    key: Optional[str] = None,
    stage: Optional[Stage] = None,
    invoked_command: str = "",
) -> Any:
    org: Optional[Organization] = get_organization()

    if not stage:
        host_stage = get_host_config(key_name="stage")
        stage = host_stage if host_stage else Stage.development

    proxy_config: Optional[Dict[str, str]] = get_proxy_dict(
        proxy_protocol,  # type: ignore
        proxy_host,  # type: ignore
        proxy_port,  # type: ignore
    )

    client_session, openid_config = build_client_session(
        api_key=key, proxies=proxy_config
    )
    keys = get_keys(client_session, openid_config)

    auth = Auth(
        stage=stage,
        keys=keys,
        org=org,
        client_id=CLIENT_ID,  # type: ignore
        client=client_session,
        code_verifier=generate_token(48),
    )

    if not ctx.obj:
        ctx.obj = SafetyCLI()

    ctx.obj.auth = auth

    load_auth_session(ctx)

    info = get_auth_info(ctx)

    if info:
        ctx.obj.auth.name = info.get("name")
        ctx.obj.auth.email = info.get("email")
        ctx.obj.auth.email_verified = is_email_verified(info)  # type: ignore
        SafetyContext().account = info["email"]
    else:
        SafetyContext().account = ""

    @ctx.call_on_close
    def clean_up_on_close():
        LOG.debug("Closing requests session.")
        ctx.obj.auth.client.close()

        if ctx.obj.event_bus:
            from safety.events.utils import (
                create_internal_event,
                InternalEventType,
                InternalPayload,
            )

            payload = InternalPayload(ctx=ctx)

            flush_event = create_internal_event(
                event_type=InternalEventType.FLUSH_SECURITY_TRACES, payload=payload
            )
            close_event = create_internal_event(
                event_type=InternalEventType.CLOSE_RESOURCES, payload=payload
            )

            flush_future = ctx.obj.event_bus.emit(flush_event)
            close_future = ctx.obj.event_bus.emit(close_event)

            # Wait for both events to be processed
            if flush_future and close_future:
                try:
                    flush_future.result()
                    close_future.result()
                except Exception as e:
                    LOG.warning(f"Error waiting for events to process: {e}")

            ctx.obj.event_bus.stop()
