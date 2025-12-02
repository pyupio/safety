import logging
from typing import Optional, Any, Callable

import click

from .main import (
    TYPE_CHECKING,
    get_auth_info,
    get_host_config,
    get_organization,
    get_redirect_url,
)
from authlib.common.security import generate_token
from safety.auth.constants import CLIENT_ID

from safety.auth.models import Organization, Auth
from safety.auth.utils import (
    is_email_verified,
)
from safety.platform import SafetyPlatformClient
from safety.scan.constants import (
    CLI_KEY_HELP,
    CLI_PROXY_HOST_HELP,
    CLI_PROXY_PORT_HELP,
    CLI_PROXY_PROTOCOL_HELP,
    CLI_STAGE_HELP,
)
from safety.util import DependentOption, SafetyContext
from safety.models import SafetyCLI
from safety_schemas.models import Stage
from safety.config.proxy import ProxyConfig
from safety.auth.oauth2 import update_token
from safety.auth.constants import (
    SAFETY_PLATFORM_URL,
    OAUTH2_SCOPE,
    AUTH_SERVER_URL,
    OPENID_CONFIG_URL,
)
from safety.config import get_proxy_config, get_tls_config


if TYPE_CHECKING:
    from safety.config.tls import TLSConfig


logger = logging.getLogger(__name__)


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
        default=None,
        cls=DependentOption,
        required_options=["proxy_host"],
        help=CLI_PROXY_PROTOCOL_HELP,
    )(func)
    func = click.option(
        "--proxy-port",
        multiple=False,
        type=int,
        default=None,
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


def _create_platform_client(
    tls_config: "TLSConfig",
    proxy_config: Optional[ProxyConfig] = None,
    api_key: Optional[str] = None,
    **kwargs,
) -> SafetyPlatformClient:
    """
    Create a Safety Platform client with configuration.

    Args:
        tls_config: TLS configuration
        proxy_config: Proxy configuration
        api_key: API key for authentication

    Returns:
        SafetyPlatformClient: Configured platform client
    """
    safety_platform_client = SafetyPlatformClient(
        base_url=SAFETY_PLATFORM_URL,
        auth_server_url=AUTH_SERVER_URL,
        openid_config_url=OPENID_CONFIG_URL,
        api_key=api_key,
        proxy_config=proxy_config,
        tls_config=tls_config,
        **kwargs,
    )

    return safety_platform_client


def configure_auth_session(
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

    proxy_config = get_proxy_config(
        scheme=proxy_protocol,
        host=proxy_host,
        port=proxy_port,
    )

    tls_config = get_tls_config()

    platform_client = _create_platform_client(
        api_key=key,
        proxy_config=proxy_config,
        tls_config=tls_config,
        redirect_uri=get_redirect_url(),
        update_token=update_token,
        client_id=CLIENT_ID,
        scope=OAUTH2_SCOPE,
        code_challenge_method="S256",
    )

    jwks = platform_client.get_jwks()

    auth = Auth(
        stage=stage,
        jwks=jwks,
        org=org,
        client_id=CLIENT_ID,
        http_client=platform_client._http_client,  # TODO: Improve this on a future refactor
        platform=platform_client,
        code_verifier=generate_token(48),
    )

    if not ctx.obj:
        ctx.obj = SafetyCLI()

    ctx.obj.auth = auth

    if not platform_client.api_key:
        platform_client.load_auth_token_from_storage(jwks=jwks)

    info = get_auth_info(ctx.obj.auth)

    if info:
        ctx.obj.auth.name = info.get("name")
        ctx.obj.auth.email = info.get("email")
        ctx.obj.auth.email_verified = is_email_verified(info)  # type: ignore
        SafetyContext().account = info["email"]
    else:
        SafetyContext().account = ""

    @ctx.call_on_close
    def clean_up_on_close():
        logger.debug("Closing requests session.")
        ctx.obj.auth.http_client.close()

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
                    logger.warning(f"Error waiting for events to process: {e}")

            ctx.obj.event_bus.stop()
