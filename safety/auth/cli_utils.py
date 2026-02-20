import logging
from typing import Dict, Optional, Any, Callable

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
from safety.config.auth import AuthConfig, MachineCredentialConfig


if TYPE_CHECKING:
    from safety.config.tls import TLSConfig


logger = logging.getLogger(__name__)

# Commands under `safety auth` that require an OAuth2Client (for
# create_authorization_url()).  When machine creds are present but no
# OAuth2 tokens exist, these commands must NOT use machine-token auth —
# otherwise the plain httpx.Client will crash on OAuth2-specific methods.
_OAUTH2_FLOW_AUTH_SUBCOMMANDS = frozenset({"login", "register"})


def _is_oauth2_flow_command(ctx: click.Context) -> bool:
    """Return True if the invoked command needs an OAuth2Client for login flows.

    These commands call create_authorization_url() which requires an
    OAuth2Client, not a plain httpx.Client with MachineTokenAuth.
    """
    args = getattr(ctx, "protected_args", []) or []
    if not args or args[0] != "auth":
        return False
    # 'safety auth' without subcommand defaults to login
    if len(args) < 2 or args[1].startswith("-"):
        return True
    return args[1] in _OAUTH2_FLOW_AUTH_SUBCOMMANDS


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
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    update_token: Optional[Any] = None,
    scope: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    machine_id: Optional[str] = None,
    machine_token: Optional[str] = None,
) -> SafetyPlatformClient:
    """
    Create a Safety Platform client with configuration.

    Args:
        tls_config: TLS configuration
        proxy_config: Proxy configuration
        api_key: API key for authentication
        client_id: OAuth2 client ID
        redirect_uri: OAuth2 redirect URI
        update_token: OAuth2 token update callback
        scope: OAuth2 scope
        code_challenge_method: OAuth2 code challenge method
        machine_id: Machine credential ID
        machine_token: Machine credential token

    Returns:
        SafetyPlatformClient: Configured platform client
    """
    return SafetyPlatformClient(
        base_url=SAFETY_PLATFORM_URL,
        auth_server_url=AUTH_SERVER_URL,
        openid_config_url=OPENID_CONFIG_URL,
        api_key=api_key,
        proxy_config=proxy_config,
        tls_config=tls_config,
        client_id=client_id,
        redirect_uri=redirect_uri,
        update_token=update_token,
        scope=scope,
        code_challenge_method=code_challenge_method,
        machine_id=machine_id,
        machine_token=machine_token,
    )


def configure_auth_session(
    ctx: click.Context,
    proxy_protocol: Optional[str] = None,
    proxy_host: Optional[str] = None,
    proxy_port: Optional[str] = None,
    key: Optional[str] = None,
    stage: Optional[Stage] = None,
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

    # Load machine credentials on every invocation (coexists with OAuth2)
    machine_creds = MachineCredentialConfig.from_storage()

    # Machine token is used when no API key or OAuth2 tokens are present,
    # UNLESS the command needs an OAuth2Client for login flows.
    # The server enforces which endpoints accept machine token auth.
    use_machine_token = False
    if not key and machine_creds:
        oauth2_config = AuthConfig.from_storage()
        if not oauth2_config and not _is_oauth2_flow_command(ctx):
            use_machine_token = True

    client_kwargs: Dict[str, Any] = dict(
        proxy_config=proxy_config,
        tls_config=tls_config,
        api_key=key,
        redirect_uri=get_redirect_url(),
        update_token=update_token,
        client_id=CLIENT_ID,
        scope=OAUTH2_SCOPE,
        code_challenge_method="S256",
    )

    if use_machine_token:
        assert machine_creds is not None  # guarded by `if not key and machine_creds:`
        client_kwargs["machine_id"] = machine_creds.machine_id
        client_kwargs["machine_token"] = machine_creds.machine_token

    platform_client = _create_platform_client(**client_kwargs)

    jwks = None if use_machine_token else platform_client.get_jwks()

    auth = Auth(
        stage=stage,
        jwks=jwks,
        org=org,
        client_id=CLIENT_ID,
        platform=platform_client,
        code_verifier=generate_token(48),
    )

    if not ctx.obj:
        ctx.obj = SafetyCLI()

    ctx.obj.auth = auth

    if use_machine_token:
        assert machine_creds is not None  # guarded by `if not key and machine_creds:`
        SafetyContext().account = f"machine:{machine_creds.machine_id}"
    else:
        if not platform_client.api_key:
            platform_client.load_auth_token_from_storage(jwks=jwks or {})

        info = get_auth_info(ctx.obj.auth)

        if info:
            ctx.obj.auth.refresh_from(info)
            ctx.obj.auth.email_verified = is_email_verified(info)  # type: ignore
            SafetyContext().account = info["email"]
        else:
            SafetyContext().account = ""

    @ctx.call_on_close
    def clean_up_on_close():
        logger.debug("Closing HTTP session.")
        ctx.obj.auth.platform._http_client.close()

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
