# type: ignore
import logging
import os
import re
import sys
from datetime import datetime, timezone

from safety.auth.models import Auth
from safety.auth.utils import initialize, is_email_verified
from safety.console import main_console as console
from safety.constants import (
    MSG_FINISH_REGISTRATION_TPL,
    MSG_VERIFICATION_HINT,
    DEFAULT_EPILOG,
)
from safety.meta import get_version
from safety.decorators import notify

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

from typing import Optional

import click
import typer
from rich.padding import Padding
from typer import Typer

from safety.auth.main import (
    get_auth_info,
    get_authorization_data,
    get_token,
)
from safety.auth.server import process_browser_callback
from safety.events.utils import emit_auth_started, emit_auth_completed
from safety.util import initialize_event_bus
from safety.scan.constants import (
    CLI_AUTH_COMMAND_HELP,
    CLI_AUTH_ENROLL_HELP,
    CLI_AUTH_HEADLESS_HELP,
    CLI_AUTH_LOGIN_HELP,
    CLI_AUTH_LOGOUT_HELP,
    CLI_AUTH_STATUS_HELP,
)
from safety.config.auth import AuthConfig, MachineCredentialConfig
from safety.utils.tokens import get_token_claims
from safety.errors import EnrollmentError
from safety.utils.auth_session import discard_token

from ..cli_util import SafetyCLISubGroup, get_command_for, pass_safety_cli_obj
from safety.error_handlers import handle_cmd_exception
from .constants import (
    MSG_FAIL_LOGIN_AUTHED,
    MSG_FAIL_REGISTER_AUTHED,
    MSG_LOGOUT_DONE,
    MSG_LOGOUT_FAILED,
    MSG_NON_AUTHENTICATED,
)

LOG = logging.getLogger(__name__)

auth_app = Typer(rich_markup_mode="rich", name="auth")


def _extract_org_uuid_from_jwt(ctx: "typer.Context") -> str:
    """Extract the org legacy UUID from the current JWT access token.

    Pure read — does not persist anything.  Returns ``""`` on failure.
    """
    auth_config = AuthConfig.from_storage()
    if not auth_config:
        return ""
    try:
        claims = get_token_claims(
            auth_config.access_token,
            "access_token",
            ctx.obj.auth.jwks,
            silent_if_expired=True,
        )
        if claims:
            org_uuid = claims.get("https://api.safetycli.com/org_uuid", "")
            return str(org_uuid) if org_uuid else ""
    except Exception:
        LOG.warning("Failed to extract org UUID from access token", exc_info=True)
    return ""


def _check_cross_org_enrollment(login_org_uuid: str, ctx: "typer.Context") -> bool:
    """Check that *login_org_uuid* matches the enrolled org (if any).

    Returns True if login should proceed, False if cross-org mismatch
    detected (tokens are discarded in that case).
    """
    machine_cred = MachineCredentialConfig.from_storage()
    if not (login_org_uuid and machine_cred and machine_cred.org_legacy_uuid):
        return True

    if machine_cred.org_legacy_uuid != login_org_uuid:
        discard_token(ctx.obj.auth.platform.http_client)
        console.print()
        console.print(
            "[red]This device is enrolled with machine authentication to a different "
            "organization than the one you are attempting to log in to. "
            "Please log in with a user in the same organization.[/red]"
        )
        return False

    return True


def _save_org_uuid(org_uuid: str) -> None:
    """Persist *org_uuid* to AuthConfig on disk."""
    if not org_uuid:
        return
    auth_config = AuthConfig.from_storage()
    if auth_config:
        auth_config.org_legacy_uuid = org_uuid
        auth_config.save()


CMD_LOGIN_NAME = "login"
CMD_REGISTER_NAME = "register"
CMD_STATUS_NAME = "status"
CMD_LOGOUT_NAME = "logout"
CMD_ENROLL_NAME = "enroll"
DEFAULT_CMD = CMD_LOGIN_NAME


@auth_app.callback(
    invoke_without_command=True,
    cls=SafetyCLISubGroup,
    help=CLI_AUTH_COMMAND_HELP,
    epilog=DEFAULT_EPILOG,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
@pass_safety_cli_obj
def auth(ctx: typer.Context) -> None:
    """
    Authenticate Safety CLI with your account.

    Args:
        ctx (typer.Context): The Typer context object.
    """
    LOG.info("auth started")

    # If no subcommand is invoked, forward to the default command
    if not ctx.invoked_subcommand:
        default_command = get_command_for(name=DEFAULT_CMD, typer_instance=auth_app)
        return ctx.forward(default_command)


def fail_if_authenticated(ctx: typer.Context, with_msg: str) -> None:
    """
    Exits the command if the user is already authenticated.

    Args:
        ctx (typer.Context): The Typer context object.
        with_msg (str): The message to display if authenticated.
    """
    info = get_auth_info(ctx.obj.auth)

    if info:
        console.print()
        email = f"[green]{ctx.obj.auth.email}[/green]"
        if not ctx.obj.auth.email_verified:
            email = f"{email} {render_email_note(ctx.obj.auth)}"

        console.print(with_msg.format(email=email))
        sys.exit(0)


def render_email_note(auth: Auth) -> str:
    """
    Renders a note indicating whether email verification is required.

    Args:
        auth (Auth): The Auth object.

    Returns:
        str: The rendered email note.
    """
    return "" if auth.email_verified else "[red](email verification required)[/red]"


def render_successful_login(auth: Auth, organization: Optional[str] = None) -> None:
    """
    Renders a message indicating a successful login.

    Args:
        auth (Auth): The Auth object.
        organization (Optional[str]): The organization name.
    """
    DEFAULT = "--"
    name = auth.name if auth.name else DEFAULT
    email = auth.email if auth.email else DEFAULT
    email_note = render_email_note(auth)
    console.print()
    console.print("[bold][green]You're authenticated[/green][/bold]")
    if name and name != email:
        details = [f"[green][bold]Account:[/bold] {name}, {email}[/green] {email_note}"]
    else:
        details = [f"[green][bold]Account:[/bold] {email}[/green] {email_note}"]

    if organization:
        details.insert(0, f"[green][bold]Organization:[/bold] {organization}[green]")

    for msg in details:
        console.print(Padding(msg, (0, 0, 0, 1)), emoji=True)


@auth_app.command(name=CMD_LOGIN_NAME, help=CLI_AUTH_LOGIN_HELP)
@handle_cmd_exception
@notify
def login(
    ctx: typer.Context,
    headless: Annotated[
        Optional[bool],
        typer.Option(
            "--headless",
            help=CLI_AUTH_HEADLESS_HELP,
        ),
    ] = None,
) -> None:
    """
    Authenticate Safety CLI with your safetycli.com account using your default browser.

    Args:
        ctx (typer.Context): The Typer context object.
        headless (bool): Whether to run in headless mode.
    """
    LOG.info("login started")
    headless = headless is True

    # Check if the user is already authenticated
    fail_if_authenticated(ctx, with_msg=MSG_FAIL_LOGIN_AUTHED)

    console.print()

    info = None

    brief_msg: str = (
        "Redirecting your browser to log in; once authenticated, "
        "return here to start using Safety"
    )

    if ctx.obj.auth.org:
        console.print(
            f"Logging into [bold]{ctx.obj.auth.org.name}[/bold] organization."
        )

    if headless:
        brief_msg = "Running in headless mode. Please copy and open the following URL in a browser"

    uri, initial_state = get_authorization_data(
        http_client=ctx.obj.auth.platform.http_client,
        code_verifier=ctx.obj.auth.code_verifier,
        organization=ctx.obj.auth.org,
        headless=headless,
    )
    click.secho(brief_msg)
    click.echo()

    emit_auth_started(ctx.obj.event_bus, ctx)
    # Process the browser callback to complete the authentication
    info = process_browser_callback(
        uri, initial_state=initial_state, ctx=ctx, headless=headless
    )

    is_success = False
    error_msg = None

    if info:
        if info.get("email", None):
            organization = None
            if ctx.obj.auth.org and ctx.obj.auth.org.name:
                organization = ctx.obj.auth.org.name
            ctx.obj.auth.refresh_from(info)
            if headless:
                console.print()

            initialize(ctx, refresh=True)

            login_org_uuid = _extract_org_uuid_from_jwt(ctx)
            if not _check_cross_org_enrollment(login_org_uuid, ctx):
                is_success = False
                emit_auth_completed(
                    ctx.obj.event_bus,
                    ctx,
                    success=False,
                    error_message="Cross-org enrollment mismatch",
                )
                return
            _save_org_uuid(login_org_uuid)

            initialize_event_bus(ctx=ctx)
            render_successful_login(ctx.obj.auth, organization=organization)
            is_success = True

            console.print()
            if ctx.obj.auth.org or ctx.obj.auth.email_verified:
                if not getattr(ctx.obj, "only_auth_msg", False):
                    console.print(
                        "[tip]Tip[/tip]: now try [bold]`safety scan`[/bold] in your project’s root "
                        "folder to run a project scan or [bold]`safety -–help`[/bold] to learn more."
                    )
            else:
                console.print(
                    MSG_FINISH_REGISTRATION_TPL.format(email=ctx.obj.auth.email)
                )
                console.print()
                console.print(MSG_VERIFICATION_HINT)
        else:
            click.secho("Safety is now authenticated but your email is missing.")
    else:
        error_msg = ":stop_sign: [red]"
        if ctx.obj.auth.org:
            error_msg += (
                f"Error logging into {ctx.obj.auth.org.name} organization "
                f"with auth ID: {ctx.obj.auth.org.id}."
            )
        else:
            error_msg += "Error logging into Safety."

        error_msg += (
            " Please try again, or use [bold]`safety auth -–help`[/bold] "
            "for more information[/red]"
        )

        console.print(error_msg, emoji=True)

    emit_auth_completed(
        ctx.obj.event_bus, ctx, success=is_success, error_message=error_msg
    )


@auth_app.command(name=CMD_LOGOUT_NAME, help=CLI_AUTH_LOGOUT_HELP)
@handle_cmd_exception
@notify
def logout(ctx: typer.Context) -> None:
    """
    Log out of your current session.

    Args:
        ctx (typer.Context): The Typer context object.
    """
    LOG.info("logout started")

    id_token = get_token("id_token")

    msg = MSG_NON_AUTHENTICATED

    if id_token:
        if discard_token(ctx.obj.auth.platform.http_client):
            msg = MSG_LOGOUT_DONE
        else:
            msg = MSG_LOGOUT_FAILED

    console.print(msg)


@auth_app.command(name=CMD_STATUS_NAME, help=CLI_AUTH_STATUS_HELP)
@click.option(
    "--ensure-auth/--no-ensure-auth",
    default=False,
    help="This will keep running the command until anauthentication is made.",
)
@click.option(
    "--login-timeout",
    "-w",
    type=int,
    default=600,
    help="Max time allowed to wait for an authentication.",
)
@handle_cmd_exception
@notify
def status(
    ctx: typer.Context, ensure_auth: bool = False, login_timeout: int = 600
) -> None:
    """
    Display Safety CLI's current authentication status.

    Args:
        ctx (typer.Context): The Typer context object.
        ensure_auth (bool): Whether to keep running until authentication is made.
        login_timeout (int): Max time allowed to wait for authentication.
    """
    LOG.info("status started")
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safety_version = get_version()
    console.print(f"[{current_time}]: Safety {safety_version}")

    # Machine token auth: display status and return early
    if ctx.obj.auth.platform.has_machine_token:
        machine_id = ctx.obj.auth.platform.machine_id
        if not machine_id:
            console.print(
                "[red]Machine token authentication is misconfigured: no machine ID found.\n"
                "Try re-enrolling with [bold]`safety auth enroll --force`[/bold][/red]"
            )
            sys.exit(1)
        console.print(
            f"[green]Authenticated via machine token (machine:{machine_id})[/green]"
        )
        initialize(ctx, refresh=True)
        return

    # Load enrollment state from storage
    machine_cred = MachineCredentialConfig.from_storage()

    info = get_auth_info(ctx.obj.auth)

    initialize(ctx, refresh=True)

    if ensure_auth:
        console.print("running: safety auth status --ensure-auth")
        console.print()

    if info:
        verified = is_email_verified(info)
        email_status = " [red](email not verified)[/red]" if not verified else ""

        console.print(f"[green]Authenticated as {info['email']}[/green]{email_status}")
    elif ensure_auth:
        console.print(
            "Safety is not authenticated. Launching default browser to log in"
        )
        console.print()
        uri, initial_state = get_authorization_data(
            http_client=ctx.obj.auth.platform.http_client,
            code_verifier=ctx.obj.auth.code_verifier,
            organization=ctx.obj.auth.org,
            ensure_auth=ensure_auth,
        )

        # Process the browser callback to complete the authentication
        info = process_browser_callback(
            uri, initial_state=initial_state, timeout=login_timeout, ctx=ctx
        )

        if not info:
            console.print(
                f"[red]Timeout error ({login_timeout} seconds): not successfully authenticated without the timeout period.[/red]"
            )
            sys.exit(1)

        login_org_uuid = _extract_org_uuid_from_jwt(ctx)
        if not _check_cross_org_enrollment(login_org_uuid, ctx):
            sys.exit(1)
        _save_org_uuid(login_org_uuid)

        organization = None
        if ctx.obj.auth.org and ctx.obj.auth.org.name:
            organization = ctx.obj.auth.org.name

        render_successful_login(ctx.obj.auth, organization=organization)
        console.print()

    else:
        if not machine_cred:
            console.print(MSG_NON_AUTHENTICATED)

    # Show enrollment status if enrolled
    if machine_cred:
        console.print(f"  Enrolled system: {machine_cred.machine_id}")
        if machine_cred.enrolled_at:
            console.print(f"  Enrolled at: {machine_cred.enrolled_at}")
        if machine_cred.org_id:
            console.print(f"  Organization ID: {machine_cred.org_id}")
        if machine_cred.org_slug:
            console.print(f"  Organization Slug: {machine_cred.org_slug}")
        if machine_cred.org_legacy_uuid:
            console.print(f"  Organization UUID: {machine_cred.org_legacy_uuid}")


@auth_app.command(name=CMD_REGISTER_NAME)
@handle_cmd_exception
@notify
def register(ctx: typer.Context) -> None:
    """
    Create a new user account for the safetycli.com service.

    Args:
        ctx (typer.Context): The Typer context object.
    """
    LOG.info("register started")

    # Check if the user is already authenticated
    fail_if_authenticated(ctx, with_msg=MSG_FAIL_REGISTER_AUTHED)

    uri, initial_state = get_authorization_data(
        http_client=ctx.obj.auth.platform.http_client,
        code_verifier=ctx.obj.auth.code_verifier,
        sign_up=True,
    )

    console.print(
        "\nRedirecting your browser to register for a free account. Once registered, return here to start using Safety."
    )
    console.print()

    # Process the browser callback to complete the registration
    info = process_browser_callback(uri, initial_state=initial_state, ctx=ctx)
    console.print()

    if info:
        console.print(f"[green]Successfully registered {info.get('email')}[/green]")
        console.print()
    else:
        console.print("[red]Unable to register in this time, try again.[/red]")


@auth_app.command(name=CMD_ENROLL_NAME, help=CLI_AUTH_ENROLL_HELP)
@handle_cmd_exception
@notify
def enroll(
    ctx: typer.Context,
    enrollment_key: Annotated[
        Optional[str],
        typer.Argument(
            envvar="SAFETY_ENROLLMENT_KEY",
            help="Enrollment key provided by your MDM administrator.",
        ),
    ] = None,
    machine_id: Annotated[
        Optional[str],
        typer.Option(
            "--machine-id",
            envvar="SAFETY_MACHINE_ID",
            help="Override machine identity. If not set, auto-detected. Note: separate from hostname, which is also transmitted to the server.",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Force re-enrollment even if already enrolled.",
        ),
    ] = False,
) -> None:
    """Enroll this machine with the Safety Platform for MDM-managed scanning."""
    from safety.auth.constants import ENROLLMENT_KEY_PATTERN
    from safety.auth.enrollment import call_enrollment_endpoint
    from safety.auth.machine_id import resolve_machine_id

    LOG.info("enroll started")

    # 1. Check if already enrolled
    existing = MachineCredentialConfig.from_storage()
    if existing and not force:
        LOG.info("machine already enrolled, skipping (use --force to re-enroll)")
        console.print()
        console.print("[green]This machine is already enrolled.[/green]")
        console.print(f"  Machine ID: {existing.machine_id}")
        console.print(f"  Enrolled at: {existing.enrolled_at}")
        console.print()
        console.print("Use [bold]--force[/bold] to re-enroll.")
        return

    # 2. Resolve enrollment key
    if not enrollment_key:
        raise EnrollmentError("Enrollment key is required")

    # 3. Validate enrollment key format
    if not re.match(ENROLLMENT_KEY_PATTERN, enrollment_key):
        raise EnrollmentError("Invalid enrollment key format")

    # 4. Resolve machine ID — determine source for logging
    if machine_id is not None:
        machine_id_source = "flag (--machine-id)"
    elif os.environ.get("SAFETY_MACHINE_ID"):
        machine_id_source = "env (SAFETY_MACHINE_ID)"
    else:
        machine_id_source = "platform detection"

    LOG.info(
        "enrollment attempt: machine_id_source=%s, force=%s",
        machine_id_source,
        force,
    )

    resolved_machine_id = resolve_machine_id(override=machine_id, skip_enrolled=True)

    # Cross-org guard rail: if user is logged in, pass org identity for server-side validation
    auth_config = AuthConfig.from_storage()
    org_legacy_uuid_for_request = ""
    if auth_config and auth_config.org_legacy_uuid:
        org_legacy_uuid_for_request = auth_config.org_legacy_uuid

    # 5. Call enrollment HTTP helper (reuses the platform client created
    #    during CLI startup — TLS/proxy already probed)
    response = call_enrollment_endpoint(
        platform_client=ctx.obj.auth.platform,
        enrollment_key=enrollment_key,
        machine_id=resolved_machine_id,
        force=force,
        org_legacy_uuid=org_legacy_uuid_for_request,
    )

    # 6. Save credentials
    response_token = response.get("machine_token")
    if not response_token:
        LOG.info("enrollment failed: server response missing machine token")
        raise EnrollmentError("Server response missing machine token")
    enrolled_at = datetime.now(timezone.utc).isoformat()

    MachineCredentialConfig(
        machine_id=resolved_machine_id,
        machine_token=response_token,
        enrolled_at=enrolled_at,
        org_id=str(response.get("org_id") or ""),
        org_legacy_uuid=str(response.get("org_legacy_uuid") or ""),
        org_slug=str(response.get("org_slug") or ""),
    ).save()

    LOG.info("enrollment successful: machine_id=%s", resolved_machine_id)

    # 7. Print success
    org_id = str(response.get("org_id") or "")
    org_legacy_uuid = str(response.get("org_legacy_uuid") or "")
    org_slug = str(response.get("org_slug") or "")
    console.print()
    console.print("[bold][green]Enrollment successful![/green][/bold]")
    console.print(f"  Machine ID:      {resolved_machine_id}")
    console.print(f"  Machine Token:   {response_token}")
    console.print(f"  Enrolled at:     {enrolled_at}")
    if org_id:
        console.print(f"  Organization ID: {org_id}")
    if org_slug:
        console.print(f"  Organization Slug: {org_slug}")
    if org_legacy_uuid:
        console.print(f"  Organization UUID: {org_legacy_uuid}")
    console.print()
    console.print(
        "[green]You don't need to save these, they are automatically stored.[/green]"
    )
