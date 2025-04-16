# type: ignore
import logging
import sys
from datetime import datetime

from safety.auth.models import Auth
from safety.auth.utils import initialize, is_email_verified
from safety.console import main_console as console
from safety.constants import MSG_FINISH_REGISTRATION_TPL, MSG_VERIFICATION_HINT
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
    clean_session,
    get_auth_info,
    get_authorization_data,
    get_token,
)
from safety.auth.server import process_browser_callback
from safety.events.utils import emit_auth_started, emit_auth_completed
from safety.util import initialize_event_bus
from safety.scan.constants import (
    CLI_AUTH_COMMAND_HELP,
    CLI_AUTH_HEADLESS_HELP,
    CLI_AUTH_LOGIN_HELP,
    CLI_AUTH_LOGOUT_HELP,
    CLI_AUTH_STATUS_HELP,
    DEFAULT_EPILOG,
)

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


CMD_LOGIN_NAME = "login"
CMD_REGISTER_NAME = "register"
CMD_STATUS_NAME = "status"
CMD_LOGOUT_NAME = "logout"
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
    info = get_auth_info(ctx)

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

    # Get authorization data and generate the authorization URL
    uri, initial_state = get_authorization_data(
        client=ctx.obj.auth.client,
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
        # Clean the session if an ID token is found
        if clean_session(ctx.obj.auth.client):
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

    info = get_auth_info(ctx)

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
            client=ctx.obj.auth.client,
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

        organization = None
        if ctx.obj.auth.org and ctx.obj.auth.org.name:
            organization = ctx.obj.auth.org.name

        render_successful_login(ctx.obj.auth, organization=organization)
        console.print()

    else:
        console.print(MSG_NON_AUTHENTICATED)


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

    # Get authorization data and generate the registration URL
    uri, initial_state = get_authorization_data(
        client=ctx.obj.auth.client,
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
