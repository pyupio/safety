from datetime import datetime
import logging
import sys
from safety.auth.models import Auth

from safety.console import main_console as console
from safety.constants import MSG_FINISH_REGISTRATION_TPL, MSG_VERIFICATION_HINT

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

from typing import Optional

import click
from typer import Typer
import typer

from safety.auth.main import get_auth_info, get_authorization_data, get_token, clean_session
from safety.auth.server import process_browser_callback
from ..cli_util import get_command_for, pass_safety_cli_obj, SafetyCLISubGroup

from .constants import MSG_FAIL_LOGIN_AUTHED, MSG_FAIL_REGISTER_AUTHED, MSG_LOGOUT_DONE, MSG_LOGOUT_FAILED, MSG_NON_AUTHENTICATED
from safety.scan.constants import CLI_AUTH_COMMAND_HELP, DEFAULT_EPILOG, CLI_AUTH_LOGIN_HELP, CLI_AUTH_LOGOUT_HELP, CLI_AUTH_STATUS_HELP


from rich.padding import Padding

LOG = logging.getLogger(__name__)

auth_app = Typer(rich_markup_mode="rich")



CMD_LOGIN_NAME = "login"
CMD_REGISTER_NAME = "register"
CMD_STATUS_NAME = "status"
CMD_LOGOUT_NAME = "logout"
DEFAULT_CMD = CMD_LOGIN_NAME

@auth_app.callback(invoke_without_command=True, 
                   cls=SafetyCLISubGroup, 
                   help=CLI_AUTH_COMMAND_HELP, 
                   epilog=DEFAULT_EPILOG,
                   context_settings={"allow_extra_args": True, 
                                     "ignore_unknown_options": True})
@pass_safety_cli_obj
def auth(ctx: typer.Context):
    """
    Authenticate Safety CLI with your account
    """
    LOG.info('auth started')

    if not ctx.invoked_subcommand:
        default_command = get_command_for(name=DEFAULT_CMD, 
                                          typer_instance=auth_app)
        return ctx.forward(default_command)


def fail_if_authenticated(ctx, with_msg: str):
    info = get_auth_info(ctx)

    if info:
        console.print()
        email = f"[green]{ctx.obj.auth.email}[/green]"
        if not ctx.obj.auth.email_verified:
            email = f"{email} {render_email_note(ctx.obj.auth)}"

        console.print(with_msg.format(email=email))
        sys.exit(0)

def render_email_note(auth: Auth) -> str:
    return "" if auth.email_verified else "[red](email verification required)[/red]"

def render_successful_login(auth: Auth,
                            organization: Optional[str] = None):
    DEFAULT = "--"
    name = auth.name if auth.name else DEFAULT
    email = auth.email if auth.email else DEFAULT
    email_note = render_email_note(auth)

    console.print("[bold][green]You're authenticated[/green][/bold]")
    if name and name != email:
        details = [f"[green][bold]Account:[/bold] {name}, {email}[/green] {email_note}"]
    else:
        details = [f"[green][bold]Account:[/bold] {email}[/green] {email_note}"]

    if organization:
        details.insert(0, 
                        "[green][bold]Organization:[/bold] " \
                        f"{organization}[green]")

    for msg in details:
        console.print(Padding(msg, (0, 0, 0, 1)), emoji=True)    


@auth_app.command(name=CMD_LOGIN_NAME, help=CLI_AUTH_LOGIN_HELP)
def login(ctx: typer.Context):
    """
    Authenticate Safety CLI with your safetycli.com account using your default browser.
    """
    LOG.info('login started')

    fail_if_authenticated(ctx, with_msg=MSG_FAIL_LOGIN_AUTHED)

    console.print()
    brief_msg: str = "Redirecting your browser to log in; once authenticated, " \
          "return here to start using Safety"    
    
    uri, initial_state = get_authorization_data(client=ctx.obj.auth.client,
                                                code_verifier=ctx.obj.auth.code_verifier,
                                                organization=ctx.obj.auth.org)
    
    if ctx.obj.auth.org:
        console.print(f"Logging into [bold]{ctx.obj.auth.org.name}[/bold] " \
                      "organization.")
    
    click.secho(brief_msg)
    click.echo()

    info = process_browser_callback(uri, 
                                    initial_state=initial_state, ctx=ctx)

    if info:
        if info.get("email", None):
            organization = None
            if ctx.obj.auth.org and ctx.obj.auth.org.name:
                organization = ctx.obj.auth.org.name
            ctx.obj.auth.refresh_from(info)
            render_successful_login(ctx.obj.auth, organization=organization)

            console.print()
            if ctx.obj.auth.org or ctx.obj.auth.email_verified:
                console.print(
                    "[tip]Tip[/tip]: now try [bold]`safety scan`[/bold] in your project’s root " \
                    "folder to run a project scan or [bold]`safety -–help`[/bold] to learn more.")
            else:
                console.print(MSG_FINISH_REGISTRATION_TPL.format(email=ctx.obj.auth.email))
                console.print()
                console.print(MSG_VERIFICATION_HINT)
        else:
            click.secho("Safety is now authenticated but your email is missing.")
    else:
        msg = ":stop_sign: [red]"
        if ctx.obj.auth.org:
            msg += f"Error logging into {ctx.obj.auth.org.name} organization " \
                f"with auth ID: {ctx.obj.auth.org.id}."
        else:
            msg += "Error logging into Safety."

        msg += " Please try again, or use [bold]`safety auth –help`[/bold] " \
            "for more information[/red]"
        
        console.print(msg, emoji=True)

@auth_app.command(name=CMD_LOGOUT_NAME, help=CLI_AUTH_LOGOUT_HELP)
def logout(ctx: typer.Context):
    """
    Log out of your current session.
    """
    LOG.info('logout started')

    id_token = get_token('id_token')
    
    msg = MSG_NON_AUTHENTICATED
    
    if id_token:
        if clean_session(ctx.obj.auth.client):
            msg = MSG_LOGOUT_DONE
        else:
            msg = MSG_LOGOUT_FAILED

    console.print(msg)


@auth_app.command(name=CMD_STATUS_NAME, help=CLI_AUTH_STATUS_HELP)
@click.option("--ensure-auth/--no-ensure-auth", default=False,
              help="This will keep running the command until an" \
                "authentication is made.")
@click.option("--login-timeout", "-w", type=int, default=600,
              help="Max time allowed to wait for an authentication.")
def status(ctx: typer.Context, ensure_auth: bool = False, 
           login_timeout: int = 600):
    """
    Display Safety CLI's current authentication status.
    """
    LOG.info('status started')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    from safety.util import get_safety_version
    safety_version = get_safety_version()
    console.print(f"[{current_time}]: Safety {safety_version}")

    info = get_auth_info(ctx)

    if ensure_auth:
        console.print("running: safety auth status --ensure-auth")
        console.print()

    if info:
        verified = info.get("email_verified", False)
        email_status = " [red](email not verified)[/red]" if not verified else ""

        console.print(f'[green]Authenticated as {info["email"]}[/green]{email_status}')    
    elif ensure_auth:
        console.print('Safety is not authenticated. Launching default browser to log in')
        console.print()
        uri, initial_state = get_authorization_data(client=ctx.obj.auth.client,
                                                    code_verifier=ctx.obj.auth.code_verifier,
                                                    organization=ctx.obj.auth.org, ensure_auth=ensure_auth)
        
        info = process_browser_callback(uri, initial_state=initial_state, 
                                          timeout=login_timeout, ctx=ctx)           
        
        if not info:
            console.print(f'[red]Timeout error ({login_timeout} seconds): not successfully authenticated without the timeout period.[/red]')
            sys.exit(1)
        
        organization = None
        if ctx.obj.auth.org and ctx.obj.auth.org.name:
            organization = ctx.obj.auth.org.name

        render_successful_login(ctx.obj.auth, organization=organization)
        console.print()

    else:
        console.print(MSG_NON_AUTHENTICATED)


@auth_app.command(name=CMD_REGISTER_NAME)
def register(ctx: typer.Context):
    """
    Create a new user account for the safetycli.com service.
    """
    LOG.info('register started')

    fail_if_authenticated(ctx, with_msg=MSG_FAIL_REGISTER_AUTHED)

    uri, initial_state = get_authorization_data(client=ctx.obj.auth.client,
                                                code_verifier=ctx.obj.auth.code_verifier,
                                                sign_up=True)
    
    console.print("Redirecting your browser to register for a free account. Once registered, return here to start using Safety.")
    console.print()

    info = process_browser_callback(uri,
                                    initial_state=initial_state, ctx=ctx)

    if info:
        console.print(f'[green]Successfully registered {info.get("email")}[/green]')
        console.print()
    else:
        console.print('[red]Unable to register in this time, try again.[/red]')
    
