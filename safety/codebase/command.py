import logging
from os import name
import typer
from safety.cli_util import SafetyCLISubGroup, SafetyCLICommand
from .constants import CMD_CODEBASE_INIT_NAME, CMD_HELP_CODEBASE_INIT, CMD_HELP_CODEBASE, CMD_CODEBASE_GROUP_NAME

from ..cli_util import get_command_for
from ..error_handlers import handle_cmd_exception
from ..decorators import notify
from ..constants import DEFAULT_EPILOG
from safety.console import main_console as console

logger = logging.getLogger(__name__)

cli_apps_opts = {"rich_markup_mode": "rich", "cls": SafetyCLISubGroup, "name": CMD_CODEBASE_GROUP_NAME}
codebase_app = typer.Typer(**cli_apps_opts)

DEFAULT_CMD = CMD_CODEBASE_INIT_NAME


@codebase_app.callback(
    invoke_without_command=True,
    cls=SafetyCLISubGroup,
    help=CMD_HELP_CODEBASE,
    epilog=DEFAULT_EPILOG,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def codebase(
    ctx: typer.Context,
):
    """
    Group command for Safety Codebase (project) operations. Running this command will forward to the default command.
    """
    logger.info("codebase started")

    # If no subcommand is invoked, forward to the default command
    if not ctx.invoked_subcommand:
        default_command = get_command_for(name=DEFAULT_CMD, typer_instance=codebase_app)
        return ctx.forward(default_command)



@codebase_app.command(
    cls=SafetyCLICommand,
    help=CMD_HELP_CODEBASE_INIT,
    name=CMD_CODEBASE_INIT_NAME,
    epilog=DEFAULT_EPILOG,
    options_metavar="[OPTIONS]",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
@handle_cmd_exception
@notify
def init(ctx: typer.Context):
    """
    Initialize a Safety Codebase (project). The codebase may be entirely new to Safety Platform, or may already exist in Safety Platform and the user is wanting to initialize it locally.
    """
    console.print("Initializing Safety Codebase...")
