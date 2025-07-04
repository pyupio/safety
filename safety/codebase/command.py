import logging
from pathlib import Path
from typing import Optional
from safety.codebase.render import render_initialization_result
from safety.errors import SafetyError
from safety.events.utils.emission import (
    emit_codebase_detection_status,
    emit_codebase_setup_completed,
)
from safety.init.main import launch_auth_if_needed
from safety.tool.main import find_local_tool_files
from safety.util import clean_project_id
from typing_extensions import Annotated

import typer
from safety.cli_util import SafetyCLISubGroup, SafetyCLICommand
from .constants import (
    CMD_CODEBASE_INIT_NAME,
    CMD_HELP_CODEBASE_INIT,
    CMD_HELP_CODEBASE,
    CMD_CODEBASE_GROUP_NAME,
    CMD_HELP_CODEBASE_INIT_DISABLE_FIREWALL,
    CMD_HELP_CODEBASE_INIT_LINK_TO,
    CMD_HELP_CODEBASE_INIT_NAME,
    CMD_HELP_CODEBASE_INIT_PATH,
)

from ..cli_util import CommandType, get_command_for
from ..error_handlers import handle_cmd_exception
from ..decorators import notify
from ..constants import CONTEXT_COMMAND_TYPE, DEFAULT_EPILOG
from safety.console import main_console as console
from .main import initialize_codebase, prepare_unverified_codebase


logger = logging.getLogger(__name__)

cli_apps_opts = {
    "rich_markup_mode": "rich",
    "cls": SafetyCLISubGroup,
    "name": CMD_CODEBASE_GROUP_NAME,
}
codebase_app = typer.Typer(**cli_apps_opts)

DEFAULT_CMD = CMD_CODEBASE_INIT_NAME


@codebase_app.callback(
    invoke_without_command=True,
    cls=SafetyCLISubGroup,
    help=CMD_HELP_CODEBASE,
    epilog=DEFAULT_EPILOG,
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        CONTEXT_COMMAND_TYPE: CommandType.BETA,
    },
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
def init(
    ctx: typer.Context,
    name: Annotated[
        Optional[str],
        typer.Option(
            help=CMD_HELP_CODEBASE_INIT_NAME,
            callback=lambda name: clean_project_id(name) if name else None,
        ),
    ] = None,
    link_to: Annotated[
        Optional[str],
        typer.Option(
            "--link-to",
            help=CMD_HELP_CODEBASE_INIT_LINK_TO,
            callback=lambda name: clean_project_id(name) if name else None,
        ),
    ] = None,
    skip_firewall_setup: Annotated[
        bool, typer.Option(help=CMD_HELP_CODEBASE_INIT_DISABLE_FIREWALL)
    ] = False,
    codebase_path: Annotated[
        Path,
        typer.Option(
            "--path",
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=True,
            readable=True,
            resolve_path=True,
            show_default=False,
            help=CMD_HELP_CODEBASE_INIT_PATH,
        ),
    ] = Path("."),
):
    """
    Initialize a Safety Codebase. The codebase may be entirely new to Safety Platform,
    or may already exist in Safety Platform and the user is wanting to initialize it locally.
    """
    logger.info("codebase init started")

    if link_to and name:
        raise typer.BadParameter("--link-to and --name cannot be used together")

    org_slug = launch_auth_if_needed(ctx, console)

    if not org_slug:
        raise SafetyError(
            "Organization not found, please run 'safety auth status' or 'safety auth login'"
        )

    should_enable_firewall = not skip_firewall_setup and ctx.obj.firewall_enabled

    unverified_codebase = prepare_unverified_codebase(
        codebase_path=codebase_path,
        user_provided_name=name,
        user_provided_link_to=link_to,
    )

    local_files = find_local_tool_files(codebase_path)

    emit_codebase_detection_status(
        event_bus=ctx.obj.event_bus,
        ctx=ctx,
        detected=any(local_files),
        detected_files=local_files if local_files else None,
    )

    project_file_created, project_status = initialize_codebase(
        ctx=ctx,
        console=console,
        codebase_path=codebase_path,
        unverified_codebase=unverified_codebase,
        org_slug=org_slug,
        link_to=link_to,
        should_enable_firewall=should_enable_firewall,
    )

    codebase_init_status = (
        "reinitialized" if unverified_codebase.created else project_status
    )
    codebase_id = ctx.obj.project.id if ctx.obj.project and ctx.obj.project.id else None

    render_initialization_result(
        console=console,
        codebase_init_status=codebase_init_status,
        codebase_id=codebase_id,
    )

    emit_codebase_setup_completed(
        event_bus=ctx.obj.event_bus,
        ctx=ctx,
        is_created=project_file_created,
        codebase_id=codebase_id,
    )
