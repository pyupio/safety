from pathlib import Path

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

import typer

from safety.decorators import notify
from safety.error_handlers import handle_cmd_exception
from ..cli_util import (
    CommandType,
    FeatureType,
    SafetyCLICommand,
    SafetyCLISubGroup,
)
from ..constants import CONTEXT_COMMAND_TYPE, CONTEXT_FEATURE_TYPE
from ..tool.utils import UvCommand
from ..pip.decorators import optional_project_command

from .constants import COMMAND_HELP, COMMAND_NAME

uv_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)


@uv_app.command(
    cls=SafetyCLICommand,
    help=COMMAND_HELP,
    name=COMMAND_NAME,
    options_metavar="[OPTIONS]",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        CONTEXT_COMMAND_TYPE: CommandType.BETA,
        CONTEXT_FEATURE_TYPE: FeatureType.FIREWALL,
    },
)
@handle_cmd_exception
@optional_project_command
@notify
def init(
    ctx: typer.Context,
    target: Annotated[
        Path,
        typer.Option(
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
            show_default=False,
        ),  # type: ignore
    ] = Path("."),
):
    command = UvCommand.from_args(ctx.args)
    command.execute(ctx)
