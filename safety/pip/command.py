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
from ..tool.utils import PipCommand

from .constants import PIP_COMMAND_HELP, PIP_COMMAND_NAME
from .decorators import optional_project_command

pip_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)


@pip_app.command(
    cls=SafetyCLICommand,
    help=PIP_COMMAND_HELP,
    name=PIP_COMMAND_NAME,
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
    command = PipCommand.from_args(ctx.args)
    command.execute(ctx)
