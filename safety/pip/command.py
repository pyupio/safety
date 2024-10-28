from pathlib import Path

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

import typer
from typer import Option

from .constants import PIP_COMMAND_NAME, PIP_COMMAND_HELP
from .decorators import optional_project_command
from ..cli_util import CommandType, FeatureType, SafetyCLICommand, \
    SafetyCLISubGroup
from ..tool.utils import PipCommand

from ..constants import CONTEXT_COMMAND_TYPE, CONTEXT_FEATURE_TYPE

pip_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)


@pip_app.command(
    cls=SafetyCLICommand,
    help=PIP_COMMAND_HELP,
    name=PIP_COMMAND_NAME,
    options_metavar="[OPTIONS]",
    context_settings={"allow_extra_args": True, 
                      "ignore_unknown_options": True,
                      CONTEXT_COMMAND_TYPE: CommandType.BETA,
                      CONTEXT_FEATURE_TYPE: FeatureType.FIREWALL},
)
@optional_project_command
def init(
    ctx: typer.Context,
    target: Annotated[
        Path,
        Option(
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
            show_default=False,
        ),
    ] = Path("."),
):
    command = PipCommand.from_args(ctx.args)
    command.execute(ctx)
