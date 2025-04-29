import logging
import sys

import typer
from rich.prompt import Prompt

from safety.console import main_console as console
from safety.decorators import notify
from safety.events.utils import emit_firewall_disabled


# TODO: refactor this import and the related code
# For now, let's keep it as is
from safety.scan.constants import DEFAULT_EPILOG
from safety.error_handlers import handle_cmd_exception

from ..cli_util import (
    CommandType,
    FeatureType,
    SafetyCLICommand,
    SafetyCLISubGroup,
    pass_safety_cli_obj,
)
from ..constants import CONTEXT_COMMAND_TYPE, CONTEXT_FEATURE_TYPE, EXIT_CODE_OK
from ..tool.interceptors import create_interceptor
from ..tool.main import reset_system
from .constants import (
    FIREWALL_CMD_NAME,
    FIREWALL_HELP,
    MSG_FEEDBACK,
    MSG_REQ_FILE_LINE,
    MSG_UNINSTALL_EXPLANATION,
    MSG_UNINSTALL_WRAPPERS,
    MSG_UNINSTALL_CONFIG,
    MSG_UNINSTALL_SUCCESS,
    UNINSTALL_CMD_NAME,
    UNINSTALL_HELP,
)


firewall_app = typer.Typer(
    rich_markup_mode="rich", cls=SafetyCLISubGroup, name=FIREWALL_CMD_NAME
)


LOG = logging.getLogger(__name__)


init_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)


@firewall_app.callback(
    cls=SafetyCLISubGroup,
    help=FIREWALL_HELP,
    epilog=DEFAULT_EPILOG,
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        CONTEXT_COMMAND_TYPE: CommandType.BETA,
        CONTEXT_FEATURE_TYPE: FeatureType.FIREWALL,
    },
)
@pass_safety_cli_obj
def firewall(ctx: typer.Context) -> None:
    """
    Main callback for the firewall commands.

    Args:
        ctx (typer.Context): The Typer context object.
    """
    LOG.info("firewall callback started")


@firewall_app.command(
    cls=SafetyCLICommand,
    name=UNINSTALL_CMD_NAME,
    help=UNINSTALL_HELP,
    options_metavar="[OPTIONS]",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        CONTEXT_COMMAND_TYPE: CommandType.BETA,
        CONTEXT_FEATURE_TYPE: FeatureType.FIREWALL,
    },
)
@handle_cmd_exception
@notify
def uninstall(ctx: typer.Context):
    console.print()
    console.print(MSG_UNINSTALL_EXPLANATION)

    console.print()
    prompt = "Uninstall?"
    should_uninstall = (
        Prompt.ask(
            prompt=prompt,
            choices=["y", "n"],
            default="y",
            show_default=True,
            console=console,
        ).lower()
        == "y"
    )

    if not should_uninstall:
        sys.exit(EXIT_CODE_OK)

    console.print()
    for msg in MSG_UNINSTALL_CONFIG:
        console.print(msg)
    # TODO: Make it robust. The reset per tool should be included in remove
    # interceptors
    reset_system()

    # TODO: support reset project files

    console.print(MSG_UNINSTALL_WRAPPERS)
    interceptor = create_interceptor()
    interceptor.remove_interceptors()

    console.print()
    console.print(MSG_UNINSTALL_SUCCESS)

    console.print()
    console.print(MSG_REQ_FILE_LINE)

    console.print()

    console.print(MSG_FEEDBACK)

    console.print()
    prompt = "Feedback (or enter to exit)"
    feedback = Prompt.ask(prompt)
    feedback = None if len(feedback) <= 0 else feedback

    emit_firewall_disabled(event_bus=ctx.obj.event_bus, reason=feedback)

    if feedback:
        console.print()
        console.print("Thank you for your feedback!")
