from pathlib import Path

from rich.prompt import Prompt
from ..cli_util import CommandType, FeatureType, SafetyCLICommand, SafetyCLISubGroup
from safety.error_handlers import handle_cmd_exception
import typer
import os


from safety.init.constants import (
    PROJECT_INIT_CMD_NAME,
    PROJECT_INIT_HELP,
    PROJECT_INIT_DIRECTORY_HELP,
)
from safety.init.main import create_project
from safety.console import main_console as console
from ..scan.command import scan
from ..scan.models import ScanOutput
from ..tool.main import (
    configure_system,
    configure_local_directory,
    has_local_tool_files,
    configure_alias,
)

from ..constants import CONTEXT_COMMAND_TYPE, CONTEXT_FEATURE_TYPE

from safety.decorators import notify
from safety.events.utils import emit_firewall_configured
from safety_schemas.models.events.payloads import AliasConfig, IndexConfig


try:
    from typing import Annotated  # type: ignore
except ImportError:
    from typing_extensions import Annotated

init_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)


@init_app.command(
    cls=SafetyCLICommand,
    help=PROJECT_INIT_HELP,
    name=PROJECT_INIT_CMD_NAME,
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
def init(
    ctx: typer.Context,
    directory: Annotated[
        Path,
        typer.Argument(  # type: ignore
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
            show_default=False,
            help=PROJECT_INIT_DIRECTORY_HELP,
        ),
    ] = Path("."),
):
    do_init(ctx, directory, False)


def do_init(ctx: typer.Context, directory: Path, prompt_user: bool = True):
    project_dir = (
        directory if os.path.isabs(directory) else os.path.join(os.getcwd(), directory)
    )

    # Fixed at the meantime, we'll revamp the init command soon.
    alias_configured = AliasConfig(is_configured=False)
    index_configured = IndexConfig(is_configured=False)

    create_project(ctx, console, Path(project_dir))

    answer = "y" if not prompt_user else None
    if prompt_user:
        console.print(
            "Safety prevents vulnerable or malicious packages from being installed on your computer. We do this by wrapping your package manager."
        )
        prompt = "Do you want to enable proactive malicious package prevention?"
        answer = Prompt.ask(
            prompt=prompt,
            choices=["y", "n"],
            default="y",
            show_default=True,
            console=console,
        ).lower()

    if answer == "y":
        configure_system(ctx.obj.org.get("slug"))
        # Naive approach, we'll revamp the init command soon.
        alias_configured.is_configured = True

    if prompt_user:
        prompt = "Do you want to alias pip to Safety?"
        answer = Prompt.ask(
            prompt=prompt,
            choices=["y", "n"],
            default="y",
            show_default=True,
            console=console,
        ).lower()

    if answer == "y":
        configure_alias()
        # Naive approach, we'll revamp the init command soon.
        index_configured.is_configured = True

    exit_code = None

    if has_local_tool_files(project_dir):  # type: ignore
        if prompt_user:
            prompt = "Do you want to enable proactive malicious package prevention for any project in working directory?"
            answer = Prompt.ask(
                prompt=prompt,
                choices=["y", "n"],
                default="y",
                show_default=True,
                console=console,
            ).lower()

        if answer == "y":
            configure_local_directory(
                project_dir,  # type: ignore
                ctx.obj.org.get("slug"),
                ctx.obj.project.id,
            )

        if prompt_user:
            prompt = "It looks like your current directory contains a requirements.txt file. Would you like Safety to scan it?"
            answer = Prompt.ask(
                prompt=prompt,
                choices=["y", "n"],
                default="y",
                show_default=True,
                console=console,
            ).lower()

        if answer == "y":
            ctx.command.name = "scan"
            ctx.params = {
                "target": directory,
                "output": ScanOutput.SCREEN,
                "policy_file_path": None,
            }
            try:
                scan(
                    ctx=ctx,
                    target=directory,
                    output=ScanOutput.SCREEN,
                    policy_file_path=None,
                )
            except SystemExit as e:
                exit_code = e

    emit_firewall_configured(
        event_bus=ctx.obj.event_bus,
        alias_config=alias_configured,
        index_config=index_configured,
    )

    if exit_code:
        raise exit_code
