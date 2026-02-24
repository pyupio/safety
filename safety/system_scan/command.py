from __future__ import annotations

from pathlib import Path
import sys
import typer
from typing import TYPE_CHECKING

from rich.console import Console

from .scanner import Config, JsonlSinkConfig, SafetyPlatformSinkConfig
from .main import run_non_interactive, run_in_background, run_interactive
from .utils import is_interactive_terminal

from ..cli_util import (
    SafetyCLISubGroup,
    get_command_for,
    pass_safety_cli_obj,
    CommandType,
    FeatureType,
)
from safety.constants import (
    DEFAULT_EPILOG,
    CONTEXT_COMMAND_TYPE,
    CONTEXT_FEATURE_TYPE,
    EXIT_CODE_INVALID_AUTH_CREDENTIAL,
    get_required_config_setting,
)

from safety.error_handlers import handle_cmd_exception
from safety.decorators import notify

if TYPE_CHECKING:
    from safety.auth.models import Auth


console = Console()
system_scan_app = typer.Typer(rich_markup_mode="rich", name="system-scan")

CMD_RUN_NAME = "run"
DEFAULT_CMD = CMD_RUN_NAME

CLI_SYSTEM_SCAN_COMMAND_HELP = (
    "[BETA] Enable discovery and observability of software supply chain assets on local development machines.\n"
    "Example: safety system-scan run\n\n"
)


@system_scan_app.callback(
    invoke_without_command=True,
    cls=SafetyCLISubGroup,
    help=CLI_SYSTEM_SCAN_COMMAND_HELP,
    epilog=DEFAULT_EPILOG,
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        CONTEXT_COMMAND_TYPE: CommandType.BETA,
        CONTEXT_FEATURE_TYPE: FeatureType.PLATFORM,
    },
)
@pass_safety_cli_obj
def discover(ctx: typer.Context) -> None:
    """
    Discover and report software inventory from the system.

    Args:
        ctx (typer.Context): The Typer context object.
    """

    # If no subcommand is invoked, forward to the default command
    if not ctx.invoked_subcommand:
        default_command = get_command_for(
            name=DEFAULT_CMD, typer_instance=system_scan_app
        )
        return ctx.forward(default_command)


@system_scan_app.command(
    CMD_RUN_NAME,
)
@handle_cmd_exception
@notify
def run_discovery(
    ctx: typer.Context,
    background: bool = typer.Option(
        False,
        "--background",
        "-b",
        help="Start scan in background subprocess and exit immediately",
    ),
    sink: str = typer.Option(
        "platform",
        "--sink",
        help="Output sink type: 'jsonl' or 'platform'",
        hidden=True,
    ),
    platform_url: str = typer.Option(
        get_required_config_setting("SAFETY_PLATFORM_V2_URL"),
        "--platform-url",
        help="Base URL for Safety Platform sink",
        hidden=True,
    ),
    jsonl_path: str = typer.Option(
        "~/.safety/", "--jsonl-path", help="Path for JSONL sink output", hidden=True
    ),
):
    """
    Discover software supply chain assets on this local development machine.
    """
    auth: "Auth | None" = ctx.obj.auth

    if not auth or not auth.platform.is_using_auth_credentials():
        console.print(
            "You are not authenticated. Please run `safety auth login` first."
        )
        sys.exit(EXIT_CODE_INVALID_AUTH_CREDENTIAL)

    if background:
        proc = run_in_background(ctx)
        console.print(f"Scan started in background (PID: {proc.pid})")
        sys.exit(0)

    config = Config()

    if sink == "jsonl":
        sink_cfg = JsonlSinkConfig(
            path=str(Path(jsonl_path).expanduser()),
        )
    elif sink == "platform":
        sink_cfg = SafetyPlatformSinkConfig(
            base_url=platform_url, timeout=30, http_client=auth.platform.http_client
        )
    else:
        console.print(
            f"[red]Invalid sink type: {sink}. Must be 'jsonl' or 'platform'[/red]"
        )
        sys.exit(1)

    if not is_interactive_terminal():
        run_non_interactive(auth=auth, config=config, sink_cfg=sink_cfg)
    else:
        run_interactive(auth=auth, config=config, sink_cfg=sink_cfg)
