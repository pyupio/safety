import logging
from pathlib import Path
import sys
import threading
import time
from typing import (
    TYPE_CHECKING,
    Optional,
    Iterator,
)

from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from safety.codebase_utils import load_unverified_project_from_config
from safety.events.utils.emission import (
    emit_codebase_detection_status,
    emit_codebase_setup_completed,
    emit_init_exited,
    emit_init_scan_completed,
)
from safety.init.models import StepTracker
from safety_schemas.models.events.types import ToolType


from .render import (
    ask_codebase_setup,
    ask_continue,
    ask_firewall_setup,
    progressive_print,
    render_header,
    typed_print,
)
from safety.scan.init_scan import start_scan
from ..cli_util import (
    CommandType,
    FeatureType,
    SafetyCLICommand,
    SafetyCLISubGroup,
)
from safety.error_handlers import handle_cmd_exception
import typer


from safety.init.constants import (
    MSG_ANALYZE_CODEBASE_TITLE,
    MSG_CODEBASE_FAILED_TO_SCAN,
    MSG_CODEBASE_NOT_CONFIGURED,
    MSG_CODEBASE_URL_DESCRIPTION,
    MSG_COMPLETE_SECURED,
    MSG_COMPLETE_TOOL_SECURED,
    MSG_FIREWALL_UNINSTALL,
    MSG_LAST_MANUAL_STEP,
    MSG_NO_VULNERABILITIES_FOUND,
    MSG_NO_VULNS_CODEBASE_URL_DESCRIPTION,
    MSG_OPEN_DASHBOARD_PROMPT,
    MSG_SETUP_CODEBASE_NO_PROJECT,
    MSG_SETUP_COMPLETE_SUBTITLE,
    MSG_SETUP_COMPLETE_TITLE,
    MSG_SETUP_INCOMPLETE,
    MSG_SETUP_NEXT_STEPS,
    MSG_SETUP_NEXT_STEPS_MANUAL_STEP,
    MSG_SETUP_NEXT_STEPS_NO_PROJECT,
    MSG_SETUP_NEXT_STEPS_NO_VULNS,
    MSG_SETUP_NEXT_STEPS_SUBTITLE,
    MSG_SETUP_PACKAGE_FIREWALL_DESCRIPTION,
    MSG_SETUP_PACKAGE_FIREWALL_TITLE,
    MSG_SETUP_CODEBASE_DESCRIPTION,
    MSG_SETUP_CODEBASE_TITLE,
    CODEBASE_INIT_CMD_NAME,
    CODEBASE_INIT_HELP,
    CODEBASE_INIT_DIRECTORY_HELP,
    MSG_TOOLS_NOT_CONFIGURED,
    MSG_WELCOME_TITLE,
    MSG_WELCOME_DESCRIPTION,
)
from safety.init.main import create_project, launch_auth_if_needed, setup_firewall
from safety.console import (
    get_spinner_animation,
    main_console as console,
    should_use_ascii,
)
from ..tool.main import (
    configure_local_directory,
    find_local_tool_files,
)

from ..constants import CONTEXT_COMMAND_TYPE, CONTEXT_FEATURE_TYPE

from safety.decorators import notify
from safety.events.utils import emit_firewall_configured, emit_init_started
from safety_schemas.models.events.payloads import AliasConfig, IndexConfig, InitExitStep


if TYPE_CHECKING:
    import typer
    from safety.scan.init_scan import ScanResult

try:
    from typing import Annotated  # type: ignore
except ImportError:
    from typing_extensions import Annotated

init_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)

logger = logging.getLogger(__name__)


class InitScanState:
    """
    Class to track scan state for vulnerability scans

    Attributes:
        scan_id: ID of the scan
        dependencies: Number of dependencies found
        critical: Count of critical vulnerabilities
        high: Count of high severity vulnerabilities
        medium: Count of medium severity vulnerabilities
        low: Count of low severity vulnerabilities
        fixes: Number of fixes available
        fixed_vulns: Number of vulnerabilities with fixes
        url: URL to view the scan results
        completed: Whether the scan has completed
        progress: Percentage progress of the scan
        status_message: Current status message from the scanner
        status_action: Current action being performed by the scanner
        current_file: Current file being processed
    """

    def __init__(self):
        self.scan_id: Optional[str] = None
        self.dependencies: int = 0
        self.critical: int = 0
        self.high: int = 0
        self.medium: int = 0
        self.low: int = 0
        self.others: int = 0
        self.vulns_count: int = 0
        self.fixes: int = 0
        self.fixed_vulns: int = 0
        self.codebase_url: Optional[str] = None
        self.completed: bool = False
        self.progress: int = 0
        self.status_message: Optional[str] = None
        self.status_action: Optional[str] = None
        self.current_file: Optional[str] = None


def generate_summary(state: InitScanState, spinner_phase=0) -> Text:
    """
    Generate the summary text based on current scan state
    """
    spinner = get_spinner_animation()

    text_markup = f"Tested {state.dependencies} dependenc{'y' if state.dependencies == 1 else 'ies'} for security issues\n"
    text_markup += "\nFound:\n\n"

    categories = [
        {
            "name": "CRITICAL",
            "icon": ":fire:",
            "style": "bold red",
            "dim_style": "dim red",
            "count_attr": "critical",
            "spinner_offset": 0,
        },
        {
            "name": "HIGH",
            "icon": ":yellow_circle:",
            "style": "bold yellow",
            "dim_style": "dim yellow",
            "count_attr": "high",
            "spinner_offset": 2,
        },
        {
            "name": "MEDIUM",
            "icon": "!!",
            "style": "yellow",
            "dim_style": "dim yellow",
            "count_attr": "medium",
            "spinner_offset": 4,
        },
        {
            "name": "LOW",
            "icon": ":icon_info: ",
            "style": "bold blue",
            "dim_style": "dim blue",
            "count_attr": "low",
            "spinner_offset": 6,
        },
        {
            "name": "OTHER",
            "icon": "**",
            "style": "blue",
            "dim_style": "dim blue",
            "count_attr": "others",
            "spinner_offset": 8,
        },
    ]

    # No vulnerabilities case
    prepend_text_codebase_url = MSG_CODEBASE_URL_DESCRIPTION

    if state.completed and state.vulns_count <= 0:
        text_markup += MSG_NO_VULNERABILITIES_FOUND
        prepend_text_codebase_url = MSG_NO_VULNS_CODEBASE_URL_DESCRIPTION
    else:
        for category in categories:
            category_count = getattr(state, category["count_attr"])

            if state.completed and category_count == 0:
                continue

            style = category["style"]
            text_markup += f"[{style}]{category['icon']} {category['name']}: [/{style}]"

            if category_count > 0:
                vulns_word = f"vulnerabilit{'y' if category_count == 1 else 'ies'}"
                text_markup += f"[{style}]{category_count}[/{style}] {vulns_word}\n"
            else:
                spinner_status = spinner[
                    (spinner_phase + category["spinner_offset"]) % len(spinner)
                ]
                style = category["dim_style"]
                text_markup += f"[{style}]{spinner_status}[/{style}] Scanning\n"

        # Show fixes info if we have vulnerabilities
        if state.vulns_count > 0 and state.fixes is not None:
            text_markup += "\n"

            if state.fixes > 0:
                fix_word = f"fix{'' if state.fixes == 1 else 'es'}"
                vulns_word = f"vulnerabilit{'y' if state.fixed_vulns == 1 else 'ies'}"
                text_markup += f":sparkles: [green]{state.fixes}[/green] automatic {fix_word} available, resolving {state.fixed_vulns} {vulns_word}\n"
            else:
                text_markup += (
                    " No automatic fixes available for these vulnerabilities\n"
                )

    # Dashboard link if URL is available
    if state.codebase_url is not None:
        text_markup += f"\n{prepend_text_codebase_url}[blue underline]:link: {state.codebase_url}\n[/blue underline]"

    elif state.completed:
        text_markup += "\n"

    return console.render_str(text_markup)


def generate_status_updates(state: InitScanState, spinner_phase: int = 0) -> Text:
    """
    Generate text displaying current status updates and progress information

    Args:
        state: The InitScanState object containing status information
        spinner_phase: Current phase of the spinner animation

    Returns:
        Rich Text object containing formatted status updates
    """
    spinner = get_spinner_animation()

    markup_text = f"[cyan]{spinner[spinner_phase % len(spinner)]} Scanning...[/cyan]"

    # Display current status message if available
    if state.status_message:
        action_symbol = {
            "init": ":arrows_counterclockwise:",
            "scanning": ":magnifying_glass_tilted_left:",
            "uploading": ":cloud: ",
            "complete": ":white_heavy_check_mark:",
            "error": ":cross_mark:",
        }
        status_key = state.status_action if state.status_action is not None else "init"
        action_symbol = action_symbol.get(status_key, ":information_source: ")

        markup_text = f"\n[bold cyan]{action_symbol} Status: [/bold cyan][cyan]{state.status_message}[/cyan]\n"

        # If we're processing a file, show that
        if state.current_file and state.status_action == "scanning":
            markup_text += f"[bold cyan]:file_folder: Current file: [/bold cyan][dim cyan]{state.current_file}[/dim cyan]\n"

            # Ensure progress is capped at 100%
            display_progress = min(state.progress, 100)
            markup_text += f"[cyan]:bar_chart: Progress: {display_progress}%[/cyan]\n"

    return console.render_str(markup_text)


def process_scan_results(
    scan_results: Iterator["ScanResult"], state: InitScanState
) -> None:
    """Process the scan iterator and update state from typed result models

    Args:
        scan_results: Iterator yielding scan results from init_scan
        state: The InitScanState object to update with scan results
    """
    # Import the scan result types to handle typed results
    from safety.scan.init_scan import (
        ScanResultType,
    )

    try:
        for result in scan_results:
            # Now result is a typed model with proper attributes
            if result.type == ScanResultType.INIT:
                # Initial state with dependency count
                state.dependencies = result.dependencies
                state.status_message = "Initializing scan"
                state.status_action = "init"

            elif result.type == ScanResultType.PROGRESS:
                # Update all the state fields from the progress result
                # Type checker knows result is ProgressScanResult
                # Ensure progress never exceeds 100%
                state.progress = min(result.percent, 100)
                state.dependencies = result.dependencies

                # Track current file being processed
                state.current_file = result.file
                state.status_message = f"Processing {result.file}"
                state.status_action = "scanning"

                # Update severity counts if present
                if result.critical is not None:
                    state.critical = result.critical
                if result.high is not None:
                    state.high = result.high
                if result.medium is not None:
                    state.medium = result.medium
                if result.low is not None:
                    state.low = result.low
                if result.others is not None:
                    state.others = result.others

                # Update vulnerability count
                if result.vulns_count is not None:
                    state.vulns_count = result.vulns_count

                # Update fix information if present
                if result.fixes is not None:
                    state.fixes = result.fixes
                if result.fixed_vulns is not None:
                    state.fixed_vulns = result.fixed_vulns

            elif result.type == ScanResultType.STATUS:
                # Generic status update
                state.status_message = result.message
                state.status_action = result.action
                if result.percent is not None:
                    state.progress = min(result.percent, 100)

            elif result.type == ScanResultType.UPLOADING:
                # Status update for uploading phase
                state.status_message = result.message
                state.status_action = "uploading"
                if result.percent is not None:
                    state.progress = min(result.percent, 100)

            elif result.type == ScanResultType.COMPLETE:
                # Final update with complete data
                # Type checker knows result is CompleteScanResult
                state.progress = 100
                state.dependencies = result.dependencies
                state.critical = result.critical
                state.high = result.high
                state.medium = result.medium
                state.low = result.low
                state.others = result.others
                state.fixes = result.fixes
                state.fixed_vulns = result.fixed_vulns
                state.status_message = "Scan completed"
                state.status_action = "complete"
                state.vulns_count = result.vulns_count

                # Update project URL if available
                if result.codebase_url:
                    state.codebase_url = result.codebase_url

                if result.scan_id:
                    state.scan_id = result.scan_id

                # We're done processing
                state.completed = True

            # Add a small delay between updates to allow UI thread to refresh
            time.sleep(0.05)
    except Exception as e:
        console.print(f"Error processing scan results: {e}", style="bold red")
        state.status_message = f"Error: {str(e)}"
        state.status_action = "error"
    finally:
        # Ensure we mark as completed even if there was an exception
        state.completed = True


def init_scan_ui(ctx: "typer.Context", prompt_user: bool = False) -> InitScanState:
    """
    Initialize and run a scan for the init command, showing a live UI with scan progress.
    Uses the start_scan function to get an iterator of scan results and displays UI based on them.

    Args:
        ctx: The Typer context object containing configuration and project information
    """
    # Initialize state for tracking scan progress
    state = InitScanState()

    # Set up scan parameters and get the scan iterator
    target = ctx.obj.project.project_path.parent
    use_server_matching = False

    # Start the scan using the dedicated function
    scan_results = start_scan(
        ctx=ctx,
        target=target,
        use_server_matching=use_server_matching,
        auth_type=ctx.obj.auth.client.get_authentication_type(),
        is_authenticated=ctx.obj.auth.client.is_using_auth_credentials(),
        client=ctx.obj.auth.client,
        project=ctx.obj.project,
        platform_enabled=ctx.obj.platform_enabled,
    )

    # Process the scan results in a separate thread
    scan_thread = threading.Thread(
        target=process_scan_results, args=(scan_results, state)
    )
    scan_thread.daemon = True
    scan_thread.start()

    # Handle UI updates in the main thread
    spinner_phase = 0
    render_header(
        MSG_ANALYZE_CODEBASE_TITLE.format(project_name=ctx.obj.project.id),
        emoji=":magnifying_glass_tilted_left:",
    )
    time.sleep(0.8)

    # Detect if running on Windows
    is_windows = sys.platform == "win32" or should_use_ascii()

    # Alternate screen in Windows is buggy, so we disable it
    live_kwargs = {
        "refresh_per_second": 10,
        "screen": False if is_windows else True,
        "transient": False,
    }

    refresh_sleep = 0.1

    with Live(**live_kwargs) as live:
        while not state.completed or scan_thread.is_alive():
            # Update spinner phase for animation
            spinner_phase = (spinner_phase + 1) % 10

            # Summary information shown below status updates
            summary = generate_summary(state, spinner_phase)

            if is_windows:
                content = summary
            else:
                # Create a container for all UI elements
                container = Table.grid(padding=0, expand=True)
                container.add_row(None)
                container.add_row(
                    Panel(
                        generate_status_updates(state, spinner_phase),
                        border_style="cyan",
                        padding=(0, 1),
                    )
                )
                container.add_row(None)
                container.add_row(summary)
                content = container

            # Display the updated UI
            live.update(content)

            time.sleep(refresh_sleep)

        # Last sync
        if state.completed:
            live.update(generate_summary(state, spinner_phase))
        time.sleep(2)

    # Windows is not using alternate screen, so summary is already rendered
    if not is_windows:
        # Final update to ensure completion state is shown
        console.print(generate_summary(state))

    if state.codebase_url:
        typed_print(MSG_OPEN_DASHBOARD_PROMPT, end_line=False)
        should_open = "y"

        if prompt_user:
            should_open = Prompt.ask(
                "",
                choices=["y", "n", "Y", "N"],
                default="y",
                show_default=False,
                show_choices=False,
                console=console,
            ).lower()

        if should_open == "y":
            typer.launch(state.codebase_url)

    return state


@init_app.command(
    cls=SafetyCLICommand,
    help=CODEBASE_INIT_HELP,
    name=CODEBASE_INIT_CMD_NAME,
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
            help=CODEBASE_INIT_DIRECTORY_HELP,
        ),
    ] = Path("."),
):
    emit_init_started(ctx.obj.event_bus, ctx)
    # TODO: check if tty is available
    tracker = StepTracker()
    try:
        do_init(ctx, directory, tracker, prompt_user=console.is_interactive)
    except KeyboardInterrupt as e:
        emit_init_exited(ctx.obj.event_bus, ctx, exit_step=tracker.current_step)
        raise e


def do_init(
    ctx: typer.Context, directory: Path, tracker: StepTracker, prompt_user: bool = True
):
    """
    Initialize Safety CLI with the new onboarding flow.

    Args:
        ctx: The CLI context
        directory: The target directory to initialize
        prompt_user: Whether to prompt the user for input or use defaults
    """
    project_dir = directory.resolve()

    typed_print(MSG_WELCOME_TITLE)
    progressive_print(MSG_WELCOME_DESCRIPTION)

    tracker.current_step = InitExitStep.PRE_AUTH
    org_slug = launch_auth_if_needed(ctx, console)
    tracker.current_step = InitExitStep.POST_AUTH

    render_header(MSG_SETUP_PACKAGE_FIREWALL_TITLE, margin_right=1)
    console.print(MSG_SETUP_PACKAGE_FIREWALL_DESCRIPTION)

    console.print(
        Syntax(
            MSG_FIREWALL_UNINSTALL, "bash", theme="monokai", background_color="default"
        )
    )

    completed_tools = ""
    all_completed = False
    all_missing = True

    status = {
        ToolType.PIP: {
            "alias": AliasConfig(is_configured=False),
            "index": IndexConfig(is_configured=False),
        },
        ToolType.POETRY: {
            "alias": AliasConfig(is_configured=False),
            "index": IndexConfig(is_configured=False),
        },
        ToolType.UV: {
            "alias": AliasConfig(is_configured=False),
            "index": IndexConfig(is_configured=False),
        },
    }

    tracker.current_step = InitExitStep.PRE_FIREWALL_SETUP
    if ask_firewall_setup(ctx, prompt_user):
        completed_tools, all_completed, all_missing, status = setup_firewall(
            ctx, status, org_slug, console
        )
        console.line()
        ask_continue(ctx, prompt_user)
        console.line()

    tracker.current_step = InitExitStep.POST_FIREWALL_SETUP

    render_header(MSG_SETUP_CODEBASE_TITLE, emoji=":locked:")
    console.print(MSG_SETUP_CODEBASE_DESCRIPTION)

    project_scan_state = None

    tracker.current_step = InitExitStep.PRE_CODEBASE_SETUP
    local_files = find_local_tool_files(project_dir)

    emit_codebase_detection_status(
        event_bus=ctx.obj.event_bus,
        ctx=ctx,
        detected=any(local_files),
        detected_files=local_files if local_files else None,
    )

    if local_files:
        progressive_print(
            [
                f":pushpin: We found a `{file.name}` file in this directory."
                for file in local_files
            ]
        )

        console.line()

        if ask_codebase_setup(ctx, prompt_user):
            unverified_project = load_unverified_project_from_config(
                project_root=project_dir
            )
            link_behavior = "prompt"

            if unverified_project.created:
                link_behavior = "always"

            project_created, project_status = create_project(
                ctx,
                console,
                project_dir,
                unverified_project=unverified_project,
                link_behavior=link_behavior,
            )

            configure_local_directory(project_dir, org_slug, ctx.obj.project.id)

            emit_codebase_setup_completed(
                event_bus=ctx.obj.event_bus,
                ctx=ctx,
                is_created=project_created,
                codebase_id=ctx.obj.project.id if project_created else None,
            )

            if project_created:
                console.print(
                    "\n"
                    + f"{ctx.obj.project.id} codebase {project_status} :white_heavy_check_mark:"
                )
            else:
                progressive_print([":x: Failed to create codebase"])

            console.line()

            tracker.current_step = InitExitStep.PRE_SCAN
            project_scan_state = init_scan_ui(ctx, prompt_user)
            tracker.current_step = InitExitStep.POST_SCAN
            emit_init_scan_completed(
                event_bus=ctx.obj.event_bus,
                ctx=ctx,
                scan_id=project_scan_state.scan_id,
            )
    else:
        console.print(MSG_SETUP_CODEBASE_NO_PROJECT)

    tracker.current_step = InitExitStep.POST_CODEBASE_SETUP

    console.line()
    render_header(MSG_SETUP_COMPLETE_TITLE, emoji=":trophy:")

    is_setup_complete = all_completed and project_scan_state

    wrap_up_msg = []

    if all_completed:
        wrap_up_msg.append(
            MSG_COMPLETE_TOOL_SECURED.format(
                tools=completed_tools,
                firewall_url="https://platform.safetycli.com/firewall/",
            )
        )
    elif all_missing:
        wrap_up_msg.append(MSG_TOOLS_NOT_CONFIGURED)
    else:
        wrap_up_msg.append(MSG_SETUP_INCOMPLETE)

    wrap_up_msg.append("")

    if project_scan_state:
        if project_scan_state.scan_id:
            wrap_up_msg.append(
                MSG_COMPLETE_SECURED.format(
                    codebase_url=project_scan_state.codebase_url
                )
            )
        else:
            msg = (
                project_scan_state.status_message
                if project_scan_state.status_message
                else "Unknown"
            )
            wrap_up_msg.append(MSG_CODEBASE_FAILED_TO_SCAN.format(reason=msg))
    else:
        wrap_up_msg.append(MSG_CODEBASE_NOT_CONFIGURED)

    if wrap_up_msg:
        progressive_print(wrap_up_msg)
        console.line()

        if is_setup_complete:
            typed_print(MSG_SETUP_COMPLETE_SUBTITLE)
            console.line()
            typed_print(MSG_LAST_MANUAL_STEP)
            console.line()

    render_header(title=MSG_SETUP_NEXT_STEPS_SUBTITLE, emoji=":rocket:")
    console.line()

    next_steps_msg = MSG_SETUP_NEXT_STEPS

    if not project_scan_state:
        next_steps_msg = MSG_SETUP_NEXT_STEPS_NO_PROJECT
    elif project_scan_state.vulns_count <= 0:
        next_steps_msg = MSG_SETUP_NEXT_STEPS_NO_VULNS

    progressive_print(
        [Padding(console.render_str(line), (0, 0, 1, 0)) for line in next_steps_msg]
    )

    console.line()
    typed_print(MSG_SETUP_NEXT_STEPS_MANUAL_STEP, delay=0.04)
    console.line()

    # Emit event for firewall configuration
    emit_firewall_configured(
        event_bus=ctx.obj.event_bus,
        status=status,
    )
    tracker.current_step = InitExitStep.COMPLETED
