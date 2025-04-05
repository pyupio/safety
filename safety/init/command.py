from pathlib import Path
import platform
import threading
import time
from typing import TYPE_CHECKING, List, Optional, Iterator, Generator, Tuple, Dict, Any, Union
import webbrowser

from rich import box
from rich.align import Align
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .render import load_emoji, progressive_print, render_header, typed_print
from safety.scan.constants import DEFAULT_SPINNER
from safety.scan.init_scan import start_scan
from ..cli_util import CommandType, Console, FeatureType, SafetyCLICommand, SafetyCLISubGroup
from safety.error_handlers import handle_cmd_exception
import typer
import os


from safety.init.constants import (
    MSG_ANALYZE_CODEBASE_TITLE,
    MSG_AUTH_PROMPT,
    MSG_COMPLETE_SECURED,
    MSG_COMPLETE_TOOL_SECURED,
    MSG_FIREWALL_UNINSTALL,
    MSG_OPEN_DASHBOARD_PROMPT,
    MSG_SETUP_COMPLETE_SUBTITLE,
    MSG_SETUP_COMPLETE_TITLE,
    MSG_SETUP_NEXT_STEPS,
    MSG_SETUP_NEXT_STEPS_SUBTITLE,
    MSG_SETUP_PACKAGE_FIREWALL_DESCRIPTION,
    MSG_SETUP_PACKAGE_FIREWALL_NOTE_STATUS,
    MSG_SETUP_PACKAGE_FIREWALL_PROMPT,
    MSG_SETUP_PACKAGE_FIREWALL_RESULT,
    MSG_SETUP_PACKAGE_FIREWALL_TITLE,
    MSG_SETUP_CODEBASE_DESCRIPTION,
    MSG_SETUP_CODEBASE_PROMPT,
    MSG_SETUP_CODEBASE_TITLE,
    CODEBASE_INIT_CMD_NAME,
    CODEBASE_INIT_HELP,
    CODEBASE_INIT_DIRECTORY_HELP,
    MSG_WELCOME_TITLE,
    MSG_WELCOME_DESCRIPTION,
    MSG_NEED_AUTHENTICATION
)
from safety.init.main import create_project
from safety.console import main_console as console
from ..scan.command import scan
from ..scan.models import ScanOutput
from ..tool.main import (
    configure_system,
    configure_local_directory,
    find_local_tool_files,
    configure_alias,
)

from ..constants import CONTEXT_COMMAND_TYPE, CONTEXT_FEATURE_TYPE

from safety.decorators import notify
from safety.events.utils import emit_firewall_configured
from safety_schemas.models.events.payloads import AliasConfig, IndexConfig


if TYPE_CHECKING:
    from safety.models import SafetyCLI
    import typer
    from safety.scan.init_scan import ScanResult
    from safety_schemas.models import ReportModel, FileModel, ConfigModel, MetadataModel, TelemetryModel, ProjectModel

try:
    from typing import Annotated  # type: ignore
except ImportError:
    from typing_extensions import Annotated

init_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)



class InitScanState:
    """
    Class to track scan state for vulnerability scans
    
    Attributes:
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
        self.dependencies: int = 0
        self.critical: Optional[int] = None
        self.high: Optional[int] = None
        self.medium: Optional[int] = None
        self.low: Optional[int] = None
        self.fixes: int = 0
        self.fixed_vulns: int = 0
        self.codebase_url: Optional[str] = None
        self.completed: bool = False
        self.progress: int = 0
        self.status_message: Optional[str] = None
        self.status_action: Optional[str] = None
        self.current_file: Optional[str] = None


def generate_summary(state, spinner_phase=0):
    """
    Generate the summary text based on current scan state
    """
    text = Text()
    
    spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    
    text.append(f"Tested {state.dependencies} dependenc{'y' if state.dependencies == 1 else 'ies'} for security issues\n")
    text.append("\nFound:\n\n")
    
    total_vulns = 0
    if state.critical is not None and state.critical > 0:
        total_vulns += state.critical
    if state.high is not None and state.high > 0:
        total_vulns += state.high
    if state.medium is not None and state.medium > 0:
        total_vulns += state.medium
    if state.low is not None and state.low > 0:
        total_vulns += state.low
    
    # No vulnerabilities case
    if state.completed and total_vulns == 0:
        text.append("✅ No vulnerabilities found!\n\n")
    else:
        # Critical vulnerabilities - only show if scanning or if there are actual vulnerabilities
        if state.critical is None or state.critical > 0:
            text.append("🔥 CRITICAL: ", style="bold red")
            
            if state.critical is None:
                text.append(f"{spinner[spinner_phase % len(spinner)]} Scanning", style="dim red")
                text.append("\n")
            else:
                text.append(f"{state.critical} ", style="bold red")
                text.append(f"vulnerabilit{'y' if state.critical == 1 else 'ies'}\n")
        
        # High vulnerabilities - only show if scanning or if there are actual vulnerabilities
        if state.high is None or state.high > 0:
            text.append("🟡 HIGH: ", style="bold yellow")
            
            if state.high is None:
                text.append(f"{spinner[(spinner_phase + 2) % len(spinner)]} Scanning", style="dim yellow")
                text.append("\n")
            else:
                text.append(f"{state.high} ", style="bold yellow")
                text.append(f"vulnerabilit{'y' if state.high == 1 else 'ies'}\n")
        
        # Medium vulnerabilities - only show if scanning or if there are actual vulnerabilities
        if state.medium is None or state.medium > 0:
            text.append("!! MEDIUM: ", style="yellow")
            
            if state.medium is None:
                text.append(f"{spinner[(spinner_phase + 4) % len(spinner)]} Scanning", style="dim yellow")
                text.append("\n")
            else:
                text.append(f"{state.medium} ", style="yellow")
                text.append(f"vulnerabilit{'y' if state.medium == 1 else 'ies'}\n")
        
        # Low vulnerabilities - only show if scanning or if there are actual vulnerabilities
        if state.low is None or state.low > 0:
            text.append("ℹ️  LOW: ", style="bold blue")
            
            if state.low is None:
                text.append(f"{spinner[(spinner_phase + 6) % len(spinner)]} Scanning", style="dim blue")
                text.append("\n")
            else:
                text.append(f"{state.low} ", style="blue")
                text.append(f"vulnerabilit{'y' if state.low == 1 else 'ies'}\n")
        
        # Show fixes info if we have vulnerabilities
        if total_vulns > 0 and state.fixes is not None:
            text.append("\n")
            if state.fixes > 0:
                text.append("✨ ")
                text.append(f"{state.fixes} ", style="green")
                text.append("automatic ")
                text.append(f"{'fix' if state.fixes == 1 else 'fixes'} available, ")
                if state.fixed_vulns is not None:
                    text.append(f"resolving {state.fixed_vulns} vulnerabilities\n")
                else:
                    text.append(f"{spinner[(spinner_phase + 8) % len(spinner)]} calculating", style="dim green")
                    text.append("\n")
            else:
                text.append(" No automatic fixes available for these vulnerabilities\n")
    
    # Dashboard link if URL is available
    if state.codebase_url is not None:
        text.append("\n")
        text.append("🔎 View detailed results in your Safety dashboard:\n")
        text.append(f"🔗 {state.codebase_url}\n", style="blue underline")
        # text.append("💡 Open this in a new browser window now? (Y/n): ")
    elif state.completed:
        text.append("\n")
        # text.append("🔎 Generating your dashboard report...\n")
    
    return text


def generate_status_updates(state, spinner_phase=0):
    """
    Generate text displaying current status updates and progress information
    
    Args:
        state: The InitScanState object containing status information
        spinner_phase: Current phase of the spinner animation
        
    Returns:
        Rich Text object containing formatted status updates
    """
    text = Text()
    spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    
    # Display current status message if available
    if state.status_message:
        action_symbol = {
            "init": "🔄",
            "scanning": "🔍",
            "uploading": "☁️ ",
            "complete": "✅",
            "error": "❌"
        }.get(state.status_action, "ℹ️ ")
        
        text.append("\n")
        text.append(f"{action_symbol} Status: ", style="bold cyan")
        text.append(f"{state.status_message}\n", style="cyan")
        
        # If we're processing a file, show that
        if state.current_file and state.status_action == "scanning":
            text.append(f"📁 Current file: ", style="bold cyan")
            text.append(f"{state.current_file}\n", style="dim cyan")
            # Ensure progress is capped at 100%
            display_progress = min(state.progress, 100)
            text.append(f"📊 Progress: {display_progress}%\n", style="cyan")
    else:
        # If no status message, just show a spinner
        text.append(f"{spinner[spinner_phase % len(spinner)]} Scanning...", style="cyan")
        
    return text


def process_scan_results(scan_results: Iterator['ScanResult'], state: InitScanState) -> None:
    """Process the scan iterator and update state from typed result models
    
    Args:
        scan_results: Iterator yielding scan results from init_scan
        state: The InitScanState object to update with scan results
    """
    # Import the scan result types to handle typed results
    from safety.scan.init_scan import (
        ScanResultType, InitScanResult, ProgressScanResult, 
        CompleteScanResult, StatusScanResult, UploadingScanResult
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
                state.fixes = result.fixes
                state.fixed_vulns = result.fixed_vulns
                state.status_message = "Scan completed"
                state.status_action = "complete"
                
                # Update project URL if available
                if result.codebase_url:
                    state.codebase_url = result.codebase_url
                    
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


def init_scan_ui(ctx: 'typer.Context') -> InitScanState:
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
        target=process_scan_results, 
        args=(scan_results, state)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    # Handle UI updates in the main thread
    spinner_phase = 0
    render_header(MSG_ANALYZE_CODEBASE_TITLE.format(project_name=ctx.obj.project.id), emoji="🔍")
    time.sleep(0.8)
    
    # Display live UI with scan progress
    with Live(screen=True, refresh_per_second=10) as live:
        while not state.completed or scan_thread.is_alive():
            # Update spinner phase for animation
            spinner_phase = (spinner_phase + 1) % 10

            # Create a container for all UI elements
            container = Table.grid(padding=0, expand=True)
            container.add_row(None)
            container.add_row(Panel(generate_status_updates(state, spinner_phase), border_style="cyan", padding=(0, 1)))
            container.add_row(None)
            # Summary information shown below status updates
            summary = generate_summary(state, spinner_phase)
            container.add_row(summary)
            
            # Display the updated UI
            live.update(container)
            
            # Sleep to control animation speed
            time.sleep(0.1)
        time.sleep(0.8)
    
    # Final update to ensure completion state is shown
    console.print(generate_summary(state))

    if state.codebase_url:
        typed_print(MSG_OPEN_DASHBOARD_PROMPT, end_line=False)
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
    # TODO: check if tty is available
    do_init(ctx, directory, True)


def do_init(ctx: typer.Context, directory: Path, prompt_user: bool = True):
    """
    Initialize Safety CLI with the new onboarding flow.
    
    Args:
        ctx: The CLI context
        directory: The target directory to initialize
        prompt_user: Whether to prompt the user for input or use defaults
    """
    project_dir = directory.resolve()
    
    # Initialize configuration status
    alias_configured = AliasConfig(is_configured=False)
    index_configured = IndexConfig(is_configured=False)
    
    typed_print(MSG_WELCOME_TITLE)

    progressive_print(MSG_WELCOME_DESCRIPTION)

    obj: "SafetyCLI" = ctx.obj

    if not obj.auth or not obj.auth.client or not obj.auth.client.is_using_auth_credentials():
        console.print(MSG_NEED_AUTHENTICATION)
        auth_choice = Prompt.ask(
            MSG_AUTH_PROMPT,
            choices=["r", "l", "R", "L"],
            default="L",
            show_choices=False,
            show_default=True,
            console=console,
        ).lower()

        from safety.auth.cli import auth_app
        from safety.cli_util import get_command_for

        login_command = get_command_for(name="login", typer_instance=auth_app)
        register_command = get_command_for(
            name="register", typer_instance=auth_app
        )

        ctx.obj.only_auth_msg = True

        if auth_choice == "r":
            ctx.invoke(register_command)
        else:
            ctx.invoke(login_command)
        

    render_header(MSG_SETUP_PACKAGE_FIREWALL_TITLE, margin_right=1)
    emoji_check = f"[green]{load_emoji('✓')}[/green]"
    console.print(MSG_SETUP_PACKAGE_FIREWALL_DESCRIPTION)

    console.print(Syntax(MSG_FIREWALL_UNINSTALL, "bash", theme="monokai", background_color="default"))

    firewall_choice = Prompt.ask(
        MSG_SETUP_PACKAGE_FIREWALL_PROMPT,
        choices=["y", "n", "Y", "N"],
        default="y",
        show_default=False,
        show_choices=False,
        console=console,
    ).lower()

    org_slug = getattr(ctx.obj, "org", None) and getattr(ctx.obj.org, "slug", None)

    if firewall_choice == "y":        
        configured_index = configure_system(org_slug)
        configured_alias = configure_alias()
        if configured_alias is None:
            configured_alias = []

        # Only handle pip, assume pip is the first one
        configured_index = configured_index[:1]
        configured_alias = configured_alias[:1]
        console.print()

        # Aliased pip to safety
        configured = {}
        if configured_index:
            configured["index"] = configured_index

        if configured_alias:
            configured["alias"] = configured_alias

        if configured:
            for key, paths in configured.items():
                for path in paths:
                    if path:
                        if key == "index":
                            index_configured.is_configured = True
                            msg = "Configured pip’s global index"
                        else:
                            alias_configured.is_configured = True
                            msg = "Aliased pip to safety"

                        configured_msg = f"{emoji_check} {msg}"
                        if len(path.parts) > 1:
                            progressive_print([f"{configured_msg} (`{path}`)"])
                        else:
                            progressive_print([configured_msg])
                    else:
                        if key == "index":
                            index_configured.is_configured = False
                            msg = "pip’s global index"  
                        else:
                            alias_configured.is_configured = False
                            msg = "pip alias"
                        
                        error = Text()
                        error.append("x ", style="red bold")
                        error.append(f"Failed to configure {msg}")
                        progressive_print([error])

        else:
            error = Text()
            error.append("x ", style="red bold")
            error.append("Failed to configure system")
            progressive_print([error])

            # Naive approach, we'll add support for multiple tools soon.
            alias_configured.is_configured = False

        console.print(f"\n{emoji_check} Pip {MSG_SETUP_PACKAGE_FIREWALL_RESULT}")
        console.print(MSG_SETUP_PACKAGE_FIREWALL_NOTE_STATUS)

    render_header(MSG_SETUP_CODEBASE_TITLE, emoji="🔒")
    console.print(MSG_SETUP_CODEBASE_DESCRIPTION)

    if local_files := find_local_tool_files(project_dir):
        progressive_print([f"{load_emoji('📌')} We found a `{file.name}` file in this directory." for file in local_files])

        console.print()
        project_choice = Prompt.ask(
            MSG_SETUP_CODEBASE_PROMPT,
            choices=["y", "n", "Y", "N"],
            default="y",
            show_default=False,
            show_choices=False,
            console=console,
        ).lower()

        project_choice = "n"

        if project_choice == "y":
            configure_local_directory(
                project_dir,
                org_slug,
        )

    project_created, project_status = create_project(ctx, console, project_dir)

    if project_created:
        console.print("\n" + f"{ctx.obj.project.id} codebase {project_status} ✅")

    console.print()

    state = init_scan_ui(ctx)

    console.print()
    render_header(MSG_SETUP_COMPLETE_TITLE, emoji="🏆")

    typed_print(MSG_SETUP_COMPLETE_SUBTITLE)
    console.print()
    
    progressive_print([
        MSG_COMPLETE_TOOL_SECURED.format(firewall_url="https://platform.safetycli.com/firewall"),
        "",
        MSG_COMPLETE_SECURED.format(codebase_url=state.codebase_url)
    ])

    console.print()

    render_header(title=MSG_SETUP_NEXT_STEPS_SUBTITLE, emoji="🚀")
    console.line()

    progressive_print([Padding(Text.from_markup(line), (0, 0, 1, 0)) for line in MSG_SETUP_NEXT_STEPS])

    # Emit event for firewall configuration
    emit_firewall_configured(
        event_bus=ctx.obj.event_bus,
        alias_config=alias_configured,
        index_config=index_configured,
    )
