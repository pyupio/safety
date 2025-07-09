# type: ignore
from enum import Enum
import logging
from pathlib import Path

import json
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Callable

from safety.constants import EXIT_CODE_VULNERABILITIES_FOUND, DEFAULT_EPILOG
from safety.safety import process_fixes_scan
from safety.scan.finder.handlers import ECOSYSTEM_HANDLER_MAPPING, FileHandler
from safety.scan.validators import output_callback, save_as_callback
from safety.util import pluralize
from ..cli_util import SafetyCLICommand, SafetyCLISubGroup
from safety.error_handlers import handle_cmd_exception
from rich.padding import Padding
import typer
from safety.auth.constants import SAFETY_PLATFORM_URL
from safety.cli_util import get_command_for, get_git_branch_name
from rich.console import Console

from safety.decorators import notify
from safety.errors import SafetyError

from safety.scan.finder import FileFinder
from safety.scan.constants import (
    CMD_PROJECT_NAME,
    CMD_SYSTEM_NAME,
    DEFAULT_SPINNER,
    SCAN_OUTPUT_HELP,
    SCAN_POLICY_FILE_HELP,
    SCAN_SAVE_AS_HELP,
    SCAN_TARGET_HELP,
    SYSTEM_SCAN_OUTPUT_HELP,
    SYSTEM_SCAN_POLICY_FILE_HELP,
    SYSTEM_SCAN_SAVE_AS_HELP,
    SYSTEM_SCAN_TARGET_HELP,
    SCAN_APPLY_FIXES,
    SCAN_DETAILED_OUTPUT,
    CLI_SCAN_COMMAND_HELP,
    CLI_SYSTEM_SCAN_COMMAND_HELP,
)
from safety.scan.decorators import (
    inject_metadata,
    scan_project_command_init,
    scan_system_command_init,
)
from safety.scan.finder.file_finder import should_exclude
from ..codebase_utils import load_unverified_project_from_config
from safety.scan.main import load_policy_file, process_files, save_report_as
from safety.scan.models import (
    ScanExport,
    ScanOutput,
    SystemScanExport,
    SystemScanOutput,
)
from safety.scan.render import (
    print_detected_ecosystems_section,
    print_fixes_section,
    print_summary,
    render_scan_html,
    render_scan_spdx,
    render_to_console,
)
from safety_schemas.models import (
    Ecosystem,
    FileModel,
    FileType,
    ProjectModel,
    ReportModel,
    ScanType,
    VulnerabilitySeverityLabels,
    SecurityUpdates,
    Vulnerability,
    Stage,
)
from safety.scan.fun_mode.easter_eggs import run_easter_egg

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

LOG = logging.getLogger(__name__)


# CONSTANTS
# Icons and Emojis
ICON_PENCIL = ":pencil:"
ICON_CHECKMARK = ":white_check_mark:"
ICON_STOP_SIGN = ":stop_sign:"
ICON_UPLOAD = ":arrow_up:"

# Rich Markup Tags
TAG_FILE_TITLE_START = "[file_title]"
TAG_FILE_TITLE_END = "[/file_title]"
TAG_DEP_NAME_START = "[dep_name]"
TAG_DEP_NAME_END = "[/dep_name]"
TAG_SPECIFIER_START = "[specifier]"
TAG_SPECIFIER_END = "[/specifier]"
TAG_BRIEF_SEVERITY = "[brief_severity]"
TAG_REM_SEVERITY = "[rem_severity]"
TAG_RECOMMENDED_VER = "[recommended_ver]"

# Thresholds
CRITICAL_VULN_THRESHOLD = 3
MIN_CRITICAL_COUNT = 0
MIN_DETAILED_OUTPUT_THRESHOLD = 3

# Padding
PADDING_VALUES = (0, 0, 0, 1)

# Rich Defaults
RICH_DEFAULT_KWARGS = {"emoji": True, "overflow": "crop"}

# Messages
WAIT_MSG_PROCESSING_REPORT = "Processing report"
WAIT_MSG_FETCHING_DB = "Fetching Safety's vulnerability database..."
WAIT_MSG_SCANNING_DIRECTORY = "Scanning project directory"
WAIT_MSG_ANALYZING_TARGETS = (
    "Analyzing {0} files and environments for security findings"
)

MSG_UPLOADING_REPORT = "Uploading report to: {0}"
MSG_REPORT_UPLOADED = "Report uploaded"
MSG_PROJECT_DASHBOARD = "Project dashboard: [link]{0}[/link]"
MSG_SYSTEM_SCAN_REPORT = "System scan report: [link]{0}[/link]"

MSG_AUTH_REQUIRED = "Authentication required. Please run 'safety auth login' to authenticate before using this command."

MSG_DEPENDENCY_VULNERABILITIES_DETECTED = "Dependency vulnerabilities detected:"

MSG_NO_KNOWN_FIX = "No known fix for [dep_name]{0}[/dep_name][specifier]{1}[/specifier] to fix [number]{2}[/number] {3}"
MSG_RECOMMENDED_UPDATE = (
    "[rem_brief]Update {0} to {1}=={2}[/rem_brief] to fix [number]{3}[/number] {4}"
)
MSG_NO_VULNERABILITIES = "Versions of {0} with no known vulnerabilities: [recommended_ver]{1}[/recommended_ver]"

MSG_LEARN_MORE = "Learn more: [link]{0}[/link]"

MSG_NO_ISSUES_FOUND = (
    f"{ICON_CHECKMARK} [file_title]{{0}}: No issues found.[/file_title]"
)

MSG_SAFETY_UPDATES_RUNNING = "Safety updates running"
MSG_EXIT_CODE_FAILURE = ":stop_sign: Scan-failing vulnerabilities were found, returning non-zero exit code: {0}"
MSG_EXIT_CODE_SUCCESS = (
    "No scan-failing vulnerabilities were matched, returning success exit code: 0"
)

cli_apps_opts = {"rich_markup_mode": "rich", "cls": SafetyCLISubGroup}
scan_project_app = typer.Typer(**cli_apps_opts)
scan_system_app = typer.Typer(**cli_apps_opts)


class ScannableEcosystems(Enum):
    """Enum representing scannable ecosystems."""

    PYTHON = Ecosystem.PYTHON.value


def process_report(
    obj: Any,
    console: Console,
    report: ReportModel,
    output: str,
    save_as: Optional[Tuple[str, Path]],
    detailed_output: bool = False,
    filter_keys: Optional[List[str]] = None,
    **kwargs,
) -> Optional[str]:
    """
    Processes and outputs the report based on the given parameters.

    Args:
        obj (Any): The context object.
        console (Console): The console object.
        report (ReportModel): The report model.
        output (str): The output format.
        save_as (Optional[Tuple[str, Path]]): The save-as format and path.
        detailed_output (bool): Whether detailed output is enabled.
        filter_keys (Optional[List[str]]): Keys to filter from the JSON output.
        kwargs: Additional keyword arguments.

    Returns:
        Optional[str]: The URL of the report if uploaded, otherwise None.
    """
    with console.status(WAIT_MSG_PROCESSING_REPORT, spinner=DEFAULT_SPINNER) as status:
        json_format = report.as_v30().json()

    export_type, export_path = None, None

    if save_as:
        export_type, export_path = save_as
        export_type = ScanExport(export_type)

    output = ScanOutput(output)

    report_to_export = None
    report_to_output = None

    with console.status(WAIT_MSG_PROCESSING_REPORT, spinner=DEFAULT_SPINNER) as status:
        spdx_format, html_format = None, None

        if ScanExport.is_format(export_type, ScanExport.SPDX) or ScanOutput.is_format(
            output, ScanOutput.SPDX
        ):
            spdx_version = None
            if export_type:
                spdx_version = (
                    export_type.version
                    if export_type.version
                    and ScanExport.is_format(export_type, ScanExport.SPDX)
                    else None
                )

            if not spdx_version and output:
                spdx_version = (
                    output.version
                    if output.version and ScanOutput.is_format(output, ScanOutput.SPDX)
                    else None
                )

            spdx_format = render_scan_spdx(report, obj, spdx_version=spdx_version)

        if export_type is ScanExport.HTML or output is ScanOutput.HTML:
            html_format = render_scan_html(report, obj)

        save_as_format_mapping = {
            ScanExport.JSON: json_format,
            ScanExport.HTML: html_format,
            ScanExport.SPDX: spdx_format,
            ScanExport.SPDX_2_3: spdx_format,
            ScanExport.SPDX_2_2: spdx_format,
        }

        output_format_mapping = {
            ScanOutput.JSON: json_format,
            ScanOutput.HTML: html_format,
            ScanOutput.SPDX: spdx_format,
            ScanOutput.SPDX_2_3: spdx_format,
            ScanOutput.SPDX_2_2: spdx_format,
        }

        report_to_export = save_as_format_mapping.get(export_type, None)
        report_to_output = output_format_mapping.get(output, None)

        if report_to_export:
            msg = f"Saving {export_type} report at: {export_path}"
            status.update(msg)
            LOG.debug(msg)
            save_report_as(
                report.metadata.scan_type,
                export_type,
                Path(export_path),
                report_to_export,
            )
        report_url = None

        if obj.platform_enabled:
            status.update(
                console.render_str(
                    f"{ICON_UPLOAD} {MSG_UPLOADING_REPORT.format(SAFETY_PLATFORM_URL)}"
                )
            )
            try:
                result = obj.auth.client.upload_report(json_format)
                status.update(MSG_REPORT_UPLOADED)
                report_url = f"{SAFETY_PLATFORM_URL}{result['url']}"
            except Exception as e:
                raise e

        if output is ScanOutput.SCREEN:
            console.print()
            lines = []

            if obj.platform_enabled and report_url:
                if report.metadata.scan_type is ScanType.scan:
                    project_url = f"{SAFETY_PLATFORM_URL}{obj.project.url_path}"
                    # Get the current branch name
                    branch_name = get_git_branch_name()

                    # Append the branch name if available
                    if branch_name:
                        project_url_with_branch = f"{project_url}?branch={branch_name}"
                    else:
                        project_url_with_branch = project_url

                    lines.append(MSG_PROJECT_DASHBOARD.format(project_url_with_branch))

                elif report.metadata.scan_type is ScanType.system_scan:
                    lines.append(MSG_SYSTEM_SCAN_REPORT.format(report_url))

            for line in lines:
                console.print(line, emoji=True)

    if output.is_silent():
        console.quiet = False

        if output is ScanOutput.JSON or ScanOutput.is_format(output, ScanOutput.SPDX):
            if output is ScanOutput.JSON:
                if detailed_output:
                    report_to_output = add_cve_details_to_report(
                        report_to_output, obj.project.files
                    )

                if filter_keys:
                    report_to_output = filter_json_keys(report_to_output, filter_keys)

                kwargs = {"json": report_to_output}
            else:
                kwargs = {"data": report_to_output}
            console.print_json(**kwargs)

        else:
            console.print(report_to_output)

        console.quiet = True

    return report_url


def filter_json_keys(json_string: str, keys: List[str]) -> str:
    """
    Filters the given JSON string by the specified top-level keys.

    Args:
        json_string (str): The JSON string to filter.
        keys (List[str]): List of top-level keys to include in the output.

    Returns:
        str: A JSON string containing only the specified keys.
    """
    report_dict = json.loads(json_string)
    filtered_data = {key: report_dict[key] for key in keys if key in report_dict}
    return json.dumps(filtered_data, indent=4)


def filter_valid_cves(vulnerabilities: List[Any]) -> List[Dict[str, Any]]:
    """
    Filters and returns valid CVE details from a list of vulnerabilities.

    Args:
        vulnerabilities (List[Any]): A list of vulnerabilities, which may include invalid data types.

    Returns:
        List[Dict[str, Any]]: A list of filtered CVE details that are either strings or dictionaries.
    """
    return [
        cve for cve in vulnerabilities if isinstance(cve, str) or isinstance(cve, dict)
    ]  # type:ignore


def sort_cve_data(cve_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sorts CVE details by severity in descending order.

    Args:
        cve_data (List[Dict[str, Any]]): A list of CVE details dictionaries, each containing a 'severity' key.

    Returns:
        List[Dict[str, Any]]: The sorted list of CVE details, prioritized by severity (e.g., CRITICAL > HIGH > MEDIUM).
    """
    severity_order = {
        key.name: id for (id, key) in enumerate(VulnerabilitySeverityLabels)
    }
    return sorted(
        cve_data,
        key=lambda x: severity_order.get(x["severity"].upper(), 0),
        reverse=True,
    )


def generate_cve_details(files: List[FileModel]) -> List[Dict[str, Any]]:
    """
    Generate CVE details from the scanned files.

    Args:
        files (List[FileModel]): List of scanned file models.

    Returns:
        List[Dict[str, Any]]: List of CVE details sorted by severity.
    """
    cve_data = []
    for file in files:
        for spec in file.results.get_affected_specifications():
            for vuln in spec.vulnerabilities:
                if vuln.CVE:
                    cve_data.append(
                        {
                            "package": spec.name,
                            "affected_version": str(spec.specifier),
                            "safety_vulnerability_id": vuln.vulnerability_id,
                            "CVE": filter_valid_cves(vuln.CVE),
                            "more_info": vuln.more_info_url,
                            "advisory": vuln.advisory,
                            "severity": vuln.severity.cvssv3.get(
                                "base_severity", "Unknown"
                            )
                            if vuln.severity and vuln.severity.cvssv3
                            else "Unknown",
                        }
                    )
    return sort_cve_data(cve_data)


def add_cve_details_to_report(report_to_output: str, files: List[FileModel]) -> str:
    """
    Add CVE details to the JSON report output.

    Args:
        report_to_output (str): The current JSON string of the report.
        files (List[FileModel]): List of scanned files containing vulnerability data.

    Returns:
        str: The updated JSON string with CVE details added.
    """
    cve_details = generate_cve_details(files)
    report_dict = json.loads(report_to_output)
    report_dict["cve_details"] = cve_details
    return json.dumps(report_dict)


def generate_updates_arguments() -> List:
    """
    Generates a list of file types and update limits for apply fixes.

    Returns:
        List: A list of file types and update limits.
    """
    fixes = []
    limit_type = SecurityUpdates.UpdateLevel.PATCH
    DEFAULT_FILE_TYPES = [
        FileType.REQUIREMENTS_TXT,
        FileType.PIPENV_LOCK,
        FileType.POETRY_LOCK,
        FileType.VIRTUAL_ENVIRONMENT,
    ]
    fixes.extend(
        [(default_file_type, limit_type) for default_file_type in DEFAULT_FILE_TYPES]
    )

    return fixes


def validate_authentication(ctx: typer.Context) -> None:
    """
    Validates that the user is authenticated.

    Args:
        ctx (typer.Context): The Typer context object.

    Raises:
        SafetyError: If the user is not authenticated.
    """
    if not ctx.obj.metadata.authenticated:
        raise SafetyError(MSG_AUTH_REQUIRED)


def generate_fixes_target(apply_updates: bool) -> List:
    """
    Generates a list of update targets if `apply_updates` is enabled.

    Args:
        apply_updates (bool): Whether to generate fixes target.

    Returns:
        List: A list of update targets if enabled, otherwise an empty list.
    """
    return generate_updates_arguments() if apply_updates else []


def validate_save_as(
    ctx: typer.Context, save_as: Optional[Tuple[ScanExport, Path]]
) -> None:
    """
    Ensures the `save_as` parameters are valid.

    Args:
        ctx (typer.Context): The Typer context object.
        save_as (Optional[Tuple[ScanExport, Path]]): The save-as parameters.
    """
    if not all(save_as):
        ctx.params["save_as"] = None


def initialize_file_finder(
    ctx: typer.Context,
    target: Path,
    console: Optional[Console],
    ecosystems: List[Ecosystem],
) -> FileFinder:
    """
    Initializes the FileFinder for scanning files in the target directory.

    Args:
        ctx (typer.Context): The Typer context object.
        target (Path): The target directory to scan.
        console (Optional[Console]): The console object for logging.
        ecosystems (List[Ecosystem]): The list of scannable ecosystems.

    Returns:
        FileFinder: An initialized FileFinder object.
    """
    to_include = {
        file_type: paths
        for file_type, paths in ctx.obj.config.scan.include_files.items()
        if file_type.ecosystem in ecosystems
    }

    file_finder = FileFinder(
        target=target,
        ecosystems=ecosystems,
        max_level=ctx.obj.config.scan.max_depth,
        exclude=ctx.obj.config.scan.ignore,
        include_files=to_include,
    )

    # Download necessary assets for each handler
    for handler in file_finder.handlers:
        if handler.ecosystem:
            if console:
                with console.status(WAIT_MSG_FETCHING_DB, spinner=DEFAULT_SPINNER):
                    handler.download_required_assets(ctx.obj.auth.client)
            else:
                handler.download_required_assets(ctx.obj.auth.client)

    return file_finder


def scan_project_directory(
    file_finder: FileFinder, console: Optional[Console]
) -> Tuple[Path, Dict]:
    """
    Scans the project directory and identifies relevant files for analysis.

    Args:
        file_finder (FileFinder): Initialized file finder object.
        console (Console): Console for logging output.

    Returns:
        Tuple[Path, Dict]: The base path of the project and a dictionary of file paths grouped by type.
    """
    if console:
        with console.status(WAIT_MSG_SCANNING_DIRECTORY, spinner=DEFAULT_SPINNER):
            path, file_paths = file_finder.search()
            print_detected_ecosystems_section(
                console, file_paths, include_safety_prjs=True
            )
    else:
        path, file_paths = file_finder.search()

    return path, file_paths


def detect_dependency_vulnerabilities(
    console: Console, dependency_vuln_detected: bool
) -> bool:
    """
    Prints a message indicating that dependency vulnerabilities were detected.

    Args:
        console (Console): The console object for printing.
        dependency_vuln_detected (bool): Whether vulnerabilities have been detected.

    Returns:
        bool: True if vulnerabilities are detected, False otherwise.
    """
    if not dependency_vuln_detected:
        console.print()
        console.print(MSG_DEPENDENCY_VULNERABILITIES_DETECTED)
        return True
    return dependency_vuln_detected


def print_file_info(console: Console, path: Path, target: Path) -> None:
    """
    Prints the file information for vulnerabilities.

    Args:
        console (Console): The console object for printing.
        path (Path): The file path of the current file.
        target (Path): The base path to which the file path is relative.
    """
    console.print()
    msg = f"{ICON_PENCIL} {TAG_FILE_TITLE_START}{path.relative_to(target)}:{TAG_FILE_TITLE_END}"
    console.print(msg)


def sort_and_filter_vulnerabilities(
    vulnerabilities: List[Any], key_func: Callable[[Any], int], reverse: bool = True
) -> List[Any]:
    """
    Sorts and filters vulnerabilities.

    Args:
        vulnerabilities (List[Any]): A list of vulnerabilities to sort and filter.
        key_func (Callable[[Any], int]): A function to determine the sort key.
        reverse (bool): Whether to sort in descending order (default is True).

    Returns:
        List[Any]: The sorted and filtered list of vulnerabilities.
    """
    return sorted(
        [vuln for vuln in vulnerabilities if not vuln.ignored],
        key=key_func,
        reverse=reverse,
    )


def count_critical_vulnerabilities(vulnerabilities: List[Vulnerability]) -> int:
    """
    Count the number of critical vulnerabilities in a list of vulnerabilities.

    Args:
        vulnerabilities (List[Vulnerability]): List of vulnerabilities to evaluate.

    Returns:
        int: The number of vulnerabilities with a critical severity level.
    """
    return sum(
        1
        for vuln in vulnerabilities
        if vuln.severity
        and vuln.severity.cvssv3
        and vuln.severity.cvssv3.get("base_severity", "none").lower()
        == VulnerabilitySeverityLabels.CRITICAL.value.lower()
    )


def generate_vulnerability_message(
    spec_name: str,
    spec_raw: str,
    vulns_found: int,
    critical_vulns_count: int,
    vuln_word: str,
) -> str:
    """
    Generate a formatted message for vulnerabilities in a specific dependency.

    Args:
        spec_name (str): Name of the dependency.
        spec_raw (str): Raw specification string of the dependency.
        vulns_found (int): Number of vulnerabilities found.
        critical_vulns_count (int): Number of critical vulnerabilities found.
        vuln_word (str): Pluralized form of the word "vulnerability."

    Returns:
        str: Formatted vulnerability message.
    """
    msg = f"{TAG_DEP_NAME_START}{spec_name}{TAG_DEP_NAME_END}{TAG_SPECIFIER_START}{spec_raw.replace(spec_name, '')}{TAG_SPECIFIER_END} [{vulns_found} {vuln_word} found"

    if (
        vulns_found > CRITICAL_VULN_THRESHOLD
        and critical_vulns_count > MIN_CRITICAL_COUNT
    ):
        msg += f", {TAG_BRIEF_SEVERITY}including {critical_vulns_count} critical severity {pluralize('vulnerability', critical_vulns_count)}{TAG_BRIEF_SEVERITY}"
    return msg


def render_vulnerabilities(
    vulns_to_report: List[Vulnerability], console: Console, detailed_output: bool
) -> None:
    """
    Render vulnerabilities to the console.

    Args:
        vulns_to_report (List[Vulnerability]): List of vulnerabilities to render.
        console (Console): Console object for printing.
        detailed_output (bool): Whether to display detailed output.
    """
    for vuln in vulns_to_report:
        render_to_console(
            vuln,
            console,
            rich_kwargs=RICH_DEFAULT_KWARGS,
            detailed_output=detailed_output,
        )


def generate_remediation_details(
    spec: Any, vuln_word: str, critical_vulns_count: int
) -> Tuple[List[str], int, int]:
    """
    Generate remediation details for a specific dependency.

    Args:
        spec (Any): Dependency specification object.
        vuln_word (str): Pluralized word for vulnerabilities.
        critical_vulns_count (int): Number of critical vulnerabilities.

    Returns:
        Tuple[List[str], int, int]: A tuple containing:
            - List of remediation lines.
            - Total resolved vulnerabilities.
            - Fixes count.
    """
    lines = []
    total_resolved_vulns = 0
    fixes_count = 0

    if not spec.remediation.recommended:
        lines.append(
            MSG_NO_KNOWN_FIX.format(
                spec.name,
                spec.raw.replace(spec.name, ""),
                spec.remediation.vulnerabilities_found,
                vuln_word,
            )
        )
    else:
        total_resolved_vulns += spec.remediation.vulnerabilities_found
        msg = MSG_RECOMMENDED_UPDATE.format(
            spec.raw,
            spec.name,
            spec.remediation.recommended,
            spec.remediation.vulnerabilities_found,
            vuln_word,
        )

        if (
            spec.remediation.vulnerabilities_found > CRITICAL_VULN_THRESHOLD
            and critical_vulns_count > MIN_CRITICAL_COUNT
        ):
            msg += f", {TAG_REM_SEVERITY}including {critical_vulns_count} critical severity {pluralize('vulnerability', critical_vulns_count)}{TAG_REM_SEVERITY} {ICON_STOP_SIGN}"

        fixes_count += 1
        lines.append(msg)

        if spec.remediation.other_recommended:
            other_versions = "[/recommended_ver], [recommended_ver]".join(
                spec.remediation.other_recommended
            )
            lines.append(MSG_NO_VULNERABILITIES.format(spec.name, other_versions))

    return lines, total_resolved_vulns, fixes_count


def should_display_fix_suggestion(
    ctx: typer.Context,
    analyzed_file: Any,
    affected_specifications: List[Any],
    apply_updates: bool,
) -> bool:
    """
    Determine whether to display a fix suggestion based on the current context and file analysis.

    Args:
        ctx (typer.Context): The Typer context object.
        analyzed_file (Any): The file currently being analyzed.
        affected_specifications (List[Any]): List of affected specifications.
        apply_updates (bool): Whether fixes are being applied.

    Returns:
        bool: True if the fix suggestion should be displayed, False otherwise.
    """
    return (
        ctx.obj.auth.stage == Stage.development
        and analyzed_file.ecosystem == Ecosystem.PYTHON
        and analyzed_file.file_type == FileType.REQUIREMENTS_TXT
        and any(affected_specifications)
        and not apply_updates
    )


def process_file_fixes(
    file_to_fix: FileModel,
    specs_to_fix: List[Any],
    options: Dict,
    policy_limits: List[SecurityUpdates.UpdateLevel],
    output: ScanOutput,
    no_output: bool,
    prompt: bool,
) -> Any:
    """
    Process fixes for a given file and its specifications.

    Args:
        file_to_fix (FileModel): The file to fix.
        specs_to_fix (List[Any]): The specifications to fix in the file.
        options (Dict): Mapping of file types to update limits.
        policy_limits (List[SecurityUpdates.UpdateLevel]): Policy-defined update limits.
        output (ScanOutput): The scan output format.
        no_output (bool): Whether to suppress output.
        prompt (bool): Whether to prompt the user for confirmation.

    Returns:
        Any: The result of the `process_fixes_scan` function.
    """
    try:
        limit = options[file_to_fix.file_type]
    except KeyError:
        try:
            limit = options[file_to_fix.file_type.value]
        except KeyError:
            limit = SecurityUpdates.UpdateLevel("patch")

    # Set defaults
    update_limits = [limit.value]

    if any(policy_limits):
        update_limits = [policy_limit.value for policy_limit in policy_limits]

    return process_fixes_scan(
        file_to_fix,
        specs_to_fix,
        update_limits,
        output,
        no_output=no_output,
        prompt=prompt,
    )


@scan_project_app.command(
    cls=SafetyCLICommand,
    help=CLI_SCAN_COMMAND_HELP,
    name=CMD_PROJECT_NAME,
    epilog=DEFAULT_EPILOG,
    options_metavar="[OPTIONS]",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
@handle_cmd_exception
@scan_project_command_init
@inject_metadata
@notify
def scan(
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
            help=SCAN_TARGET_HELP,
        ),
    ] = Path("."),
    output: Annotated[
        ScanOutput,
        typer.Option(
            help=SCAN_OUTPUT_HELP, show_default=False, callback=output_callback
        ),
    ] = ScanOutput.SCREEN,
    detailed_output: Annotated[
        bool,
        typer.Option(
            "--detailed-output", help=SCAN_DETAILED_OUTPUT, show_default=False
        ),
    ] = False,
    save_as: Annotated[
        Optional[Tuple[ScanExport, Path]],
        typer.Option(
            help=SCAN_SAVE_AS_HELP, show_default=False, callback=save_as_callback
        ),
    ] = (None, None),
    policy_file_path: Annotated[
        Optional[Path],
        typer.Option(
            "--policy-file",
            exists=False,
            file_okay=True,
            dir_okay=False,
            writable=True,
            readable=True,
            resolve_path=True,
            help=SCAN_POLICY_FILE_HELP,
            show_default=False,
        ),
    ] = None,
    apply_updates: Annotated[
        bool, typer.Option("--apply-fixes", help=SCAN_APPLY_FIXES, show_default=False)
    ] = False,
    use_server_matching: Annotated[
        bool,
        typer.Option(
            "--use-server-matching",
            help="Flag to enable using server side vulnerability matching. This just sends data to server for now.",
            show_default=False,
        ),
    ] = False,
    filter_keys: Annotated[
        Optional[List[str]],
        typer.Option("--filter", help="Filter output by specific top-level JSON keys."),
    ] = None,
):
    """
    Scans a project (defaulted to the current directory) for supply-chain security and configuration issues
    """

    # Step 1: Validate inputs and initialize settings
    validate_authentication(ctx)
    fixes_target = generate_fixes_target(apply_updates)  # Determine targets for updates
    validate_save_as(ctx, save_as)

    # Step 2: Setup console and ecosystems for scanning
    console = ctx.obj.console
    ecosystems = [Ecosystem(member.value) for member in list(ScannableEcosystems)]

    # Step 3: Initialize file finder and locate project files
    file_finder = initialize_file_finder(ctx, target, console, ecosystems)
    path, file_paths = scan_project_directory(file_finder, console)

    # Step 4: Prepare metadata for analysis
    if ecosystems:
        target_ecosystems = ", ".join([member.value for member in ecosystems])
        wait_msg = WAIT_MSG_ANALYZING_TARGETS.format(target_ecosystems)
    else:
        # Handle the case where no ecosystems are detected
        target_ecosystems = "No ecosystems detected"
        wait_msg = "Analyzing files and environments for security findings"

    # Step 5: Initialize data structures and counters for analysis
    files: List[FileModel] = []
    to_fix_files = []
    ignored_vulns_data = iter([])
    config = ctx.obj.config
    count = 0  # Total dependencies processed
    affected_count = 0
    exit_code = 0
    fixes_count = 0
    total_resolved_vulns = 0
    fix_file_types = [
        fix_target[0] if isinstance(fix_target[0], str) else fix_target[0].value
        for fix_target in fixes_target
    ]
    dependency_vuln_detected = False
    requirements_txt_found = False
    display_apply_fix_suggestion = False

    # Process each file for dependencies and vulnerabilities
    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        for path, analyzed_file in process_files(
            paths=file_paths,
            config=config,
            use_server_matching=use_server_matching,
            obj=ctx.obj,
            target=target,
        ):
            # Update counts and track vulnerabilities
            count += len(analyzed_file.dependency_results.dependencies)
            if exit_code == 0 and analyzed_file.dependency_results.failed:
                exit_code = EXIT_CODE_VULNERABILITIES_FOUND

            affected_specifications = (
                analyzed_file.dependency_results.get_affected_specifications()
            )
            affected_count += len(affected_specifications)

            # Sort vulnerabilities by severity
            def sort_vulns_by_score(vuln: Vulnerability) -> int:
                if vuln.severity and vuln.severity.cvssv3:
                    return vuln.severity.cvssv3.get("base_score", 0)
                return 0

            # Prepare to collect files needing fixes
            to_fix_spec = []
            file_matched_for_fix = analyzed_file.file_type.value in fix_file_types

            # Handle files with affected specifications
            if any(affected_specifications):
                dependency_vuln_detected = detect_dependency_vulnerabilities(
                    console, dependency_vuln_detected
                )
                print_file_info(console, path, target)

                for spec in affected_specifications:
                    if file_matched_for_fix:
                        to_fix_spec.append(spec)

                    # Print vulnerabilities for each specification
                    console.print()
                    vulns_to_report = sort_and_filter_vulnerabilities(
                        spec.vulnerabilities, key_func=sort_vulns_by_score
                    )
                    critical_vulns_count = count_critical_vulnerabilities(
                        vulns_to_report
                    )
                    vulns_found = len(vulns_to_report)
                    vuln_word = pluralize("vulnerability", vulns_found)

                    msg = generate_vulnerability_message(
                        spec.name,
                        spec.raw,
                        vulns_found,
                        critical_vulns_count,
                        vuln_word,
                    )
                    console.print(
                        Padding(f"{msg}]", PADDING_VALUES), emoji=True, overflow="crop"
                    )

                    # Display detailed vulnerability information if applicable
                    if detailed_output or vulns_found < MIN_DETAILED_OUTPUT_THRESHOLD:
                        render_vulnerabilities(
                            vulns_to_report, console, detailed_output
                        )

                    # Generate remediation details and print them
                    lines, resolved_vulns, fixes = generate_remediation_details(
                        spec, vuln_word, critical_vulns_count
                    )
                    total_resolved_vulns += resolved_vulns
                    fixes_count += fixes

                    for line in lines:
                        console.print(Padding(line, PADDING_VALUES), emoji=True)

                    # Provide a link for additional information
                    console.print(
                        Padding(
                            MSG_LEARN_MORE.format(spec.remediation.more_info_url),
                            PADDING_VALUES,
                        ),
                        emoji=True,
                    )
            else:
                # Handle files with no issues
                console.print()
                console.print(
                    f"{ICON_CHECKMARK} [file_title]{path.relative_to(target)}: No issues found.[/file_title]",
                    emoji=True,
                )

            # Track whether to suggest applying fixes
            display_apply_fix_suggestion = should_display_fix_suggestion(
                ctx, analyzed_file, affected_specifications, apply_updates
            )

            # Track if a requirements.txt file was found
            if (
                not requirements_txt_found
                and analyzed_file.file_type is FileType.REQUIREMENTS_TXT
            ):
                requirements_txt_found = True

            # Save file data for further processing
            file = FileModel(
                location=path,
                file_type=analyzed_file.file_type,
                results=analyzed_file.dependency_results,
            )

            if file_matched_for_fix:
                to_fix_files.append((file, to_fix_spec))

            files.append(file)

    # Suggest fixes if applicable
    if display_apply_fix_suggestion:
        console.print()
        print_fixes_section(console, requirements_txt_found, detailed_output)

    # Finalize report metadata and print summary
    console.print()
    version = ctx.obj.schema
    metadata = ctx.obj.metadata
    telemetry = ctx.obj.telemetry
    ctx.obj.project.files = files

    report = ReportModel(
        version=version,
        metadata=metadata,
        telemetry=telemetry,
        files=[],
        projects=[ctx.obj.project],
    )

    # Generate and print vulnerability summary
    total_issues_with_duplicates, total_ignored_issues = get_vulnerability_summary(
        report.as_v30()
    )

    print_summary(
        console=console,
        total_issues_with_duplicates=total_issues_with_duplicates,
        total_ignored_issues=total_ignored_issues,
        project=ctx.obj.project,
        dependencies_count=count,
        fixes_count=fixes_count,
        resolved_vulns_per_fix=total_resolved_vulns,
        is_detailed_output=detailed_output,
        ignored_vulns_data=ignored_vulns_data,
    )

    # Process report and upload if required
    report_url = process_report(
        obj=ctx.obj,
        console=console,
        report=report,
        output=output,
        save_as=save_as if save_as and all(save_as) else None,
        detailed_output=detailed_output,
        filter_keys=filter_keys,
        **{
            k: v
            for k, v in ctx.params.items()
            if k not in {"detailed_output", "output", "save_as", "filter_keys"}
        },
    )

    project_url = f"{SAFETY_PLATFORM_URL}{ctx.obj.project.url_path}"

    # Handle fix application if enabled
    if apply_updates:
        options = dict(fixes_target)
        policy_limits = ctx.obj.config.depedendency_vulnerability.security_updates.auto_security_updates_limit
        no_output = output is not ScanOutput.SCREEN
        prompt = output is ScanOutput.SCREEN

        # TODO: rename that 'no_output' confusing name
        if not no_output:
            console.print()
            console.print("-" * console.size.width)
            console.print(MSG_SAFETY_UPDATES_RUNNING)
            console.print("-" * console.size.width)

        for file_to_fix, specs_to_fix in to_fix_files:
            fixes = process_file_fixes(
                file_to_fix,
                specs_to_fix,
                options,
                policy_limits,
                output,
                no_output,
                prompt,
            )

        if not no_output:
            console.print("-" * console.size.width)

    # Print final exit messages and handle exit code
    if output is ScanOutput.SCREEN:
        run_easter_egg(console, exit_code)

    if output is not ScanOutput.NONE:
        if detailed_output:
            if exit_code > 0:
                console.print(MSG_EXIT_CODE_FAILURE.format(exit_code))
            else:
                console.print(MSG_EXIT_CODE_SUCCESS)
        sys.exit(exit_code)

    return project_url, report, report_url


@scan_system_app.command(
    cls=SafetyCLICommand,
    help=CLI_SYSTEM_SCAN_COMMAND_HELP,
    hidden=True,
    options_metavar="[COMMAND-OPTIONS]",
    name=CMD_SYSTEM_NAME,
    epilog=DEFAULT_EPILOG,
)
@inject_metadata
@scan_system_command_init
@handle_cmd_exception
@notify
def system_scan(
    ctx: typer.Context,
    policy_file_path: Annotated[
        Optional[Path],
        typer.Option(
            "--policy-file",
            exists=False,
            file_okay=True,
            dir_okay=False,
            writable=True,
            readable=True,
            resolve_path=True,
            help=SYSTEM_SCAN_POLICY_FILE_HELP,
            show_default=False,
        ),
    ] = None,
    targets: Annotated[
        List[Path],
        typer.Option(
            "--target",
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
            help=SYSTEM_SCAN_TARGET_HELP,
            show_default=False,
        ),
    ] = [],
    output: Annotated[
        SystemScanOutput, typer.Option(help=SYSTEM_SCAN_OUTPUT_HELP, show_default=False)
    ] = SystemScanOutput.SCREEN,
    save_as: Annotated[
        Optional[Tuple[SystemScanExport, Path]],
        typer.Option(help=SYSTEM_SCAN_SAVE_AS_HELP, show_default=False),
    ] = (None, None),
):
    """
    Scans a system (machine) for supply-chain security and configuration issues\n
    This will search for projects, requirements files and environment variables
    """
    if not all(save_as):
        ctx.params["save_as"] = None

    console = ctx.obj.console
    version = ctx.obj.schema
    metadata = ctx.obj.metadata
    telemetry = ctx.obj.telemetry

    ecosystems = [Ecosystem(member.value) for member in list(ScannableEcosystems)]
    ecosystems.append(Ecosystem.SAFETY_PROJECT)

    config = ctx.obj.config

    console.print(
        "Searching for Python projects, requirements files and virtual environments across this machine."
    )
    console.print(
        "If necessary, please grant Safety permission to access folders you want scanned."
    )
    console.print()

    with console.status("...", spinner=DEFAULT_SPINNER) as status:
        handlers: Set[FileHandler] = set(
            ECOSYSTEM_HANDLER_MAPPING[ecosystem]() for ecosystem in ecosystems
        )
        for handler in handlers:
            if handler.ecosystem:
                wait_msg = "Fetching Safety's proprietary vulnerability database..."
                status.update(wait_msg)
                handler.download_required_assets(ctx.obj.auth.client)

        file_paths = {}
        file_finders = []
        to_include = {
            file_type: paths
            for file_type, paths in config.scan.include_files.items()
            if file_type.ecosystem in ecosystems
        }

        for target in targets:
            file_finder = FileFinder(
                target=target,
                ecosystems=ecosystems,
                max_level=config.scan.max_depth,
                exclude=config.scan.ignore,
                console=console,
                include_files=to_include,
                live_status=status,
                handlers=handlers,
            )
            file_finders.append(file_finder)

            _, target_paths = file_finder.search()

            for file_type, paths in target_paths.items():
                current = file_paths.get(file_type, set())
                current.update(paths)
                file_paths[file_type] = current

    scan_project_command = get_command_for(
        name=CMD_PROJECT_NAME, typer_instance=scan_project_app
    )

    projects_dirs = set()
    projects: List[ProjectModel] = []

    project_data = {}
    with console.status(":mag:", spinner=DEFAULT_SPINNER) as status:
        # Handle projects first
        if FileType.SAFETY_PROJECT.value in file_paths.keys():
            projects_file_paths = file_paths[FileType.SAFETY_PROJECT.value]
            basic_params = ctx.params.copy()
            basic_params.pop("targets", None)

            prjs_console = Console(quiet=True)

            for project_path in projects_file_paths:
                projects_dirs.add(project_path.parent)
                project_dir = str(project_path.parent)
                try:
                    project = load_unverified_project_from_config(project_path.parent)
                    local_policy_file = load_policy_file(
                        project_path.parent / ".safety-policy.yml"
                    )
                except Exception as e:
                    LOG.exception(
                        f"Unable to load project from {project_path}. Reason {e}"
                    )
                    console.print(
                        f"{project_dir}: unable to load project found, skipped, use --debug for more details."
                    )
                    continue

                if not project or not project.id:
                    LOG.warning(
                        f"{project_path} parsed but project id is not defined or valid."
                    )
                    continue

                if not ctx.obj.platform_enabled:
                    msg = f"project found and skipped, navigate to `{project.project_path}` and scan this project with ‘safety scan’"
                    console.print(f"{project.id}: {msg}")
                    continue

                msg = f"Existing project found at {project_dir}"
                console.print(f"{project.id}: {msg}")
                project_data[project.id] = {
                    "path": project_dir,
                    "report_url": None,
                    "project_url": None,
                    "failed_exception": None,
                }

                upload_request_id = None
                try:
                    result = ctx.obj.auth.client.project_scan_request(
                        project_id=project.id
                    )
                    if "scan_upload_request_id" in result:
                        upload_request_id = result["scan_upload_request_id"]
                    else:
                        raise SafetyError(message=str(result))
                except Exception as e:
                    project_data[project.id]["failed_exception"] = e
                    LOG.exception(f"Unable to get a valid scan request id. Reason {e}")
                    console.print(
                        Padding(
                            f":no_entry_sign: Unable to start project scan for {project.id}, reason: {e}",
                            (0, 0, 0, 1),
                        ),
                        emoji=True,
                    )
                    continue

                projects.append(
                    ProjectModel(id=project.id, upload_request_id=upload_request_id)
                )

                kwargs = {
                    "target": project_dir,
                    "output": str(ScanOutput.NONE.value),
                    "save_as": (None, None),
                    "upload_request_id": upload_request_id,
                    "local_policy": local_policy_file,
                    "console": prjs_console,
                }
                try:
                    # TODO: Refactor to avoid calling invoke, also, launch
                    # this on background.
                    console.print(
                        Padding(
                            f"Running safety scan for {project.id} project",
                            (0, 0, 0, 1),
                        ),
                        emoji=True,
                    )
                    status.update(f":mag: Processing project scan for {project.id}")

                    project_url, report, report_url = ctx.invoke(
                        scan_project_command, **{**basic_params, **kwargs}
                    )
                    project_data[project.id]["project_url"] = project_url
                    project_data[project.id]["report_url"] = report_url

                except Exception as e:
                    project_data[project.id]["failed_exception"] = e
                    console.print(
                        Padding(
                            f":cross_mark: Failed project scan for {project.id}, reason: {e}",
                            (0, 0, 0, 1),
                        ),
                        emoji=True,
                    )
                    LOG.exception(
                        f"Failed to run scan on project {project.id}, "
                        f"Upload request ID: {upload_request_id}. Reason {e}"
                    )

                console.print()

        file_paths.pop(FileType.SAFETY_PROJECT.value, None)

        files: List[FileModel] = []

        status.update(":mag: Finishing projects processing.")

        for k, f_paths in file_paths.items():
            file_paths[k] = {
                fp
                for fp in f_paths
                if not should_exclude(excludes=projects_dirs, to_analyze=fp)
            }

        pkgs_count = 0
        file_count = 0
        venv_count = 0

        for path, analyzed_file in process_files(paths=file_paths, config=config):
            status.update(f":mag: {path}")
            files.append(
                FileModel(
                    location=path,
                    file_type=analyzed_file.file_type,
                    results=analyzed_file.dependency_results,
                )
            )
            file_pkg_count = len(analyzed_file.dependency_results.dependencies)

            affected_dependencies = (
                analyzed_file.dependency_results.get_affected_dependencies()
            )

            # Per file
            affected_pkgs_count = 0
            critical_vulns_count = 0
            other_vulns_count = 0

            if any(affected_dependencies):
                affected_pkgs_count = len(affected_dependencies)

                for dep in affected_dependencies:
                    for spec in dep.specifications:
                        for vuln in spec.vulnerabilities:
                            if vuln.ignored:
                                continue
                            if (
                                vuln.CVE
                                and vuln.CVE.cvssv3
                                and VulnerabilitySeverityLabels(
                                    vuln.CVE.cvssv3.get("base_severity", "none").lower()
                                )
                                is VulnerabilitySeverityLabels.CRITICAL
                            ):
                                critical_vulns_count += 1
                            else:
                                other_vulns_count += 1

            msg = pluralize("package", file_pkg_count)
            if analyzed_file.file_type is FileType.VIRTUAL_ENVIRONMENT:
                msg = f"installed {msg} found"
                venv_count += 1
            else:
                file_count += 1

            pkgs_count += file_pkg_count
            console.print(f":package: {file_pkg_count} {msg} in {path}", emoji=True)

            if affected_pkgs_count <= 0:
                msg = "No vulnerabilities found"
            else:
                msg = f"{affected_pkgs_count} vulnerable {pluralize('package', affected_pkgs_count)}"
                if critical_vulns_count > 0:
                    msg += f", {critical_vulns_count} critical"
                if other_vulns_count > 0:
                    msg += f" and {other_vulns_count} other {pluralize('vulnerability', other_vulns_count)} found"

            console.print(Padding(msg, (0, 0, 0, 1)), emoji=True)
            console.print()

    report = ReportModel(
        version=version,
        metadata=metadata,
        telemetry=telemetry,
        files=files,
        projects=projects,
    )

    console.print()
    total_count = sum([finder.file_count for finder in file_finders], 0)
    console.print(f"Searched {total_count:,} files for dependency security issues")
    packages_msg = f"{pkgs_count:,} {pluralize('package', pkgs_count)} found across"
    files_msg = f"{file_count:,} {pluralize('file', file_count)}"
    venv_msg = f"{venv_count:,} virtual {pluralize('environment', venv_count)}"
    console.print(
        f":package: Python files and environments: {packages_msg} {files_msg} and {venv_msg}",
        emoji=True,
    )
    console.print()

    proccessed = dict(
        filter(
            lambda item: item[1]["report_url"] and item[1]["project_url"],
            project_data.items(),
        )
    )

    if proccessed:
        run_word = "runs" if len(proccessed) == 1 else "run"
        console.print(
            f"Project {pluralize('scan', len(proccessed))} {run_word} on {len(proccessed)} existing {pluralize('project', len(proccessed))}:"
        )

        for prj, data in proccessed.items():
            console.print(f"[bold]{prj}[/bold] at {data['path']}")
            for detail in [f"{prj} dashboard: {data['project_url']}"]:
                console.print(
                    Padding(detail, (0, 0, 0, 1)), emoji=True, overflow="crop"
                )

    process_report(ctx.obj, console, report, **{**ctx.params})


def get_vulnerability_summary(report: Dict[str, Any]) -> Tuple[int, int]:
    """
    Summarize vulnerabilities from the given report.

    Args:
        report (ReportModel): The report containing vulnerability data.

    Returns:
        Tuple[int, int]: A tuple containing:
            - Total number of issues (including duplicates)
            - Total number of ignored issues
    """
    total_issues = 0
    ignored_issues = 0

    for project in report.scan_results.projects:
        for file in project.files:
            for dependency in file.results.dependencies:
                for specification in dependency.specifications:
                    known_vulnerabilities = (
                        specification.vulnerabilities.known_vulnerabilities
                    )
                    total_issues += len(known_vulnerabilities)
                    ignored_issues += sum(1 for v in known_vulnerabilities if v.ignored)

    return total_issues, ignored_issues
