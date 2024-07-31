from enum import Enum
import itertools
import logging
from pathlib import Path
import sys
from typing import Any, List, Optional, Set, Tuple
from typing_extensions import Annotated

from safety.constants import EXIT_CODE_VULNERABILITIES_FOUND
from safety.safety import process_fixes, process_fixes_scan
from safety.scan.finder.handlers import ECOSYSTEM_HANDLER_MAPPING, FileHandler
from safety.scan.validators import output_callback, save_as_callback
from safety.util import pluralize
from ..cli_util import SafetyCLICommand, SafetyCLISubGroup, handle_cmd_exception
from rich.padding import Padding
import typer
from safety.auth.constants import SAFETY_PLATFORM_URL
from safety.cli_util import get_command_for
from rich.console import Console
from safety.errors import SafetyError

from safety.scan.finder import FileFinder
from safety.scan.constants import CMD_PROJECT_NAME, CMD_SYSTEM_NAME, DEFAULT_SPINNER, \
    SCAN_OUTPUT_HELP, DEFAULT_EPILOG, SCAN_POLICY_FILE_HELP, SCAN_SAVE_AS_HELP, \
    SCAN_TARGET_HELP, SYSTEM_SCAN_OUTPUT_HELP, SYSTEM_SCAN_POLICY_FILE_HELP, SYSTEM_SCAN_SAVE_AS_HELP, \
    SYSTEM_SCAN_TARGET_HELP, SCAN_APPLY_FIXES, SCAN_DETAILED_OUTPUT, CLI_SCAN_COMMAND_HELP, CLI_SYSTEM_SCAN_COMMAND_HELP
from safety.scan.decorators import inject_metadata, scan_project_command_init, scan_system_command_init
from safety.scan.finder.file_finder import should_exclude
from safety.scan.main import load_policy_file, load_unverified_project_from_config, process_files, save_report_as
from safety.scan.models import ScanExport, ScanOutput, SystemScanExport, SystemScanOutput
from safety.scan.render import print_brief, print_detected_ecosystems_section, print_fixes_section, print_ignore_details, render_scan_html, render_scan_spdx, render_to_console
from safety.scan.util import Stage
from safety_schemas.models import Ecosystem, FileModel, FileType, ProjectModel, \
    ReportModel, ScanType, VulnerabilitySeverityLabels, SecurityUpdates, Vulnerability

LOG = logging.getLogger(__name__)


cli_apps_opts = {"rich_markup_mode": "rich", "cls": SafetyCLISubGroup}

scan_project_app = typer.Typer(**cli_apps_opts)
scan_system_app = typer.Typer(**cli_apps_opts)


class ScannableEcosystems(Enum):
    """Enum representing scannable ecosystems."""
    PYTHON = Ecosystem.PYTHON.value


def process_report(
    obj: Any, console: Console, report: ReportModel, output: str,
    save_as: Optional[Tuple[str, Path]], **kwargs
) -> Optional[str]:
    """
    Processes and outputs the report based on the given parameters.

    Args:
        obj (Any): The context object.
        console (Console): The console object.
        report (ReportModel): The report model.
        output (str): The output format.
        save_as (Optional[Tuple[str, Path]]): The save-as format and path.
        kwargs: Additional keyword arguments.

    Returns:
        Optional[str]: The URL of the report if uploaded, otherwise None.
    """
    wait_msg = "Processing report"
    with console.status(wait_msg, spinner=DEFAULT_SPINNER) as status:
        json_format = report.as_v30().json()

    export_type, export_path = None, None

    if save_as:
        export_type, export_path = save_as
        export_type = ScanExport(export_type)

    output = ScanOutput(output)

    report_to_export = None
    report_to_output = None

    with console.status(wait_msg, spinner=DEFAULT_SPINNER) as status:

        spdx_format, html_format = None, None

        if ScanExport.is_format(export_type, ScanExport.SPDX) or ScanOutput.is_format(output, ScanOutput.SPDX):
            spdx_version = None
            if export_type:
                spdx_version = export_type.version if export_type.version and ScanExport.is_format(export_type, ScanExport.SPDX) else None

            if not spdx_version and output:
                spdx_version = output.version if output.version and ScanOutput.is_format(output, ScanOutput.SPDX) else None

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
            save_report_as(report.metadata.scan_type, export_type, Path(export_path),
                           report_to_export)
        report_url = None

        if obj.platform_enabled:
            status.update(f"Uploading report to: {SAFETY_PLATFORM_URL}")
            try:
                result = obj.auth.client.upload_report(json_format)
                status.update("Report uploaded")
                report_url = f"{SAFETY_PLATFORM_URL}{result['url']}"
            except Exception as e:
                raise e

        if output is ScanOutput.SCREEN:
            console.print()
            lines = []

            if obj.platform_enabled and report_url:
                if report.metadata.scan_type is ScanType.scan:
                    project_url = f"{SAFETY_PLATFORM_URL}{obj.project.url_path}"
                    lines.append(f"Scan report: [link]{report_url}[/link]")
                    lines.append("Project dashboard: " \
                                f"[link]{project_url}[/link]")
                elif report.metadata.scan_type is ScanType.system_scan:
                    lines.append(f"System scan report: [link]{report_url}[/link]")

            for line in lines:
                console.print(line, emoji=True)

    if output.is_silent():
        console.quiet = False

        if output is ScanOutput.JSON or ScanOutput.is_format(output, ScanOutput.SPDX):
            if output is ScanOutput.JSON:
                kwargs = {"json": report_to_output}
            else:
                kwargs = {"data": report_to_output}
            console.print_json(**kwargs)

        else:
            console.print(report_to_output)

        console.quiet = True

    return report_url


def generate_updates_arguments() -> List:
    """
    Generates a list of file types and update limits for apply fixes.

    Returns:
        List: A list of file types and update limits.
    """
    fixes = []
    limit_type = SecurityUpdates.UpdateLevel.PATCH
    DEFAULT_FILE_TYPES = [FileType.REQUIREMENTS_TXT, FileType.PIPENV_LOCK,
                     FileType.POETRY_LOCK, FileType.VIRTUAL_ENVIRONMENT]
    fixes.extend([(default_file_type, limit_type) for default_file_type in DEFAULT_FILE_TYPES])

    return fixes


@scan_project_app.command(
        cls=SafetyCLICommand,
        help=CLI_SCAN_COMMAND_HELP,
        name=CMD_PROJECT_NAME, epilog=DEFAULT_EPILOG,
        options_metavar="[OPTIONS]",
        context_settings={"allow_extra_args": True,
                          "ignore_unknown_options": True},
                          )
@handle_cmd_exception
@inject_metadata
@scan_project_command_init
def scan(ctx: typer.Context,
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
                 help=SCAN_TARGET_HELP
             ),
         ] = Path("."),
         output: Annotated[ScanOutput,
                         typer.Option(
                            help=SCAN_OUTPUT_HELP,
                            show_default=False,
                            callback=output_callback)
                         ] = ScanOutput.SCREEN,
         detailed_output: Annotated[bool,
                            typer.Option("--detailed-output",
                                help=SCAN_DETAILED_OUTPUT,
                                show_default=False)
                        ] = False,
         save_as: Annotated[Optional[Tuple[ScanExport, Path]],
                         typer.Option(
                            help=SCAN_SAVE_AS_HELP,
                            show_default=False,
                            callback=save_as_callback)
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
                            show_default=False
                        )] = None,
        apply_updates: Annotated[bool,
                            typer.Option("--apply-fixes",
                                help=SCAN_APPLY_FIXES,
                                show_default=False)
                        ] = False
         ):
    """
    Scans a project (defaulted to the current directory) for supply-chain security and configuration issues
    """

    # Generate update arguments if apply updates option is enabled
    fixes_target = []
    if apply_updates:
        fixes_target = generate_updates_arguments()

    # Ensure save_as params are correctly set
    if not all(save_as):
        ctx.params["save_as"] = None

    console = ctx.obj.console
    ecosystems = [Ecosystem(member.value) for member in list(ScannableEcosystems)]
    to_include = {file_type: paths for file_type, paths in ctx.obj.config.scan.include_files.items() if file_type.ecosystem in ecosystems}

    # Initialize file finder
    file_finder = FileFinder(target=target, ecosystems=ecosystems,
                             max_level=ctx.obj.config.scan.max_depth,
                             exclude=ctx.obj.config.scan.ignore,
                             include_files=to_include,
                             console=console)

    # Download necessary assets for each handler
    for handler in file_finder.handlers:
        if handler.ecosystem:
            wait_msg = "Fetching Safety's vulnerability database..."
            with console.status(wait_msg, spinner=DEFAULT_SPINNER):
                handler.download_required_assets(ctx.obj.auth.client)

    # Start scanning the project directory
    wait_msg = "Scanning project directory"

    path = None
    file_paths = {}

    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        path, file_paths = file_finder.search()
        print_detected_ecosystems_section(console, file_paths,
                                          include_safety_prjs=True)

    target_ecosystems = ", ".join([member.value for member in ecosystems])
    wait_msg = f"Analyzing {target_ecosystems} files and environments for security findings"

    import time

    files: List[FileModel] = []

    config = ctx.obj.config

    count = 0
    ignored = set()

    affected_count = 0
    dependency_vuln_detected = False

    ignored_vulns_data = iter([])

    exit_code = 0
    fixes_count = 0
    to_fix_files = []
    fix_file_types = [fix_target[0] if isinstance(fix_target[0], str) else fix_target[0].value for fix_target in fixes_target]
    requirements_txt_found = False
    display_apply_fix_suggestion = False

    # Process each file for dependencies and vulnerabilities
    with console.status(wait_msg, spinner=DEFAULT_SPINNER) as status:
        for path, analyzed_file in process_files(paths=file_paths,
                                                 config=config):
            count += len(analyzed_file.dependency_results.dependencies)

            # Update exit code if vulnerabilities are found
            if exit_code == 0 and analyzed_file.dependency_results.failed:
                exit_code = EXIT_CODE_VULNERABILITIES_FOUND

            # Handle ignored vulnerabilities for detailed output
            if detailed_output:
                vulns_ignored = analyzed_file.dependency_results.ignored_vulns_data \
                    .values()
                ignored_vulns_data = itertools.chain(vulns_ignored,
                                                       ignored_vulns_data)

            ignored.update(analyzed_file.dependency_results.ignored_vulns.keys())

            affected_specifications = analyzed_file.dependency_results.get_affected_specifications()
            affected_count += len(affected_specifications)

            def sort_vulns_by_score(vuln: Vulnerability) -> int:
                if vuln.severity and vuln.severity.cvssv3:
                    return vuln.severity.cvssv3.get("base_score", 0)

                return 0

            to_fix_spec = []
            file_matched_for_fix = analyzed_file.file_type.value in fix_file_types

            if any(affected_specifications):
                if not dependency_vuln_detected:
                    console.print()
                    console.print("Dependency vulnerabilities detected:")
                    dependency_vuln_detected = True

                console.print()
                msg = f":pencil: [file_title]{path.relative_to(target)}:[/file_title]"
                console.print(msg, emoji=True)
                for spec in affected_specifications:
                    if file_matched_for_fix:
                        to_fix_spec.append(spec)

                    console.print()
                    vulns_to_report = sorted(
                        [vuln for vuln in spec.vulnerabilities if not vuln.ignored],
                        key=sort_vulns_by_score,
                        reverse=True)

                    critical_vulns_count = sum(1 for vuln in vulns_to_report if vuln.severity and vuln.severity.cvssv3 and vuln.severity.cvssv3.get("base_severity", "none").lower() == VulnerabilitySeverityLabels.CRITICAL.value.lower())

                    vulns_found = len(vulns_to_report)
                    vuln_word = pluralize("vulnerability", vulns_found)

                    msg = f"[dep_name]{spec.name}[/dep_name][specifier]{spec.raw.replace(spec.name, '')}[/specifier]  [{vulns_found} {vuln_word} found"

                    if vulns_found > 3 and critical_vulns_count > 0:
                        msg += f", [brief_severity]including {critical_vulns_count} critical severity {pluralize('vulnerability', critical_vulns_count)}[/brief_severity]"

                    console.print(Padding(f"{msg}]", (0, 0, 0, 1)), emoji=True,
                                  overflow="crop")

                    if detailed_output or vulns_found < 3:
                        for vuln in vulns_to_report:
                            render_to_console(vuln, console,
                                              rich_kwargs={"emoji": True,
                                                           "overflow": "crop"},
                                              detailed_output=detailed_output)

                    lines = []

                    # Put remediation here
                    if not spec.remediation.recommended:
                        lines.append(f"No known fix for [dep_name]{spec.name}[/dep_name][specifier]{spec.raw.replace(spec.name, '')}[/specifier] to fix " \
                                     f"[number]{spec.remediation.vulnerabilities_found}[/number] " \
                                        f"{vuln_word}")
                    else:
                        msg = f"[rem_brief]Update {spec.raw} to " \
                                     f"{spec.name}=={spec.remediation.recommended}[/rem_brief] to fix " \
                                        f"[number]{spec.remediation.vulnerabilities_found}[/number] " \
                                            f"{vuln_word}"

                        if spec.remediation.vulnerabilities_found > 3 and critical_vulns_count > 0:
                            msg += f", [rem_severity]including {critical_vulns_count} critical severity {pluralize('vulnerability', critical_vulns_count)}[/rem_severity] :stop_sign:"

                        fixes_count += 1
                        lines.append(f"{msg}")
                        if spec.remediation.other_recommended:
                            other = "[/recommended_ver], [recommended_ver]".join(spec.remediation.other_recommended)
                            lines.append(f"Versions of {spec.name} with no known vulnerabilities: " \
                                         f"[recommended_ver]{other}[/recommended_ver]")

                    for line in lines:
                        console.print(Padding(line, (0, 0, 0, 1)), emoji=True)

                    console.print(
                        Padding(f"Learn more: [link]{spec.remediation.more_info_url}[/link]",
                                (0, 0, 0, 1)), emoji=True)
            else:
                console.print()
                console.print(f":white_check_mark: [file_title]{path.relative_to(target)}: No issues found.[/file_title]",
                              emoji=True)

            if(ctx.obj.auth.stage == Stage.development
               and analyzed_file.ecosystem == Ecosystem.PYTHON
               and analyzed_file.file_type == FileType.REQUIREMENTS_TXT
               and any(affected_specifications)
               and not apply_updates):
                display_apply_fix_suggestion = True

            if not requirements_txt_found and analyzed_file.file_type is FileType.REQUIREMENTS_TXT:
                requirements_txt_found = True

            file = FileModel(location=path,
                               file_type=analyzed_file.file_type,
                               results=analyzed_file.dependency_results)

            if file_matched_for_fix:
                to_fix_files.append((file, to_fix_spec))

            files.append(file)

    if display_apply_fix_suggestion:
        console.print()
        print_fixes_section(console, requirements_txt_found, detailed_output)

    console.print()
    print_brief(console, ctx.obj.project, count, affected_count,
                fixes_count)
    print_ignore_details(console, ctx.obj.project, ignored,
                         is_detailed_output=detailed_output,
                         ignored_vulns_data=ignored_vulns_data)


    version = ctx.obj.schema
    metadata = ctx.obj.metadata
    telemetry = ctx.obj.telemetry
    ctx.obj.project.files = files

    report = ReportModel(version=version,
                metadata=metadata,
                telemetry=telemetry,
                files=[],
                projects=[ctx.obj.project])

    report_url = process_report(ctx.obj, console, report, **{**ctx.params})
    project_url = f"{SAFETY_PLATFORM_URL}{ctx.obj.project.url_path}"

    if apply_updates:
        options = dict(fixes_target)
        update_limits = []
        policy_limits = ctx.obj.config.depedendency_vulnerability.security_updates.auto_security_updates_limit

        no_output = output is not ScanOutput.SCREEN
        prompt = output is ScanOutput.SCREEN

        # TODO: rename that 'no_output' confusing name
        if not no_output:
            console.print()
            console.print("-" * console.size.width)
            console.print("Safety updates running")
            console.print("-" * console.size.width)

        for file_to_fix, specs_to_fix in to_fix_files:
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

            fixes = process_fixes_scan(file_to_fix,
                                       specs_to_fix, update_limits, output, no_output=no_output,
                                       prompt=prompt)

        if not no_output:
            console.print("-" * console.size.width)

    if output is not ScanOutput.NONE:
        if detailed_output:
            if exit_code > 0:
                console.print(f":stop_sign: Scan-failing vulnerabilities were found, returning non-zero exit code: {exit_code}")
            else:
                console.print("No scan-failing vulnerabilities were matched, returning success exit code: 0")
        sys.exit(exit_code)

    return project_url, report, report_url


@scan_system_app.command(
        cls=SafetyCLICommand,
        help=CLI_SYSTEM_SCAN_COMMAND_HELP,
        options_metavar="[COMMAND-OPTIONS]",
        name=CMD_SYSTEM_NAME, epilog=DEFAULT_EPILOG)
@handle_cmd_exception
@inject_metadata
@scan_system_command_init
def system_scan(ctx: typer.Context,
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
                            show_default=False
                        )] = None,
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
                 show_default=False
             ),
         ] = [],
         output: Annotated[SystemScanOutput,
                         typer.Option(
                            help=SYSTEM_SCAN_OUTPUT_HELP,
                            show_default=False)
                         ] = SystemScanOutput.SCREEN,
         save_as: Annotated[Optional[Tuple[SystemScanExport, Path]],
                         typer.Option(
                            help=SYSTEM_SCAN_SAVE_AS_HELP,
                            show_default=False)
                         ] = (None, None)):
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

    console.print("Searching for Python projects, requirements files and virtual environments across this machine.")
    console.print("If necessary, please grant Safety permission to access folders you want scanned.")
    console.print()

    with console.status("...", spinner=DEFAULT_SPINNER) as status:
        handlers : Set[FileHandler] = set(ECOSYSTEM_HANDLER_MAPPING[ecosystem]()
                                              for ecosystem in ecosystems)
        for handler in handlers:
            if handler.ecosystem:
                wait_msg = "Fetching Safety's proprietary vulnerability database..."
                status.update(wait_msg)
                handler.download_required_assets(ctx.obj.auth.client)

        file_paths = {}
        file_finders = []
        to_include = {file_type: paths for file_type, paths in config.scan.include_files.items() if file_type.ecosystem in ecosystems}

        for target in targets:
            file_finder = FileFinder(target=target,
                                        ecosystems=ecosystems,
                                        max_level=config.scan.max_depth,
                                        exclude=config.scan.ignore, console=console,
                                        include_files=to_include,
                                        live_status=status, handlers=handlers)
            file_finders.append(file_finder)

            _, target_paths = file_finder.search()

            for file_type, paths in target_paths.items():
                current = file_paths.get(file_type, set())
                current.update(paths)
                file_paths[file_type] = current

    scan_project_command = get_command_for(name=CMD_PROJECT_NAME,
                                           typer_instance=scan_project_app)

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
                    local_policy_file = load_policy_file(project_path.parent / ".safety-policy.yml")
                except Exception as e:
                    LOG.exception(f"Unable to load project from {project_path}. Reason {e}")
                    console.print(f"{project_dir}: unable to load project found, skipped, use --debug for more details.")
                    continue

                if not project or not project.id:
                    LOG.warn(f"{project_path} parsed but project id is not defined or valid.")
                    continue

                if not ctx.obj.platform_enabled:
                    msg = f"project found and skipped, navigate to `{project.project_path}` and scan this project with ‘safety scan’"
                    console.print(f"{project.id}: {msg}")
                    continue

                msg = f"Existing project found at {project_dir}"
                console.print(f"{project.id}: {msg}")
                project_data[project.id] = {"path": project_dir,
                                            "report_url": None,
                                            "project_url": None,
                                            "failed_exception": None}

                upload_request_id = None
                try:
                    result = ctx.obj.auth.client.project_scan_request(project_id=project.id)
                    if "scan_upload_request_id" in result:
                        upload_request_id = result["scan_upload_request_id"]
                    else:
                        raise SafetyError(message=str(result))
                except Exception as e:
                    project_data[project.id]["failed_exception"] = e
                    LOG.exception(f"Unable to get a valid scan request id. Reason {e}")
                    console.print(
                        Padding(f":no_entry_sign: Unable to start project scan for {project.id}, reason: {e}",
                                (0, 0, 0, 1)), emoji=True)
                    continue

                projects.append(ProjectModel(id=project.id,
                                            upload_request_id=upload_request_id))

                kwargs = {"target": project_dir, "output": str(ScanOutput.NONE.value),
                        "save_as": (None, None), "upload_request_id": upload_request_id,
                        "local_policy": local_policy_file, "console": prjs_console}
                try:
                    # TODO: Refactor to avoid calling invoke, also, launch
                    # this on background.
                    console.print(
                        Padding(f"Running safety scan for {project.id} project",
                                (0, 0, 0, 1)), emoji=True)
                    status.update(f":mag: Processing project scan for {project.id}")

                    project_url, report, report_url = ctx.invoke(scan_project_command, **{**basic_params, **kwargs})
                    project_data[project.id]["project_url"] = project_url
                    project_data[project.id]["report_url"] = report_url

                except Exception as e:
                    project_data[project.id]["failed_exception"] = e
                    console.print(
                        Padding(f":cross_mark: Failed project scan for {project.id}, reason: {e}",
                                (0, 0, 0, 1)), emoji=True)
                    LOG.exception(f"Failed to run scan on project {project.id}, " \
                                f"Upload request ID: {upload_request_id}. Reason {e}")

                console.print()

        file_paths.pop(FileType.SAFETY_PROJECT.value, None)

        files: List[FileModel] = []

        status.update(":mag: Finishing projects processing.")

        for k, f_paths in file_paths.items():
            file_paths[k] = {fp for fp in f_paths
                            if not should_exclude(excludes=projects_dirs,
                                                to_analyze=fp)}

        pkgs_count = 0
        file_count = 0
        venv_count = 0

        for path, analyzed_file in process_files(paths=file_paths, config=config):
            status.update(f":mag: {path}")
            files.append(FileModel(location=path,
                                file_type=analyzed_file.file_type,
                                results=analyzed_file.dependency_results))
            file_pkg_count = len(analyzed_file.dependency_results.dependencies)

            affected_dependencies = analyzed_file.dependency_results.get_affected_dependencies()

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
                            if vuln.CVE and vuln.CVE.cvssv3 \
                                and VulnerabilitySeverityLabels(
                                    vuln.CVE.cvssv3.get(
                                        "base_severity", "none")
                                        .lower()) is VulnerabilitySeverityLabels.CRITICAL:
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

            console.print(
                Padding(msg,
                        (0, 0, 0, 1)), emoji=True)
            console.print()

    report = ReportModel(version=version,
                metadata=metadata,
                telemetry=telemetry,
                files=files,
                projects=projects)

    console.print()
    total_count = sum([finder.file_count for finder in file_finders], 0)
    console.print(f"Searched {total_count:,} files for dependency security issues")
    packages_msg = f"{pkgs_count:,} {pluralize('package', pkgs_count)} found across"
    files_msg = f"{file_count:,} {pluralize('file', file_count)}"
    venv_msg = f"{venv_count:,} virtual {pluralize('environment', venv_count)}"
    console.print(f":package: Python files and environments: {packages_msg} {files_msg} and {venv_msg}", emoji=True)
    console.print()

    proccessed = dict(filter(
        lambda item: item[1]["report_url"] and item[1]["project_url"],
        project_data.items()))

    if proccessed:
        run_word = "runs" if len(proccessed) == 1 else "run"
        console.print(f"Project {pluralize('scan', len(proccessed))} {run_word} on {len(proccessed)} existing {pluralize('project', len(proccessed))}:")

        for prj, data in proccessed.items():
            console.print(f"[bold]{prj}[/bold] at {data['path']}")
            for detail in [f"{prj} dashboard: {data['project_url']}"]:
                console.print(Padding(detail, (0, 0, 0, 1)), emoji=True, overflow="crop")

    process_report(ctx.obj, console, report, **{**ctx.params})
