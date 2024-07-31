from collections import defaultdict
from datetime import datetime
import itertools
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from rich.prompt import Prompt
from rich.text import Text
from rich.console import Console
from rich.padding import Padding
from safety_schemas.models import Vulnerability, ReportModel
import typer
from safety import safety
from safety.auth.constants import SAFETY_PLATFORM_URL
from safety.errors import SafetyException
from safety.output_utils import parse_html
from safety.scan.constants import DEFAULT_SPINNER

from safety_schemas.models import Ecosystem, FileType, PolicyFileModel, \
    PolicySource, ProjectModel, IgnoreCodes, Stage, PythonDependency

from safety.util import get_basic_announcements, get_safety_version

LOG = logging.getLogger(__name__)

import datetime

def render_header(targets: List[Path], is_system_scan: bool) -> Text:
    """
    Render the header text for the scan.

    Args:
        targets (List[Path]): List of target paths for the scan.
        is_system_scan (bool): Indicates if the scan is a system scan.

    Returns:
        Text: Rendered header text.
    """
    version = get_safety_version()
    scan_datetime = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")

    action = f"scanning {', '.join([str(t) for t in targets])}"
    if is_system_scan:
        action = "running [bold]system scan[/bold]"

    return Text.from_markup(
        f"[bold]Safety[/bold] {version} {action}\n{scan_datetime}")

def print_header(console, targets: List[Path], is_system_scan: bool = False) -> None:
    """
    Print the header for the scan.

    Args:
        console (Console): The console for output.
        targets (List[Path]): List of target paths for the scan.
        is_system_scan (bool): Indicates if the scan is a system scan.
    """
    console.print(render_header(targets, is_system_scan), markup=True)

def print_announcements(console: Console, ctx: typer.Context):
    """
    Print announcements from Safety.

    Args:
        console (Console): The console for output.
        ctx (typer.Context): The context of the Typer command.
    """
    colors = {"error": "red", "warning": "yellow", "info": "default"}

    announcements = safety.get_announcements(ctx.obj.auth.client,
                                             telemetry=ctx.obj.config.telemetry_enabled,
                                             with_telemetry=ctx.obj.telemetry)
    basic_announcements = get_basic_announcements(announcements, False)

    if any(basic_announcements):
        console.print()
        console.print("[bold]Safety Announcements:[/bold]")
        console.print()
        for announcement in announcements:
            color = colors.get(announcement.get('type', "info"), "default")
            console.print(f"[{color}]* {announcement.get('message')}[/{color}]")

def print_detected_ecosystems_section(console: Console, file_paths: Dict[str, Set[Path]], include_safety_prjs: bool = True) -> None:
    """
    Print detected ecosystems section.

    Args:
        console (Console): The console for output.
        file_paths (Dict[str, Set[Path]]): Dictionary of file paths by type.
        include_safety_prjs (bool): Whether to include safety projects.
    """
    detected: Dict[Ecosystem, Dict[FileType, int]] = {}

    for file_type_key, f_paths in file_paths.items():
        file_type = FileType(file_type_key)
        if file_type.ecosystem:
            if file_type.ecosystem not in detected:
                detected[file_type.ecosystem] = {}
            detected[file_type.ecosystem][file_type] = len(f_paths)

    for ecosystem, f_type_count in detected.items():

        if not include_safety_prjs and ecosystem is Ecosystem.SAFETY_PROJECT:
            continue

        brief = "Found "
        file_types = []

        for f_type, count in f_type_count.items():
            file_types.append(f"{count} {f_type.human_name(plural=count>1)}")

        if len(file_types) > 1:
            brief += ", ".join(file_types[:-1]) + " and " + file_types[-1]
        else:
            brief += file_types[0]

        msg = f"{ecosystem.name.replace('_', ' ').title()} detected. {brief}"

        console.print(msg)

def print_brief(console: Console, project: ProjectModel, dependencies_count: int = 0, affected_count: int = 0, fixes_count: int = 0) -> None:
    """
    Print a brief summary of the scan results.

    Args:
        console (Console): The console for output.
        project (ProjectModel): The project model.
        dependencies_count (int): Number of dependencies tested.
        affected_count (int): Number of security issues found.
        fixes_count (int): Number of fixes suggested.
    """
    from ..util import pluralize

    if project.policy:
        if project.policy.source is PolicySource.cloud:
            policy_msg = f"policy fetched from Safety Platform"
        else:
            if project.id:
                policy_msg = f"local {project.id} project scan policy"
            else:
                policy_msg = f"local scan policy file"
    else:
        policy_msg = "default Safety CLI policies"

    console.print(f"Tested [number]{dependencies_count}[/number] {pluralize('dependency', dependencies_count)} for known security " \
                  f"issues using {policy_msg}")
    console.print(
        f"[number]{affected_count}[/number] security {pluralize('issue', affected_count)} found, [number]{fixes_count}[/number] {pluralize('fix', fixes_count)} suggested")

def print_fixes_section(console: Console, requirements_txt_found: bool = False, is_detailed_output: bool = False) -> None:
    """
    Print the section on applying fixes.

    Args:
        console (Console): The console for output.
        requirements_txt_found (bool): Indicates if a requirements.txt file was found.
        is_detailed_output (bool): Indicates if detailed output is enabled.
    """
    console.print("-" * console.size.width)
    console.print("Apply Fixes")
    console.print("-" * console.size.width)

    console.print()

    if requirements_txt_found:
        console.print("[green]Run `safety scan --apply-fixes`[/green] to update these packages and fix these vulnerabilities. "
                    "Documentation, limitations, and configurations for applying automated fixes: [link]https://docs.safetycli.com/safety-docs/vulnerability-remediation/applying-fixes[/link]")
        console.print()
        console.print("Alternatively, use your package manager to update packages to their secure versions. Always check for breaking changes when updating packages.")
    else:
        msg = "Use your package manager to update packages to their secure versions. Always check for breaking changes when updating packages."
        console.print(msg)

    if not is_detailed_output:
        console.print("[tip]Tip[/tip]: For more detailed output on each vulnerability, add the `--detailed-output` flag to safety scan.")

    console.print()
    console.print("-" * console.size.width)


def print_ignore_details(console: Console, project: ProjectModel, ignored: Set[str], is_detailed_output: bool = False, ignored_vulns_data: Optional[Dict[str, Vulnerability]] = None) -> None:
    """
    Print details about ignored vulnerabilities.

    Args:
        console (Console): The console for output.
        project (ProjectModel): The project model.
        ignored (Set[str]): Set of ignored vulnerabilities.
        is_detailed_output (bool): Indicates if detailed output is enabled.
        ignored_vulns_data (Optional[Dict[str, Vulnerability]]): Data of ignored vulnerabilities.
    """
    from ..util import pluralize

    if is_detailed_output:
        if not ignored_vulns_data:
            ignored_vulns_data = iter([])


        manual_ignored = {}
        cvss_severity_ignored = {}
        cvss_severity_ignored_pkgs = set()
        unpinned_ignored = {}
        unpinned_ignored_pkgs = set()
        environment_ignored = {}
        environment_ignored_pkgs = set()

        for vuln_data in ignored_vulns_data:
            code = IgnoreCodes(vuln_data.ignored_code)
            if code is IgnoreCodes.manual:
                manual_ignored[vuln_data.vulnerability_id] = vuln_data
            elif code is IgnoreCodes.cvss_severity:
                cvss_severity_ignored[vuln_data.vulnerability_id] = vuln_data
                cvss_severity_ignored_pkgs.add(vuln_data.package_name)
            elif code is IgnoreCodes.unpinned_specification:
                unpinned_ignored[vuln_data.vulnerability_id] = vuln_data
                unpinned_ignored_pkgs.add(vuln_data.package_name)
            elif code is IgnoreCodes.environment_dependency:
                environment_ignored[vuln_data.vulnerability_id] = vuln_data
                environment_ignored_pkgs.add(vuln_data.package_name)

        if manual_ignored:
            count = len(manual_ignored)
            console.print(
                f"[number]{count}[/number] were manually ignored due to the project policy:")
            for vuln in manual_ignored.values():
                render_to_console(vuln, console,
                                  rich_kwargs={"emoji": True, "overflow": "crop"},
                                  detailed_output=is_detailed_output)
        if cvss_severity_ignored:
            count = len(cvss_severity_ignored)
            console.print(
                f"[number]{count}[/number] {pluralize('vulnerability', count)} {pluralize('was', count)} ignored because " \
                     "of their severity or exploitability impacted the following" \
                        f" {pluralize('package', len(cvss_severity_ignored_pkgs))}: {', '.join(cvss_severity_ignored_pkgs)}"
            )
        if environment_ignored:
            count = len(environment_ignored)
            console.print(
                f"[number]{count}[/number] {pluralize('vulnerability', count)} {pluralize('was', count)} ignored because " \
                     "they are inside an environment dependency."
            )
        if unpinned_ignored:
            count = len(unpinned_ignored)
            console.print(
                f"[number]{count}[/number] {pluralize('vulnerability', count)} {pluralize('was', count)} ignored because " \
                    f"{pluralize('this', len(unpinned_ignored_pkgs))} {pluralize('package', len(unpinned_ignored_pkgs))} {pluralize('has', len(unpinned_ignored_pkgs))} unpinned specs: " \
                        f"{', '.join(unpinned_ignored_pkgs)}"
            )

    else:
        if len(ignored) > 0:
            console.print(f"([number]{len(ignored)}[/number] {pluralize('vulnerability', len(ignored))} {pluralize('was', len(ignored))} ignored due to " \
                          "project policy)")


def print_wait_project_verification(console: Console, project_id: str, closure: Tuple[Any, Dict[str, Any]], on_error_delay: int = 1) -> Any:
    """
    Print a waiting message while verifying a project.

    Args:
        console (Console): The console for output.
        project_id (str): The project ID.
        closure (Tuple[Any, Dict[str, Any]]): The function and its arguments to call.
        on_error_delay (int): Delay in seconds on error.

    Returns:
        Any: The status of the project verification.
    """
    status = None
    wait_msg = f"Verifying project {project_id} with Safety Platform."

    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        try:
            f, kwargs = closure
            status = f(**kwargs)
        except Exception as e:
            LOG.exception(f'Unable to verify the project, reason: {e}')
            reason = "We are currently unable to verify the project, " \
                "and it is necessary to link the scan to a specific " \
                    f"project. Reason: {e}"
            raise SafetyException(message=reason)

        if not status:
            wait_msg = f'Unable to verify "{project_id}". Starting again...'
            time.sleep(on_error_delay)

    return status

def print_project_info(console: Console, project: ProjectModel):
    """
    Print information about the project.

    Args:
        console (Console): The console for output.
        project (ProjectModel): The project model.
    """
    config_msg = "loaded without policies or custom configuration."

    if project.policy:
        if project.policy.source is PolicySource.local:
            rel_location = project.policy.location.name if project.policy.location else ""
            config_msg = "configuration and policies fetched " \
                f"from {rel_location}."
        else:
            config_msg = " policies fetched " \
                "from Safety Platform."

    msg = f"[bold]{project.id} project found[/bold] - {config_msg}"
    console.print(msg)

def print_wait_policy_download(console: Console, closure: Tuple[Any, Dict[str, Any]]) -> Optional[PolicyFileModel]:
    """
    Print a waiting message while downloading a policy from the cloud.

    Args:
        console (Console): The console for output.
        closure (Tuple[Any, Dict[str, Any]]): The function and its arguments to call.

    Returns:
        Optional[PolicyFileModel]: The downloaded policy file model.
    """
    policy = None
    wait_msg = "Looking for a policy from cloud..."

    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        try:
            f, kwargs = closure
            policy = f(**kwargs)
        except Exception as e:
            LOG.exception(f'Policy download failed, reason: {e}')
            console.print("Not using cloud policy file.")

        if policy:
            wait_msg = "Policy fetched from Safety Platform."
        else:
            # TODO: Send a log
            pass
    return policy


def prompt_project_id(console: Console, stage: Stage, prj_root_name: Optional[str], do_not_exit: bool = True) -> Optional[str]:
    """
    Prompt the user to set a project ID for the scan.

    Args:
        console (Console): The console for output.
        stage (Stage): The current stage.
        prj_root_name (Optional[str]): The root name of the project.
        do_not_exit (bool): Indicates if the function should not exit on failure.

    Returns:
        Optional[str]: The project ID.
    """
    from safety.util import clean_project_id
    default_prj_id = clean_project_id(prj_root_name) if prj_root_name else None

    non_interactive_mode = console.quiet or not console.is_interactive
    if stage is not Stage.development and non_interactive_mode:
        # Fail here
        console.print("The scan needs to be linked to a project.")
        raise typer.Exit(code=1)

    hint = ""
    if default_prj_id:
        hint = f" If empty Safety will use [bold]{default_prj_id}[/bold]"
    prompt_text = f"Set a project id for this scan (no spaces).{hint}"

    def ask():
        prj_id = None

        result = Prompt.ask(prompt_text, default=None, console=console)

        if result:
            prj_id = clean_project_id(result)
        elif default_prj_id:
            prj_id = default_prj_id

        return prj_id

    project_id = ask()

    while not project_id and do_not_exit:
        project_id = ask()

    return project_id


def prompt_link_project(console: Console, prj_name: str, prj_admin_email: str) -> bool:
    """
    Prompt the user to link the scan with an existing project.

    Args:
        console (Console): The console for output.
        prj_name (str): The project name.
        prj_admin_email (str): The project admin email.

    Returns:
        bool: True if the user wants to link the scan, False otherwise.
    """
    console.print("[bold]Safety found an existing project with this name in your organization:[/bold]")

    for detail in (f"[bold]Project name:[/bold] {prj_name}",
                   f"[bold]Project admin:[/bold] {prj_admin_email}"):
        console.print(Padding(detail, (0, 0, 0, 2)), emoji=True)

    prompt_question = "Do you want to link this scan with this existing project?"

    answer = Prompt.ask(prompt=prompt_question, choices=["y", "n"],
                        default="y", show_default=True, console=console).lower()

    return answer == "y"


def render_to_console(cls: Vulnerability, console: Console, rich_kwargs: Dict[str, Any], detailed_output: bool = False) -> None:
    """
    Render a vulnerability to the console.

    Args:
        cls (Vulnerability): The vulnerability instance.
        console (Console): The console for output.
        rich_kwargs (Dict[str, Any]): Additional arguments for rendering.
        detailed_output (bool): Indicates if detailed output is enabled.
    """
    cls.__render__(console, detailed_output, rich_kwargs)


def get_render_console(entity_type: Any) -> Any:
    """
    Get the render function for a specific entity type.

    Args:
        entity_type (Any): The entity type.

    Returns:
        Any: The render function.
    """

    if entity_type is Vulnerability:
        def __render__(self, console: Console, detailed_output: bool, rich_kwargs):
            if not rich_kwargs:
                rich_kwargs = {}

            pre = " Ignored:" if self.ignored else ""
            severity_detail = None

            if self.severity and self.severity.source:
                severity_detail = self.severity.source

                if self.severity.cvssv3 and "base_severity" in self.severity.cvssv3:
                    severity_detail += f", CVSS Severity {self.severity.cvssv3['base_severity'].upper()}"

            advisory_length = 200 if detailed_output else 110

            console.print(
                Padding(
                    f"->{pre} Vuln ID [vuln_id]{self.vulnerability_id}[/vuln_id]: {severity_detail if severity_detail else ''}",
                    (0, 0, 0, 2)
                ), **rich_kwargs)
            console.print(
                Padding(
                    f"{self.advisory[:advisory_length]}{'...' if len(self.advisory) > advisory_length else ''}",
                    (0, 0, 0, 5)
                ), **rich_kwargs)

            if detailed_output:
                console.print(
                    Padding(f"For more information: [link]{self.more_info_url}[/link]", (0, 0, 0, 5)),
                      **rich_kwargs)

        return __render__


def render_scan_html(report: ReportModel, obj: Any) -> str:
    """
    Render the scan report to HTML.

    Args:
        report (ReportModel): The scan report model.
        obj (Any): The object containing additional settings.

    Returns:
        str: The rendered HTML report.
    """
    from safety.scan.command import ScannableEcosystems

    project = report.projects[0] if any(report.projects) else None

    scanned_packages = 0
    affected_packages = 0
    ignored_packages = 0
    remediations_recommended = 0
    ignored_vulnerabilities = 0
    vulnerabilities = 0
    vulns_per_file = defaultdict(int)
    remed_per_file = defaultdict(int)

    for file in project.files:
        scanned_packages += len(file.results.dependencies)
        affected_packages += len(file.results.get_affected_dependencies())
        ignored_vulnerabilities += len(file.results.ignored_vulns)

        for spec in file.results.get_affected_specifications():
            vulnerabilities += len(spec.vulnerabilities)
            vulns_per_file[file.location] += len(spec.vulnerabilities)
            if spec.remediation:
                remed_per_file[file.location] += 1
                remediations_recommended += 1

        ignored_packages += len(file.results.ignored_vulns)

    # TODO: Get this information for the report model (?)
    summary = {"scanned_packages": scanned_packages,
               "affected_packages": affected_packages,
               "remediations_recommended": remediations_recommended,
               "ignored_vulnerabilities": ignored_vulnerabilities, "vulnerabilities": vulnerabilities}

    vulnerabilities = []


    # TODO: This should be based on the configs per command
    ecosystems = [(f"{ecosystem.name.title()}",
                  [file_type.human_name(plural=True) for file_type in ecosystem.file_types]) for ecosystem in [Ecosystem(member.value) for member in list(ScannableEcosystems)]]

    settings ={"audit_and_monitor": True, "platform_url": SAFETY_PLATFORM_URL, "ecosystems": ecosystems}
    template_context = {"report": report, "summary": summary, "announcements": [],
                        "project": project,
                        "platform_enabled": obj.platform_enabled,
                        "settings": settings,
                        "vulns_per_file": vulns_per_file,
                        "remed_per_file": remed_per_file}

    return parse_html(kwargs=template_context, template="scan/index.html")


def generate_spdx_creation_info(spdx_version: str, project_identifier: str) -> Any:
    """
    Generate SPDX creation information.

    Args:
        spdx_version (str): The SPDX version.
        project_identifier (str): The project identifier.

    Returns:
        Any: The SPDX creation information.
    """
    from spdx_tools.spdx.model import (
        Actor,
        ActorType,
        CreationInfo,
    )

    version = int(time.time())
    SPDX_ID_TYPE = "SPDXRef-DOCUMENT"
    DOC_NAME = f"{project_identifier}-{version}"

    DOC_NAMESPACE = f"https://spdx.org/spdxdocs/{DOC_NAME}"
    # DOC_NAMESPACE = f"urn:safety:{project_identifier}:{version}"

    DOC_COMMENT = f"This document was created using SPDX {spdx_version}"
    CREATOR_COMMENT = "Safety CLI automatically created this SPDX document from a scan report."

    from ..util import get_safety_version
    TOOL_ID = "safety"
    TOOL_VERSION = get_safety_version()

    doc_creator = Actor(
        actor_type=ActorType.TOOL,
        name=f"{TOOL_ID}-{TOOL_VERSION}",
        email=None
    )

    creation_info = CreationInfo(
        spdx_version=f"SPDX-{spdx_version}",
        spdx_id=SPDX_ID_TYPE,
        name=DOC_NAME,
        document_namespace=DOC_NAMESPACE,
        creators=[doc_creator],
        created=datetime.datetime.now(),
        document_comment=DOC_COMMENT,
        creator_comment=CREATOR_COMMENT
    )
    return creation_info


def create_pkg_ext_ref(*, package: PythonDependency, version: Optional[str]) -> Any:
    """
    Create an external package reference for SPDX.

    Args:
        package (PythonDependency): The package dependency.
        version (Optional[str]): The package version.

    Returns:
        Any: The external package reference.
    """
    from spdx_tools.spdx.model import (
        ExternalPackageRef,
        ExternalPackageRefCategory,
    )

    version_detail = f'@{version}' if version else ''
    pkg_ref = ExternalPackageRef(
        ExternalPackageRefCategory.PACKAGE_MANAGER,
        "purl",
        f"pkg:pypi/{package.name}{version_detail}",
    )
    return pkg_ref


def create_packages(dependencies: List[PythonDependency]) -> List[Any]:
    """
    Create a list of SPDX packages.

    Args:
        dependencies (List[PythonDependency]): List of Python dependencies.

    Returns:
        List[Any]: List of SPDX packages.
    """
    from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

    from spdx_tools.spdx.model import (
        Package,
    )

    doc_pkgs = []
    pkgs_added = set([])
    for dependency in dependencies:
        for spec in dependency.specifications:
            pkg_version = next(iter(spec.specifier)).version if spec.is_pinned() else f"{spec.specifier}"
            dep_name = dependency.name.replace('_', '-')
            pkg_id = f"SPDXRef-pip-{dep_name}-{pkg_version}" if spec.is_pinned() else f"SPDXRef-pip-{dep_name}"
            if pkg_id in pkgs_added:
                continue
            pkg_ref = create_pkg_ext_ref(package=dependency, version=pkg_version)

            pkg = Package(
                spdx_id=pkg_id,
                name=f"pip:{dep_name}",
                download_location=SpdxNoAssertion(),
                version=pkg_version,
                file_name="",
                supplier=SpdxNoAssertion(),
                files_analyzed=False,
                license_concluded=SpdxNoAssertion(),
                license_declared=SpdxNoAssertion(),
                copyright_text=SpdxNoAssertion(),
                external_references=[pkg_ref],
            )
            pkgs_added.add(pkg_id)
            doc_pkgs.append(pkg)
    return doc_pkgs


def create_spdx_document(*, report: ReportModel, spdx_version: str) -> Optional[Any]:
    """
    Create an SPDX document.

    Args:
        report (ReportModel): The scan report model.
        spdx_version (str): The SPDX version.

    Returns:
        Optional[Any]: The SPDX document.
    """
    from spdx_tools.spdx.model import (
        Document,
        Relationship,
        RelationshipType,
    )

    project =  report.projects[0] if any(report.projects) else None

    if not project:
        return None

    prj_id = project.id

    if not prj_id:
        parent_name = project.project_path.parent.name
        prj_id = parent_name if parent_name else str(int(time.time()))

    creation_info = generate_spdx_creation_info(spdx_version=spdx_version, project_identifier=prj_id)

    depedencies = iter([])
    for file in project.files:
        depedencies = itertools.chain(depedencies, file.results.dependencies)

    packages = create_packages(depedencies)

    # Requirement for document to have atleast one relationship
    relationship = Relationship(
        "SPDXRef-DOCUMENT",
        RelationshipType.DESCRIBES,
        "SPDXRef-DOCUMENT"
    )
    spdx_doc = Document(
        creation_info,
        packages,
        [],
        [],
        [],
        [relationship],
        []
    )
    return spdx_doc


def render_scan_spdx(report: ReportModel, obj: Any, spdx_version: Optional[str]) -> Optional[Any]:
    """
    Render the scan report to SPDX format.

    Args:
        report (ReportModel): The scan report model.
        obj (Any): The object containing additional settings.
        spdx_version (Optional[str]): The SPDX version.

    Returns:
        Optional[Any]: The rendered SPDX document in JSON format.
    """
    from spdx_tools.spdx.writer.write_utils import (
        convert,
        validate_and_deduplicate
    )

    # Set to latest supported if a version is not specified
    if not spdx_version:
        spdx_version = "2.3"

    document_obj = create_spdx_document(report=report, spdx_version=spdx_version)
    document_obj = validate_and_deduplicate(document=document_obj, validate=True, drop_duplicates=True)
    doc = None

    if document_obj:
        doc = convert(document=document_obj, converter=None)

    return json.dumps(doc) if doc else None
