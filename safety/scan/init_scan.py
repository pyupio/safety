import logging
from enum import Enum
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Generator,
    List,
    Optional,
    Tuple,
    Union,
    Literal,
)
from pydantic import BaseModel
import typer

from safety.auth.constants import SAFETY_PLATFORM_URL
from safety.errors import SafetyException
from safety.scan.command import (
    ScannableEcosystems,
    initialize_file_finder,
    scan_project_directory,
)
from safety.scan.main import (
    download_policy,
    load_policy_file,
    process_files,
    resolve_policy,
)
from safety_schemas.models import (
    Ecosystem,
    FileModel,
    FileType,
    RemediationModel,
    ReportModel,
    ReportSchemaVersion,
    ScanType,
    VulnerabilitySeverityLabels,
    MetadataModel,
    TelemetryModel,
    ProjectModel,
    Stage,
    AuthenticationType,
)

from safety.scan.util import GIT
from safety.util import build_telemetry_data


# Define typed models for scan results
class ScanResultType(str, Enum):
    """Types of scan results that can be yielded by the init_scan function"""

    INIT = "init"
    PROGRESS = "progress"
    UPLOADING = "uploading"
    STATUS = "status"
    COMPLETE = "complete"


class BaseScanResult(BaseModel):
    """Base class for all scan results with common attributes"""

    # No fields here - each subclass will define its own type
    pass


class InitScanResult(BaseScanResult):
    """Initial scan result with basic dependency info"""

    type: Literal[ScanResultType.INIT]
    dependencies: int
    progress: int = 0

    class Config:
        frozen = True  # Make immutable


class ProgressScanResult(BaseScanResult):
    """Progress update during scanning with current counts"""

    type: Literal[ScanResultType.PROGRESS]
    percent: int
    dependencies: int
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None
    others: Optional[int] = None
    fixes: Optional[int] = None
    fixed_vulns: Optional[int] = None
    file: str
    file_pkg_count: int
    file_count: int
    venv_count: int
    vulns_count: int

    class Config:
        frozen = True  # Make immutable


class CompleteScanResult(BaseScanResult):
    """Final scan result with complete vulnerability counts"""

    type: Literal[ScanResultType.COMPLETE]
    scan_id: Optional[str] = None
    percent: int = 100
    dependencies: int
    critical: int
    high: int
    medium: int
    low: int
    others: int
    vulns_count: int
    fixes: int
    fixed_vulns: int
    codebase_url: Optional[str] = None

    class Config:
        frozen = True  # Make immutable


class StatusScanResult(BaseScanResult):
    """Generic status update that can be used for any process"""

    type: Literal[ScanResultType.STATUS]
    message: str
    action: str  # The specific action being performed (e.g., "analyzing", "preparing")
    percent: Optional[int] = None

    class Config:
        frozen = True  # Make immutable


class UploadingScanResult(BaseScanResult):
    """Status update when uploading results to server"""

    type: Literal[ScanResultType.UPLOADING]
    message: str
    percent: Optional[int] = None

    class Config:
        frozen = True  # Make immutable


# Union type for all possible result types
ScanResult = Union[
    InitScanResult,
    ProgressScanResult,
    StatusScanResult,
    UploadingScanResult,
    CompleteScanResult,
]

LOG = logging.getLogger(__name__)

if TYPE_CHECKING:
    from safety_schemas.models import (
        ConfigModel,
        ProjectModel,
        MetadataModel,
        TelemetryModel,
        ReportModel,
        FileModel,
    )


def init_scan(
    ctx: Any,
    target: Path,
    config: "ConfigModel",
    metadata: "MetadataModel",
    telemetry: "TelemetryModel",
    project: "ProjectModel",
    use_server_matching: bool = False,
) -> Generator[ScanResult, None, Tuple["ReportModel", List["FileModel"]]]:
    """
    Core scanning logic that yields results as they become available.
    Contains no UI-related code - purely logic for scanning.

    Args:
        ctx: The context object with necessary configurations
        target: The target directory to scan
        config: The application configuration
        metadata: Metadata to include in the report
        telemetry: Telemetry data to include in the report
        project: The project object
        version: The schema version
        use_server_matching: Whether to use server-side vulnerability matching

    Yields:
        Dict containing scan progress information and results as they become available

    Returns:
        Tuple containing the final report model and list of files
    """
    # Emit status that scan is starting
    yield StatusScanResult(
        type=ScanResultType.STATUS,
        message="Starting safety scan",
        action="initializing",
        percent=0,
    )

    # Initialize ecosystems
    ecosystems = [Ecosystem(member.value) for member in list(ScannableEcosystems)]

    # Initialize file finder and locate project files
    from rich.console import Console

    console = Console()
    console.quiet = True

    yield StatusScanResult(
        type=ScanResultType.STATUS,
        message="Locating project files",
        action="discovering",
        percent=5,
    )

    file_finder = initialize_file_finder(ctx, target, None, ecosystems)

    yield StatusScanResult(
        type=ScanResultType.STATUS,
        message="Scanning project directory",
        action="scanning",
        percent=10,
    )

    _, file_paths = scan_project_directory(file_finder, console)

    total_files = sum(len(file_set) for file_set in file_paths.values())

    yield StatusScanResult(
        type=ScanResultType.STATUS,
        message=f"Found {total_files} files to analyze",
        action="analyzing",
        percent=15,
    )

    # Initialize counters and data structures
    files: List[FileModel] = []
    count = 0  # Total dependencies processed
    affected_count = 0
    critical_vulns_count = 0
    high_vulns_count = 0
    medium_vulns_count = 0
    low_vulns_count = 0
    others_vulns_count = 0
    vulns_count = 0
    fixes_count = 0
    total_resolved_vulns = 0
    file_count = 0
    venv_count = 0
    scan_id = None
    # Count the total number of files across all types

    # Initial yield with dependency info
    yield InitScanResult(type=ScanResultType.INIT, dependencies=count)

    # Status update before processing files
    yield StatusScanResult(
        type=ScanResultType.STATUS,
        message="Processing files for dependencies and vulnerabilities",
        action="analyzing",
        percent=20,
    )

    # Process each file for dependencies and vulnerabilities
    for idx, (path, analyzed_file) in enumerate(
        process_files(
            paths=file_paths,
            config=config,
            use_server_matching=use_server_matching,
            obj=ctx.obj,
            target=target,
        )
    ):
        # Calculate progress percentage
        # Calculate progress and ensure it never exceeds 100%
        if total_files > 0:
            progress = min(int((idx + 1) / total_files * 100), 100)
        else:
            progress = 100

        # Update counts for dependencies
        file_pkg_count = len(analyzed_file.dependency_results.dependencies)
        count += file_pkg_count

        # Track environment/file types
        if analyzed_file.file_type is FileType.VIRTUAL_ENVIRONMENT:
            venv_count += 1
        else:
            file_count += 1

        # Get affected specifications
        affected_specifications = (
            analyzed_file.dependency_results.get_affected_specifications()
        )
        affected_count += len(affected_specifications)

        # Count vulnerabilities by severity
        current_critical = 0
        current_high = 0
        current_medium = 0
        current_low = 0
        current_others = 0
        current_fixes = 0
        current_resolved_vulns = 0

        # Process each affected specification
        for spec in affected_specifications:
            # Access vulnerabilities
            for vuln in spec.vulnerabilities:
                if vuln.ignored:
                    continue

                vulns_count += 1

                # Determine vulnerability severity
                severity = severity = VulnerabilitySeverityLabels.UNKNOWN
                if (
                    hasattr(vuln, "CVE")
                    and vuln.CVE
                    and hasattr(vuln.CVE, "cvssv3")
                    and vuln.CVE.cvssv3
                ):
                    severity_str = vuln.CVE.cvssv3.get("base_severity", "none").lower()
                    severity = VulnerabilitySeverityLabels(severity_str)

                # Count based on severity
                if severity is VulnerabilitySeverityLabels.CRITICAL:
                    current_critical += 1
                elif severity is VulnerabilitySeverityLabels.HIGH:
                    current_high += 1
                elif severity is VulnerabilitySeverityLabels.MEDIUM:
                    current_medium += 1
                elif severity is VulnerabilitySeverityLabels.LOW:
                    current_low += 1
                else:
                    current_others += 1

            # Check for available fixes - safely access remediation attributes
            if spec.remediation:
                # Access remediation properties safely without relying on specific attribute names
                remediation: RemediationModel = spec.remediation
                has_recommended_version = True if remediation.recommended else False

                if has_recommended_version:
                    current_fixes += 1
                    current_resolved_vulns += len(
                        [v for v in spec.vulnerabilities if not v.ignored]
                    )

        # Update total counts
        critical_vulns_count += current_critical
        high_vulns_count += current_high
        medium_vulns_count += current_medium
        low_vulns_count += current_low
        others_vulns_count += current_others
        fixes_count += current_fixes
        total_resolved_vulns += current_resolved_vulns

        # Save file data for further processing
        file = FileModel(
            location=path,
            file_type=analyzed_file.file_type,
            results=analyzed_file.dependency_results,
        )
        files.append(file)

        # Yield current analysis results
        yield ProgressScanResult(
            type=ScanResultType.PROGRESS,
            percent=progress,
            dependencies=count,
            critical=critical_vulns_count,
            high=high_vulns_count,
            medium=medium_vulns_count,
            low=low_vulns_count,
            others=others_vulns_count,
            vulns_count=vulns_count,
            fixes=fixes_count,
            fixed_vulns=total_resolved_vulns,
            file=str(path),
            file_pkg_count=file_pkg_count,
            file_count=file_count,
            venv_count=venv_count,
        )

    # All files processed, create the report
    project.files = files

    yield StatusScanResult(
        type=ScanResultType.STATUS,
        message="Creating final report",
        action="reporting",
        percent=90,
    )

    # Convert dictionaries to model objects if needed
    if isinstance(metadata, dict):
        metadata_model = MetadataModel(**metadata)
    else:
        metadata_model = metadata

    if isinstance(telemetry, dict):
        telemetry_model = TelemetryModel(**telemetry)
    else:
        telemetry_model = telemetry

    report = ReportModel(
        version=ReportSchemaVersion.v3_0,
        metadata=metadata_model,
        telemetry=telemetry_model,
        files=[],
        projects=[project],
    )

    # Emit uploading status before starting upload
    yield UploadingScanResult(
        type=ScanResultType.UPLOADING, message="Preparing to upload scan results"
    )

    # TODO: Decouple platform upload logic
    try:
        # Convert report to JSON format
        yield UploadingScanResult(
            type=ScanResultType.UPLOADING,
            message="Converting report to JSON format",
            percent=25,
        )
        json_format = report.as_v30().json()

        # Start upload
        yield UploadingScanResult(
            type=ScanResultType.UPLOADING,
            message="Uploading results to Safety platform",
            percent=50,
        )
        result = ctx.obj.auth.client.upload_report(json_format)

        # Upload complete
        yield UploadingScanResult(
            type=ScanResultType.UPLOADING,
            message="Upload completed successfully",
            percent=100,
        )

        scan_id = result.get("uuid")

        codebase_url = f"{SAFETY_PLATFORM_URL}{result['url']}"

    except Exception as e:
        # Emit error status
        yield UploadingScanResult(
            type=ScanResultType.UPLOADING, message=f"Error uploading results: {str(e)}"
        )
        raise e

    # Final yield with completed flag
    yield CompleteScanResult(
        type=ScanResultType.COMPLETE,
        dependencies=count,
        critical=critical_vulns_count,
        high=high_vulns_count,
        medium=medium_vulns_count,
        low=low_vulns_count,
        others=others_vulns_count,
        vulns_count=vulns_count,
        fixes=fixes_count,
        fixed_vulns=total_resolved_vulns,
        codebase_url=codebase_url,
        scan_id=scan_id,
    )

    # Return the complete report and files
    return report, files


def start_scan(
    ctx: "typer.Context",
    auth_type: AuthenticationType,
    is_authenticated: bool,
    target: Path,
    client: Any,
    project: ProjectModel,
    branch: Optional[str] = None,
    stage: Stage = Stage.development,
    platform_enabled: bool = False,
    telemetry_enabled: bool = True,
    use_server_matching: bool = False,
) -> Generator["ScanResult", None, Tuple["ReportModel", List["FileModel"]]]:
    """
    Initialize and start a scan, returning an iterator that yields scan results.
    This function handles setting up all required parameters for the scan.

    Args:
        ctx: The Typer context object containing configuration and project information
        target: The target directory to scan
        use_server_matching: Whether to use server-side vulnerability matching

    Returns:
        An iterator that yields scan results
    """
    if not branch:
        if git_data := GIT(root=target).build_git_data():
            branch = git_data.branch

    command_name = "scan"
    telemetry = build_telemetry_data(
        telemetry=telemetry_enabled, command=command_name, subcommand=None
    )

    scan_type = ScanType(command_name)
    targets = [target]

    if not scan_type:
        raise SafetyException("Missing scan_type.")

    metadata = MetadataModel(
        scan_type=scan_type,
        stage=stage,
        scan_locations=targets,
        authenticated=is_authenticated,
        authentication_type=auth_type,
        telemetry=telemetry,
        schema_version=ReportSchemaVersion.v3_0,
    )

    policy_file_path = target / Path(".safety-policy.yml")

    # Load Policy file and pull it from CLOUD
    local_policy = load_policy_file(policy_file_path)

    cloud_policy = None
    if platform_enabled:
        cloud_policy = download_policy(
            client, project_id=project.id, stage=stage, branch=branch
        )

    project.policy = resolve_policy(local_policy, cloud_policy)
    config = (
        project.policy.config
        if project.policy and project.policy.config
        else ConfigModel()
    )

    return init_scan(
        ctx=ctx,
        target=target,
        config=config,
        metadata=metadata,
        telemetry=telemetry,
        project=project,
        use_server_matching=use_server_matching,
    )
