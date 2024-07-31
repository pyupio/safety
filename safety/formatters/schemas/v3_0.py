from datetime import datetime
from pathlib import Path
from typing import Dict, List, Literal, Optional, Union

from pydantic import Field, HttpUrl

from common.schemas import BaseModel, ConstrainedDict
from scans.schemas.base import (
    GitInfo,
    NoGit,
    PackageShort,
    RemediationsResults,
    RequirementInfo,
    Telemetry,
    Vulnerability,
)


class Meta(BaseModel):
    """
    Metadata for the scan report.

    Attributes:
        scan_type (Literal["system-scan", "scan", "check"]): The type of scan.
        scan_location (Path): The location of the scan.
        logged_to_dashboard (bool): Whether the scan was logged to the dashboard.
        authenticated (bool): Whether the scan was authenticated.
        authentication_method (Literal["token", "api_key"]): The method of authentication.
        local_database_path (Optional[Path]): The path to the local database.
        safety_version (str): The version of the Safety tool used.
        timestamp (datetime): The timestamp of the scan.
        telemetry (Telemetry): Telemetry data related to the scan.
        schema_version (str): The version of the schema used.
    """
    scan_type: Literal["system-scan", "scan", "check"]
    scan_location: Path
    logged_to_dashboard: bool
    authenticated: bool
    authentication_method: Literal["token", "api_key"]
    local_database_path: Optional[Path]
    safety_version: str
    timestamp: datetime
    telemetry: Telemetry
    schema_version: str


class Package(BaseModel):
    """
    Information about a package and its vulnerabilities.

    Attributes:
        requirements (ConstrainedDict[str, RequirementInfo]): The package requirements.
        current_version (Optional[str]): The current version of the package.
        vulnerabilities_found (Optional[int]): The number of vulnerabilities found.
        recommended_version (Optional[str]): The recommended version of the package.
        other_recommended_versions (List[str]): Other recommended versions of the package.
        more_info_url (Optional[HttpUrl]): URL for more information about the package.
    """
    requirements: ConstrainedDict[str, RequirementInfo]
    current_version: Optional[str]
    vulnerabilities_found: Optional[int]
    recommended_version: Optional[str]
    other_recommended_versions: List[str] = Field([], max_items=100, unique_items=True)
    more_info_url: Optional[HttpUrl]


class OSVulnerabilities(BaseModel):
    """
    Information about OS vulnerabilities.

    Attributes:
        packages (ConstrainedDict[str, Package]): Packages with vulnerabilities.
        vulnerabilities (List[Vulnerability]): List of vulnerabilities.
    """
    packages: ConstrainedDict[str, Package]
    vulnerabilities: List[Vulnerability] = Field(..., max_items=100, unique_items=True)


class EnvironmentFindings(BaseModel):
    """
    Findings related to the environment.

    Attributes:
        configuration (ConstrainedDict): Configuration details.
        packages (ConstrainedDict[str, Package]): Packages found in the environment.
        os_vulnerabilities (OSVulnerabilities): OS vulnerabilities found.
    """
    configuration: ConstrainedDict
    packages: ConstrainedDict[str, Package]
    os_vulnerabilities: OSVulnerabilities


class Environment(BaseModel):
    """
    Details about the environment being scanned.

    Attributes:
        full_location (Path): The full path of the environment.
        type (Literal["environment"]): The type of the environment.
        findings (EnvironmentFindings): Findings related to the environment.
    """
    full_location: Path
    type: Literal["environment"]
    findings: EnvironmentFindings


class DependencyVulnerabilities(BaseModel):
    """
    Information about dependency vulnerabilities.

    Attributes:
        packages (List[PackageShort]): List of packages with vulnerabilities.
        vulnerabilities (List[Vulnerability]): List of vulnerabilities found.
    """
    packages: List[PackageShort] = Field(..., max_items=500, unique_items=True)
    vulnerabilities: List[Vulnerability] = Field(..., max_items=100, unique_items=True)


class FileFindings(BaseModel):
    """
    Findings related to a file.

    Attributes:
        configuration (ConstrainedDict): Configuration details.
        packages (List[PackageShort]): List of packages found in the file.
        dependency_vulnerabilities (DependencyVulnerabilities): Dependency vulnerabilities found.
    """
    configuration: ConstrainedDict
    packages: List[PackageShort] = Field(..., max_items=500, unique_items=True)
    dependency_vulnerabilities: DependencyVulnerabilities


class Remediations(BaseModel):
    """
    Remediations for vulnerabilities.

    Attributes:
        configuration (ConstrainedDict): Configuration details.
        packages (ConstrainedDict[str, Package]): Packages with remediations.
        dependency_vulnerabilities (ConstrainedDict[str, Package]): Dependency vulnerabilities with remediations.
        remediations_results (RemediationsResults): Results of the remediations.
    """
    configuration: ConstrainedDict
    packages: ConstrainedDict[str, Package]
    dependency_vulnerabilities: ConstrainedDict[str, Package]
    remediations_results: RemediationsResults


class File(BaseModel):
    """
    Information about a scanned file.

    Attributes:
        full_location (Path): The full path of the file.
        type (str): The type of the file.
        language (Literal["python"]): The programming language of the file.
        format (str): The format of the file.
        findings (FileFindings): Findings related to the file.
        remediations (Remediations): Remediations for the file.
    """
    full_location: Path
    type: str
    language: Literal["python"]
    format: str
    findings: FileFindings
    remediations: Remediations


class Results(BaseModel):
    """
    The results of a scan.

    Attributes:
        environments (List[ConstrainedDict[Path, Environment]]): List of environments scanned.
        files (List[ConstrainedDict[str, File]]): List of files scanned.
    """
    environments: List[ConstrainedDict[Path, Environment]] = Field(
        [], max_items=100, unique_items=True
    )
    files: List[ConstrainedDict[str, File]] = Field(
        [], max_items=100, unique_items=True
    )


class Project(Results):
    """
    Information about a project being scanned.

    Attributes:
        id (Optional[int]): The project ID.
        location (Path): The location of the project.
        policy (Optional[Path]): The policy file for the project.
        policy_source (Optional[Literal["local", "cloud"]]): The source of the policy.
        git (Union[GitInfo, NoGit]): Git information related to the project.
    """
    id: Optional[int]
    location: Path
    policy: Optional[Path]
    policy_source: Optional[Literal["local", "cloud"]]
    git: Union[GitInfo, NoGit]


class ScanReportV30(BaseModel):
    """
    The scan report.

    Attributes:
        meta (Meta): Metadata about the scan.
        results (Union[Results, Dict]): The results of the scan.
        projects (Union[Project, Dict]): Projects involved in the scan.
    """
    meta: Meta
    results: Results | Dict = {}
    projects: Project | Dict = {}