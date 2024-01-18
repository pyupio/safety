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
    requirements: ConstrainedDict[str, RequirementInfo]
    current_version: Optional[str]
    vulnerabilities_found: Optional[int]
    recommended_version: Optional[str]
    other_recommended_versions: List[str] = Field([], max_items=100, unique_items=True)
    more_info_url: Optional[HttpUrl]


class OSVulnerabilities(BaseModel):
    packages: ConstrainedDict[str, Package]
    vulnerabilities: List[Vulnerability] = Field(..., max_items=100, unique_items=True)


class EnvironmentFindings(BaseModel):
    configuration: ConstrainedDict
    packages: ConstrainedDict[str, Package]
    os_vulnerabilities: OSVulnerabilities


class Environment(BaseModel):
    full_location: Path
    type: Literal["environment"]
    findings: EnvironmentFindings


class DependencyVulnerabilities(BaseModel):
    packages: List[PackageShort] = Field(..., max_items=500, unique_items=True)
    vulnerabilities: List[Vulnerability] = Field(..., max_items=100, unique_items=True)


class FileFindings(BaseModel):
    configuration: ConstrainedDict
    packages: List[PackageShort] = Field(..., max_items=500, unique_items=True)
    dependency_vulnerabilities: DependencyVulnerabilities


class Remediations(BaseModel):
    configuration: ConstrainedDict
    packages: ConstrainedDict[str, Package]
    dependency_vulnerabilities: ConstrainedDict[str, Package]
    remediations_results: RemediationsResults


class File(BaseModel):
    full_location: Path
    type: str
    language: Literal["python"]
    format: str
    findings: FileFindings
    remediations: Remediations


class Results(BaseModel):
    environments: List[ConstrainedDict[Path, Environment]] = Field(
        [], max_items=100, unique_items=True
    )
    files: List[ConstrainedDict[str, File]] = Field(
        [], max_items=100, unique_items=True
    )


class Project(Results):
    id: Optional[int]
    location: Path
    policy: Optional[Path]
    policy_source: Optional[Literal["local", "cloud"]]
    git: Union[GitInfo, NoGit]


class ScanReportV30(BaseModel):
    meta: Meta
    results: Results | Dict = {}
    projects: Project | Dict = {}