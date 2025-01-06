import json
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union

from dparse.dependencies import Dependency
from dparse import parse, filetypes
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version, Version
from safety_schemas.models import ConfigModel, MetadataModel, ReportSchemaVersion, TelemetryModel, PolicyFileModel
from safety.errors import InvalidRequirementError

try:
    from packaging.version import LegacyVersion as LegacyType
except ImportError:
    LegacyType = None


class DictConverter:
    """
    Base class to convert objects to dictionaries.
    """

    def to_dict(self, **kwargs: Any) -> Dict:
        """
        Convert an object to a dictionary.
        """
        pass


Announcement = namedtuple('Announcement', ['type', 'message'])
Remediation = namedtuple(
    'Remediation',
    ['package', 'closest_secure_version', 'secure_versions', 'latest_package_version']
)
CVE = namedtuple('CVE', ['name', 'cvssv2', 'cvssv3'])
Severity = namedtuple('Severity', ['source', 'cvssv2', 'cvssv3'])
Vulnerability = namedtuple(
    'Vulnerability',
    [
        'vulnerability_id', 'package_name', 'pkg', 'ignored', 'ignored_reason', 'ignored_expires',
        'vulnerable_spec', 'all_vulnerable_specs', 'analyzed_version', 'analyzed_requirement',
        'advisory', 'is_transitive', 'published_date', 'fixed_versions',
        'closest_versions_without_known_vulnerabilities', 'resources', 'CVE', 'severity',
        'affected_versions', 'more_info_url'
    ]
)
RequirementFile = namedtuple('RequirementFile', ['path'])


class SafetyRequirement(Requirement):
    """
    Represents a requirement with additional attributes for safety.
    """

    def __init__(self, requirement: Union[str, Dependency], found: Optional[str] = None) -> None:
        """
        Initialize a SafetyRequirement instance.

        Args:
            requirement (Union[str, Dependency]): The requirement as a string or Dependency object.
            found (Optional[str]): The source where the requirement was found.

        Raises:
            InvalidRequirementError: If the requirement cannot be parsed.
        """
        dep = requirement

        if isinstance(requirement, str):
            deps = parse(requirement, file_type=filetypes.requirements_txt).dependencies
            dep = deps[0] if deps else None

        if not dep:
            raise InvalidRequirementError(line=str(requirement))

        raw_line = dep.line
        to_parse = dep.line.split('#')[0].strip() if '#' in dep.line else dep.line.strip()

        for req_hash in dep.hashes:
            to_parse = to_parse.replace(req_hash, '')

        try:
            super().__init__(to_parse)
        except Exception:
            raise InvalidRequirementError(
                line=requirement.line if isinstance(requirement, Dependency) else requirement
            )

        self.raw = raw_line
        self.found = found

    def __eq__(self, other: Any) -> bool:
        return str(self) == str(other)

    def to_dict(self, **kwargs: Any) -> Dict:
        """
        Convert the requirement to a dictionary.

        Args:
            **kwargs: Additional arguments for the conversion.

        Returns:
            Dict: The dictionary representation of the requirement.
        """
        return {
            'raw': self.raw,
            'extras': list(self.extras),
            'marker': str(self.marker) if self.marker else None,
            'name': self.name,
            'specifier': kwargs.get('specifier_obj', str(self.specifier)),
            'url': self.url,
            'found': self.found
        }


def is_pinned_requirement(spec: SpecifierSet) -> bool:
    """
    Determine if a requirement is pinned.

    Args:
        spec (SpecifierSet): The specifier set of the requirement.

    Returns:
        bool: True if the requirement is pinned, False otherwise.
    """
    if not spec or len(spec) != 1:
        return False

    specifier = next(iter(spec))
    return (specifier.operator == '==' and '*' != specifier.version[-1]) or specifier.operator == '==='


@dataclass
class Package(DictConverter):
    """
    Represents a software package.
    """

    name: str
    version: Optional[str]
    requirements: List[SafetyRequirement]
    found: Optional[str] = None
    absolute_path: Optional[str] = None
    insecure_versions: List[str] = field(default_factory=list)
    secure_versions: List[str] = field(default_factory=list)
    latest_version_without_known_vulnerabilities: Optional[str] = None
    latest_version: Optional[str] = None
    more_info_url: Optional[str] = None

    def has_unpinned_req(self) -> bool:
        """
        Check if the package has unpinned requirements.

        Returns:
            bool: True if there are unpinned requirements, False otherwise.
        """
        return any(not is_pinned_requirement(req.specifier) for req in self.requirements)

    def get_unpinned_req(self):
        """
        Retrieve unpinned requirements.

        Returns:
            filter: A filter object with unpinned requirements.
        """
        return filter(lambda req: not is_pinned_requirement(req.specifier), self.requirements)

    def filter_by_supported_versions(self, versions: List[str]) -> List[str]:
        """
        Filter the given versions by those supported.

        Args:
            versions (List[str]): The list of versions to filter.

        Returns:
            List[str]: A list of supported versions.
        """
        return [version for version in versions if parse_version(version)]

    def get_versions(self, db_full: Dict) -> Set[str]:
        """
        Retrieve versions of the package from the database.

        Args:
            db_full (Dict): The database containing package information.

        Returns:
            Set[str]: A set of versions.
        """
        package_data = db_full.get('meta', {}).get('packages', {}).get(self.name, {})
        versions = package_data.get('insecure_versions', []) + package_data.get('secure_versions', [])
        return set(self.filter_by_supported_versions(versions))

    def refresh_from(self, db_full: Dict) -> None:
        """
        Refresh package data from the database.

        Args:
            db_full (Dict): The database containing package information.
        """
        package_data = db_full.get('meta', {}).get('packages', {}).get(canonicalize_name(self.name), {})
        base_domain = db_full.get('meta', {}).get('base_domain', '')

        self.update({
            'insecure_versions': self.filter_by_supported_versions(package_data.get('insecure_versions', [])),
            'secure_versions': self.filter_by_supported_versions(package_data.get('secure_versions', [])),
            'latest_version_without_known_vulnerabilities': package_data.get('latest_secure_version'),
            'latest_version': package_data.get('latest_version'),
            'more_info_url': f"{base_domain}{package_data.get('more_info_path', '')}"
        })

    def to_dict(self, **kwargs: Any) -> Dict:
        """
        Convert the package to a dictionary.

        Args:
            **kwargs: Additional arguments for the conversion.

        Returns:
            Dict: The dictionary representation of the package.
        """
        if kwargs.get('short_version', False):
            return {'name': self.name, 'version': self.version, 'requirements': self.requirements}

        return {
            'name': self.name,
            'version': self.version,
            'requirements': self.requirements,
            'found': self.found,
            'insecure_versions': self.insecure_versions,
            'secure_versions': self.secure_versions,
            'latest_version_without_known_vulnerabilities': self.latest_version_without_known_vulnerabilities,
            'latest_version': self.latest_version,
            'more_info_url': self.more_info_url
        }

    def update(self, updates: Dict) -> None:
        """
        Update package attributes with new values.

        Args:
            updates (Dict): A dictionary of attribute updates.
        """
        for key, value in updates.items():
            if hasattr(self, key):
                setattr(self, key, value)


# Remaining classes (`Announcement`, `Remediation`, `Fix`, `CVE`, `Severity`, `SafetyEncoder`, etc.)
# follow similar refactoring, ensuring consistency, descriptive naming, and clean formatting.


@dataclass
class Fix:
    """
    Represents a fix for a dependency vulnerability.
    """

    dependency: Any = None
    previous_version: Any = None
    previous_spec: Optional[str] = None
    other_options: List[str] = field(default_factory=list)
    updated_version: Any = None
    update_type: str = ''
    package: str = ''
    status: str = ''
    applied_at: str = ''
    fix_type: str = ''
    more_info_url: str = ''


class CVE(CVE, DictConverter):
    """
    Represents a Common Vulnerabilities and Exposures (CVE) entry.
    """

    def to_dict(self) -> Dict:
        """
        Convert the CVE to a dictionary.

        Returns:
            Dict: The dictionary representation of the CVE.
        """
        return {
            'name': self.name,
            'cvssv2': self.cvssv2,
            'cvssv3': self.cvssv3
        }


class Severity(Severity, DictConverter):
    """
    Represents the severity of a vulnerability.
    """

    def to_dict(self) -> Dict:
        """
        Convert the severity to a dictionary.

        Returns:
            Dict: The dictionary representation of the severity.
        """
        return {
            'severity': {
                'source': self.source,
                'cvssv2': self.cvssv2,
                'cvssv3': self.cvssv3
            }
        }


class SafetyEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for Safety-related objects.
    """

    def default(self, value: Any) -> Any:
        """
        Encode custom objects.

        Args:
            value (Any): The object to encode.

        Returns:
            Any: The encoded representation of the object.
        """
        if isinstance(value, SafetyRequirement):
            return value.to_dict()
        if isinstance(value, (Version, LegacyType)):
            return str(value)
        return super().default(value)


class Vulnerability(Vulnerability):
    """
    Represents a software vulnerability.
    """

    def to_dict(self) -> Dict:
        """
        Convert the vulnerability to a dictionary.

        Returns:
            Dict: The dictionary representation of the vulnerability.
        """
        empty_fields = ['fixed_versions', 'closest_versions_without_known_vulnerabilities', 'resources']
        result = {}

        for field, value in zip(self._fields, self):
            if field == 'pkg':
                continue

            if value is None and field in empty_fields:
                value = []

            if isinstance(value, set):
                result[field] = list(value)
            elif isinstance(value, CVE):
                result[field] = value.name if value.name.startswith('CVE') else None
            elif isinstance(value, DictConverter):
                result.update(value.to_dict())
            elif isinstance(value, (SpecifierSet, datetime)):
                result[field] = str(value)
            else:
                result[field] = value

        return result

    def get_advisory(self) -> str:
        """
        Retrieve the advisory for the vulnerability.

        Returns:
            str: The advisory text.
        """
        return self.advisory.replace('\r', '') if self.advisory else 'No advisory found for this vulnerability.'

    def to_model_dict(self) -> Dict:
        """
        Convert the vulnerability to a dictionary suitable for models.

        Returns:
            Dict: The model-friendly dictionary representation.
        """
        affected_spec = next(iter(self.vulnerable_spec), '') if self.vulnerable_spec else ''
        representation = {
            'id': self.vulnerability_id,
            'package_name': self.package_name,
            'vulnerable_spec': affected_spec,
            'analyzed_specification': self.analyzed_requirement.raw
        }

        if self.ignored:
            representation['ignored'] = {
                'reason': self.ignored_reason,
                'expires': self.ignored_expires
            }

        return representation


@dataclass
class Safety:
    """
    Represents Safety settings.
    """

    client: Any
    keys: Any


@dataclass
class SafetyCLI:
    """
    Represents Safety CLI settings.
    """

    auth: Optional[Auth] = None
    telemetry: Optional[TelemetryModel] = None
    metadata: Optional[MetadataModel] = None
    schema: Optional[ReportSchemaVersion] = None
    project: Optional[Any] = None
    config: Optional[ConfigModel] = None
    console: Optional[Console] = None
    system_scan_policy: Optional[PolicyFileModel] = None
    platform_enabled: bool = False


class Announcement(Announcement):
    """
    Represents an announcement.
    """
    pass


class Remediation(Remediation, DictConverter):
    """
    Represents a remediation for a vulnerability.
    """

    def to_dict(self) -> Dict:
        """
        Convert the remediation to a dictionary.

        Returns:
            Dict: The dictionary representation of the remediation.
        """
        return {
            'package': self.package.name,
            'closest_secure_version': self.closest_secure_version,
            'secure_versions': self.secure_versions,
            'latest_package_version': self.latest_package_version
        }
