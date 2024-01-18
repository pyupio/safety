import json
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime

from dparse.dependencies import Dependency
from dparse import parse, filetypes
from typing import Any, List, Optional
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version

from packaging.version import Version
from safety_schemas.models import ConfigModel

from safety.errors import InvalidRequirementError
from safety_schemas.models import MetadataModel, ReportSchemaVersion, TelemetryModel, \
    PolicyFileModel

try:
    from packaging.version import LegacyVersion as legacyType
except ImportError:
    legacyType = None


class DictConverter(object):

    def to_dict(self, **kwargs):
        pass


announcement_nmt = namedtuple('Announcement', ['type', 'message'])
remediation_nmt = namedtuple('Remediation', ['Package', 'closest_secure_version', 'secure_versions',
                                             'latest_package_version'])
cve_nmt = namedtuple('Cve', ['name', 'cvssv2', 'cvssv3'])
severity_nmt = namedtuple('Severity', ['source', 'cvssv2', 'cvssv3'])
vulnerability_nmt = namedtuple('Vulnerability',
                               ['vulnerability_id', 'package_name', 'pkg', 'ignored', 'ignored_reason', 'ignored_expires',
                                'vulnerable_spec', 'all_vulnerable_specs', 'analyzed_version', 'analyzed_requirement',
                                'advisory', 'is_transitive', 'published_date', 'fixed_versions',
                                'closest_versions_without_known_vulnerabilities', 'resources', 'CVE', 'severity',
                                'affected_versions', 'more_info_url'])
RequirementFile = namedtuple('RequirementFile', ['path'])


class SafetyRequirement(Requirement):
    def __init__(self, requirement: [str, Dependency], found: Optional[str] = None) -> None:
        dep = requirement

        if isinstance(requirement, str):
            deps = parse(requirement, file_type=filetypes.requirements_txt).dependencies
            dep = deps[0] if deps else None

        if not dep:
            raise InvalidRequirementError(line=str(requirement))

        raw_line = dep.line
        to_parse = dep.line
        # Hash and comments are only a pip feature, so removing them.
        if '#' in to_parse:
            to_parse = dep.line.split('#')[0]

        for req_hash in dep.hashes:
            to_parse = to_parse.replace(req_hash, '')

        to_parse = to_parse.replace('\\', '').rstrip()

        try:
            # Try to build a PEP Requirement from the cleaned line
            super(SafetyRequirement, self).__init__(to_parse)
        except Exception:
            raise InvalidRequirementError(line=requirement.line if isinstance(requirement, Dependency) else requirement)

        self.raw = raw_line
        self.found = found

    def __eq__(self, other):
        return str(self) == str(other)
    
    def to_dict(self, **kwargs):
        specifier_obj = self.specifier
        if not "specifier_obj" in kwargs:
            specifier_obj = str(self.specifier)

        return   {
                        'raw': self.raw,
                        'extras': list(self.extras),
                        'marker': str(self.marker) if self.marker else None,
                        'name': self.name,
                        'specifier': specifier_obj,
                        'url': self.url,
                        'found': self.found
                    }


def is_pinned_requirement(spec: SpecifierSet) -> bool:
    if not spec or len(spec) != 1:
        return False

    specifier = next(iter(spec))

    return (specifier.operator == '==' and '*' != specifier.version[-1]) or specifier.operator == '==='


@dataclass
class Package(DictConverter):
    name: str
    version: Optional[str]
    requirements: List[SafetyRequirement]
    found: Optional[str] = None
    absolute_path: Optional[str] = None
    insecure_versions: List[str] = field(default_factory=lambda: [])
    secure_versions: List[str] = field(default_factory=lambda: [])
    latest_version_without_known_vulnerabilities: Optional[str] = None
    latest_version: Optional[str] = None
    more_info_url: Optional[str] = None

    def has_unpinned_req(self):
        for req in self.requirements:
            if not is_pinned_requirement(req.specifier):
                return True
        return False

    def get_unpinned_req(self):
        return filter(lambda r: not is_pinned_requirement(r.specifier), self.requirements)

    def filter_by_supported_versions(self, versions: [str]) -> [str]:
        allowed = []

        for version in versions:
            try:
                parse_version(version)
                allowed.append(version)
            except Exception:
                pass

        return allowed

    def get_versions(self, db_full):
        pkg_meta = db_full.get('meta', {}).get('packages', {}).get(self.name, {})
        versions = self.filter_by_supported_versions(
            pkg_meta.get("insecure_versions", []) + pkg_meta.get("secure_versions", []))
        return set(versions)

    def refresh_from(self, db_full):
        base_domain = db_full.get('meta', {}).get('base_domain')
        pkg_meta = db_full.get('meta', {}).get('packages', {}).get(canonicalize_name(self.name), {})

        kwargs = {'insecure_versions': self.filter_by_supported_versions(pkg_meta.get("insecure_versions", [])),
                  'secure_versions': self.filter_by_supported_versions(pkg_meta.get("secure_versions", [])),
                  'latest_version_without_known_vulnerabilities': pkg_meta.get("latest_secure_version",
                                                                               None),
                  'latest_version': pkg_meta.get("latest_version", None),
                  'more_info_url': f"{base_domain}{pkg_meta.get('more_info_path', '')}"}

        self.update(kwargs)

    def to_dict(self, **kwargs):
        if kwargs.get('short_version', False):
            return {
                'name': self.name,
                'version': self.version,
                'requirements': self.requirements
            }

        return {'name': self.name,
                'version': self.version,
                'requirements': self.requirements,
                'found': None,
                'insecure_versions': self.insecure_versions,
                'secure_versions': self.secure_versions,
                'latest_version_without_known_vulnerabilities': self.latest_version_without_known_vulnerabilities,
                'latest_version': self.latest_version,
                'more_info_url': self.more_info_url
                }

    def update(self, new):
        for key, value in new.items():
            if hasattr(self, key):
                setattr(self, key, value)


class Announcement(announcement_nmt):
    pass


class Remediation(remediation_nmt, DictConverter):

    def to_dict(self):
        return {'package': self.Package.name,
                'closest_secure_version': self.closest_secure_version,
                'secure_versions': self.secure_versions,
                'latest_package_version': self.latest_package_version
                }


@dataclass
class Fix:
    dependency: Any = None
    previous_version: Any = None
    previous_spec: Optional[str] = None
    other_options: [str] = field(default_factory=lambda: [])
    updated_version: Any = None
    update_type: str = ""
    package: str = ""
    status: str = ""
    applied_at: str = ""
    fix_type: str = ""
    more_info_url: str = ""


class CVE(cve_nmt, DictConverter):

    def to_dict(self):
        return {'name': self.name, 'cvssv2': self.cvssv2, 'cvssv3': self.cvssv3}


class Severity(severity_nmt, DictConverter):
    def to_dict(self):
        result = {'severity': {'source': self.source}}

        result['severity']['cvssv2'] = self.cvssv2
        result['severity']['cvssv3'] = self.cvssv3

        return result


class SafetyEncoder(json.JSONEncoder):
    def default(self, value):
        if isinstance(value, SafetyRequirement):
            return value.to_dict()
        elif isinstance(value, Version) or (legacyType and isinstance(value, legacyType)):
            return str(value)
        else:
            return super().default(value)


class Vulnerability(vulnerability_nmt):

    def to_dict(self):
        empty_list_if_none = ['fixed_versions', 'closest_versions_without_known_vulnerabilities', 'resources']
        result = {
        }

        ignore = ['pkg']

        for field, value in zip(self._fields, self):
            if field in ignore:
                continue

            if value is None and field in empty_list_if_none:
                value = []

            if isinstance(value, set):
                result[field] = list(value)
            elif isinstance(value, CVE):
                val = None
                if value.name.startswith("CVE"):
                    val = value.name
                result[field] = val
            elif isinstance(value, DictConverter):
                result.update(value.to_dict())
            elif isinstance(value, SpecifierSet) or isinstance(value, datetime):
                result[field] = str(value)
            else:
                result[field] = value

        return result

    def get_advisory(self):
        return self.advisory.replace('\r', '') if self.advisory else "No advisory found for this vulnerability."
    
    def to_model_dict(self):
        try:
            affected_spec = next(iter(self.vulnerable_spec))
        except Exception:
            affected_spec = ""

        repr = {
            "id": self.vulnerability_id,
            "package_name": self.package_name,
            "vulnerable_spec": affected_spec,
            "analyzed_specification": self.analyzed_requirement.raw
        }

        if self.ignored:
            repr["ignored"] = {"reason": self.ignored_reason, 
                               "expires": self.ignored_expires}

        return repr


@dataclass
class Safety:
    client: Any
    keys: Any


from safety.auth.models import Auth
from rich.console import Console

@dataclass
class SafetyCLI:
    auth: Optional[Auth] = None
    telemetry: Optional[TelemetryModel] = None
    metadata: Optional[MetadataModel] = None
    schema: Optional[ReportSchemaVersion] = None
    project = None
    config: Optional[ConfigModel] = None
    console: Optional[Console] = None
    system_scan_policy: Optional[PolicyFileModel] = None
    platform_enabled: bool = False
