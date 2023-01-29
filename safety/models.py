from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional
from packaging.specifiers import SpecifierSet
from packaging.version import parse as parse_version


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
                                'vulnerable_spec', 'all_vulnerable_specs', 'analyzed_version', 'analyzed_spec',
                                'advisory', 'is_transitive', 'published_date', 'fixed_versions',
                                'closest_versions_without_known_vulnerabilities', 'resources', 'CVE', 'severity',
                                'affected_versions', 'more_info_url'])
RequirementFile = namedtuple('RequirementFile', ['path'])


@dataclass
class Package(DictConverter):
    name: str
    version: Optional[str]
    spec: SpecifierSet
    found: Optional[str] = None
    insecure_versions: List[str] = field(default_factory=lambda: [])
    secure_versions: List[str] = field(default_factory=lambda: [])
    latest_version_without_known_vulnerabilities: Optional[str] = None
    latest_version: Optional[str] = None
    more_info_url: Optional[str] = None

    def get_versions(self, db_full):
        pkg_meta = db_full.get('$meta', {}).get('packages', {}).get(self.name, {})
        return set(pkg_meta.get("insecure_versions", []) + pkg_meta.get("secure_versions", []))

    def refresh_from(self, db_full):
        base_domain = db_full.get('$meta', {}).get('base_domain')
        pkg_meta = db_full.get('$meta', {}).get('packages', {}).get(self.name, {})

        kwargs = {'insecure_versions': pkg_meta.get("insecure_versions", []),
                  'secure_versions': pkg_meta.get("secure_versions", []),
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
                'spec': str(self.spec),
            }

        return {'name': self.name,
                'version': self.version,
                'spec': str(self.spec),
                'found': self.found,
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

            if isinstance(value, CVE):
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
