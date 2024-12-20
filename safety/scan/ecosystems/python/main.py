from datetime import datetime
import itertools
import logging
from typing import List
from safety_schemas.models import FileType, PythonDependency, ClosestSecureVersion, \
    ConfigModel, PythonSpecification, RemediationModel, DependencyResultModel, \
        Vulnerability
from safety_schemas.models import VulnerabilitySeverityLabels, IgnoredItemDetail, \
    IgnoredItems, IgnoreCodes
from typer import FileTextWrite

from safety.models import Severity
from safety.util import build_remediation_info_url

from ....constants import IGNORE_UNPINNED_REQ_REASON

from ....safety import get_cve_from, get_from_cache, get_vulnerabilities


from ..python.dependencies import get_closest_ver, get_dependencies, \
    is_pinned_requirement
from ..base import InspectableFile, Remediable

from packaging.version import parse as parse_version
from packaging.utils import canonicalize_name
from packaging.specifiers import SpecifierSet


LOG = logging.getLogger(__name__)


def ignore_vuln_if_needed(
    dependency: PythonDependency, file_type: FileType,
    vuln_id: str, cve, ignore_vulns,
    ignore_unpinned: bool, ignore_environment: bool,
    specification: PythonSpecification,
    ignore_severity: List[VulnerabilitySeverityLabels] = []
) -> None:
    """
    Ignores vulnerabilities based on the provided rules.

    Args:
        dependency (PythonDependency): The Python dependency.
        file_type (FileType): The type of the file.
        vuln_id (str): The vulnerability ID.
        cve: The CVE object.
        ignore_vulns: The dictionary of ignored vulnerabilities.
        ignore_unpinned (bool): Whether to ignore unpinned specifications.
        ignore_environment (bool): Whether to ignore environment results.
        specification (PythonSpecification): The specification.
        ignore_severity (List[VulnerabilitySeverityLabels]): List of severity labels to ignore.
    """

    vuln_ignored: bool = vuln_id in ignore_vulns

    if vuln_ignored and ignore_vulns[vuln_id].code is IgnoreCodes.manual:
        if (not ignore_vulns[vuln_id].expires
                      or ignore_vulns[vuln_id].expires > datetime.utcnow().date()):
            return

        del ignore_vulns[vuln_id]

    if ignore_environment and file_type is FileType.VIRTUAL_ENVIRONMENT:
        reason = "Ignored environment by rule in policy file."
        ignore_vulns[vuln_id] = IgnoredItemDetail(
            code=IgnoreCodes.environment_dependency, reason=reason)
        return

    severity_label = VulnerabilitySeverityLabels.UNKNOWN

    if cve:
        if cve.cvssv3 and cve.cvssv3.get("base_severity", None):
            severity_label = VulnerabilitySeverityLabels(
                cve.cvssv3["base_severity"].lower())

    if severity_label in ignore_severity:
        reason = f"{severity_label.value.capitalize()} severity ignored by rule in policy file."
        ignore_vulns[vuln_id] = IgnoredItemDetail(
            code=IgnoreCodes.cvss_severity, reason=reason)
        return

    spec_ignored: bool = False

    vuln =  ignore_vulns.get(vuln_id)
    if vuln is not None and vuln.specifications is not None and str(specification.specifier) in vuln.specifications:
        spec_ignored = True

    if (not spec_ignored) and \
        (ignore_unpinned and not specification.is_pinned()):

        reason = IGNORE_UNPINNED_REQ_REASON
        specifications = set()
        specifications.add(str(specification.specifier))
        ignore_vulns[vuln_id] = IgnoredItemDetail(
            code=IgnoreCodes.unpinned_specification, reason=reason,
            specifications=specifications)


def should_fail(config: ConfigModel, vulnerability: Vulnerability) -> bool:
    """
    Determines if a vulnerability should cause a failure based on the configuration.

    Args:
        config (ConfigModel): The configuration model.
        vulnerability (Vulnerability): The vulnerability.

    Returns:
        bool: True if the vulnerability should cause a failure, False otherwise.
    """

    if not config.depedendency_vulnerability.fail_on.enabled:
        return False

    # If Severity is None type, it will be considered as UNKNOWN and NONE
    # They are not the same, but we are handling like the same when a
    # vulnerability does not have a severity value.
    severities = [VulnerabilitySeverityLabels.NONE,
                  VulnerabilitySeverityLabels.UNKNOWN]

    if vulnerability.severity and vulnerability.severity.cvssv3:
        base_severity = vulnerability.severity.cvssv3.get(
            "base_severity")

        if base_severity:
            base_severity = base_severity.lower()

        # A vulnerability only has a single severity value, this is just
        # to handle cases where the severity value is not in the expected
        # format and fallback to the default severity values [None, unknown].
        matched_severities = [
            label
            for label in VulnerabilitySeverityLabels
            if label.value == base_severity
        ]

        if matched_severities:
            severities = matched_severities
        else:
            LOG.warning(
                f"Unexpected base severity value {base_severity} for "
                f"{vulnerability.vulnerability_id}"
            )

    return any(
        severity in config.depedendency_vulnerability.fail_on.cvss_severity
        for severity in severities
    )


def get_vulnerability(
    vuln_id: str, cve, data, specifier,
    db, name, ignore_vulns: IgnoredItems,
    affected: PythonSpecification
) -> Vulnerability:
    """
    Creates a Vulnerability object from the given data.

    Args:
        vuln_id (str): The vulnerability ID.
        cve: The CVE object.
        data: The vulnerability data.
        specifier: The specifier set.
        db: The database.
        name: The package name.
        ignore_vulns (IgnoredItems): The ignored vulnerabilities.
        affected (PythonSpecification): The affected specification.

    Returns:
        Vulnerability: The created Vulnerability object.
    """
    base_domain = db.get('meta', {}).get('base_domain')
    unpinned_ignored = ignore_vulns[vuln_id].specifications \
        if vuln_id in ignore_vulns.keys() else None
    should_ignore = not unpinned_ignored or str(affected.specifier) in unpinned_ignored
    ignored: bool = bool(ignore_vulns and
                     vuln_id in ignore_vulns and
                     should_ignore)
    more_info_url = f"{base_domain}{data.get('more_info_path', '')}"
    severity = None

    if cve and (cve.cvssv2 or cve.cvssv3):
        severity = Severity(source=cve.name, cvssv2=cve.cvssv2, cvssv3=cve.cvssv3)

    analyzed_requirement = affected
    analyzed_version = next(iter(analyzed_requirement.specifier)).version if affected.is_pinned() else None

    vulnerable_spec = set()
    vulnerable_spec.add(specifier)

    reason = None
    expires = None
    ignore_code = None

    if ignored:
        reason = ignore_vulns[vuln_id].reason
        expires = str(ignore_vulns[vuln_id].expires) if ignore_vulns[vuln_id].expires else None
        ignore_code = ignore_vulns[vuln_id].code.value

    return Vulnerability(
        vulnerability_id=vuln_id,
        package_name=name,
        ignored=ignored,
        ignored_reason=reason,
        ignored_expires=expires,
        ignored_code=ignore_code,
        vulnerable_spec=vulnerable_spec,
        all_vulnerable_specs=data.get("specs", []),
        analyzed_version=analyzed_version,
        analyzed_requirement=str(analyzed_requirement),
        advisory=data.get("advisory"),
        is_transitive=data.get("transitive", False),
        published_date=data.get("published_date"),
        fixed_versions=[ver for ver in data.get("fixed_versions", []) if ver],
        closest_versions_without_known_vulnerabilities=data.get("closest_secure_versions", []),
        resources=data.get("vulnerability_resources"),
        CVE=cve,
        severity=severity,
        affected_versions=data.get("affected_versions", []),
        more_info_url=more_info_url
    )

class PythonFile(InspectableFile, Remediable):
    """
    A class representing a Python file that can be inspected for vulnerabilities and remediated.
    """

    def __init__(self, file_type: FileType, file: FileTextWrite) -> None:
        """
        Initializes the PythonFile instance.

        Args:
            file_type (FileType): The type of the file.
            file (FileTextWrite): The file object.
        """
        super().__init__(file=file)
        self.ecosystem = file_type.ecosystem
        self.file_type = file_type

    def __find_dependency_vulnerabilities__(self, dependencies: List[PythonDependency],
                                            config: ConfigModel) -> None:
        """
        Finds vulnerabilities in the dependencies.

        Args:
            dependencies (List[PythonDependency]): The list of dependencies.
            config (ConfigModel): The configuration model.
        """
        ignored_vulns_data = {}
        ignore_vulns = {} \
            if not config.depedendency_vulnerability.ignore_vulnerabilities \
                else config.depedendency_vulnerability.ignore_vulnerabilities

        ignore_severity = config.depedendency_vulnerability.ignore_cvss_severity
        ignore_unpinned = config.depedendency_vulnerability.python_ignore.unpinned_specifications
        ignore_environment = config.depedendency_vulnerability.python_ignore.environment_results

        db = get_from_cache(db_name="insecure.json", skip_time_verification=True)
        if not db:
            LOG.debug("Cache data for insecure.json is not available or is invalid.")
            return
        db_full = None
        vulnerable_packages = frozenset(db.get('vulnerable_packages', []))
        found_dependencies = {}
        specifications = iter([])

        for dependency in dependencies:
            specifications = itertools.chain(dependency.specifications, specifications)
            found_dependencies[
                canonicalize_name(dependency.name)
                ] = dependency

        # Let's report by req, pinned in environment will be ==version
        for spec in specifications:
            vuln_per_req = {}
            name = canonicalize_name(spec.name)
            dependency: PythonDependency = found_dependencies.get(name, None)
            if not dependency:
                continue

            if not dependency.version:
                if not db_full:
                    db_full = get_from_cache(db_name="insecure_full.json",
                                             skip_time_verification=True)
                    if not db_full:
                        LOG.debug("Cache data for insecure_full.json is not available or is invalid.")
                        return
                dependency.refresh_from(db_full)

            if name in vulnerable_packages:
                # we have a candidate here, build the spec set
                for specifier in db['vulnerable_packages'][name]:
                    spec_set = SpecifierSet(specifiers=specifier)

                    if spec.is_vulnerable(spec_set, dependency.insecure_versions):
                        if not db_full:
                            db_full = get_from_cache(db_name="insecure_full.json",
                                             skip_time_verification=True)
                            if not db_full:
                                LOG.debug("Cache data for insecure_full.json is not available or is invalid.")
                                return
                        if not dependency.latest_version:
                            dependency.refresh_from(db_full)

                        for data in get_vulnerabilities(pkg=name, spec=specifier, db=db_full):
                            try:
                                vuln_id: str = str(next(filter(lambda i: i.get('type', None) == 'pyup', data.get('ids', []))).get('id', ''))
                            except StopIteration:
                                vuln_id: str = ''

                            if vuln_id in vuln_per_req:
                                vuln_per_req[vuln_id].vulnerable_spec.add(specifier)
                                continue

                            cve = get_cve_from(data, db_full)

                            ignore_vuln_if_needed(dependency=dependency,
                                                  file_type=self.file_type,
                                                  vuln_id=vuln_id, cve=cve,
                                                  ignore_vulns=ignore_vulns,
                                                  ignore_severity=ignore_severity,
                                                  ignore_unpinned=ignore_unpinned,
                                                  ignore_environment=ignore_environment,
                                                  specification=spec)

                            include_ignored = True
                            vulnerability = get_vulnerability(vuln_id, cve, data,
                                                                   specifier, db_full,
                                                                   name, ignore_vulns, spec)

                            should_add_vuln = not (vulnerability.is_transitive and
                                                   dependency.found and
                                                   dependency.found.parts[-1] == FileType.VIRTUAL_ENVIRONMENT.value)

                            if vulnerability.ignored:
                                ignored_vulns_data[
                                    vulnerability.vulnerability_id] = vulnerability

                            if not self.dependency_results.failed and not vulnerability.ignored:
                                self.dependency_results.failed = should_fail(config, vulnerability)


                            if (include_ignored or vulnerability.vulnerability_id not in ignore_vulns) and should_add_vuln:
                                vuln_per_req[vulnerability.vulnerability_id] = vulnerability
                                spec.vulnerabilities.append(vulnerability)

            # TODO: dep_result Save if it should fail the JOB

        self.dependency_results.dependencies = [dep for _, dep in found_dependencies.items()]
        self.dependency_results.ignored_vulns = ignore_vulns
        self.dependency_results.ignored_vulns_data = ignored_vulns_data

    def inspect(self, config: ConfigModel) -> None:
        """
        Inspects the file for vulnerabilities based on the given configuration.

        Args:
            config (ConfigModel): The configuration model.
        """

        # We only support vulnerability checking for now
        dependencies = get_dependencies(self)

        if not dependencies:
            self.results = []

        self.__find_dependency_vulnerabilities__(dependencies=dependencies,
                                                 config=config)

    def __get_secure_specifications_for_user__(self, dependency: PythonDependency, db_full,
                                               secure_vulns_by_user=None) -> List[str]:
        """
        Gets secure specifications for the user.

        Args:
            dependency (PythonDependency): The Python dependency.
            db_full: The full database.
            secure_vulns_by_user: The set of secure vulnerabilities by user.

        Returns:
            List[str]: The list of secure specifications.
        """
        if not db_full:
            return

        if not secure_vulns_by_user:
            secure_vulns_by_user = set()

        versions = dependency.get_versions(db_full)
        affected_versions = []

        for vuln in db_full.get('vulnerable_packages', {}).get(dependency.name, []):
            vuln_id: str = str(next(filter(lambda i: i.get('type', None) == 'pyup', vuln.get('ids', []))).get('id', ''))
            if vuln_id and vuln_id not in secure_vulns_by_user:
                affected_versions += vuln.get('affected_versions', [])

        affected_v = set(affected_versions)
        sec_ver_for_user = list(versions.difference(affected_v))

        return sorted(sec_ver_for_user, key=lambda ver: parse_version(ver), reverse=True)

    def remediate(self) -> None:
        """
        Remediates the vulnerabilities in the file.
        """
        db_full = get_from_cache(db_name="insecure_full.json",
                                 skip_time_verification=True)
        if not db_full:
            return

        for dependency in self.dependency_results.get_affected_dependencies():
            secure_versions = dependency.secure_versions

            if not secure_versions:
                secure_versions = []

            secure_vulns_by_user = set(self.dependency_results.ignored_vulns.keys())
            if not secure_vulns_by_user:
                secure_v = sorted(secure_versions, key=lambda ver: parse_version(ver),
                                  reverse=True)
            else:
                secure_v = self.__get_secure_specifications_for_user__(
                    dependency=dependency, db_full=db_full,
                    secure_vulns_by_user=secure_vulns_by_user)

            for specification in dependency.specifications:
                if len(specification.vulnerabilities) <= 0:
                    continue

                version = None
                if is_pinned_requirement(specification.specifier):
                    version = next(iter(specification.specifier)).version
                closest_secure = {key: str(value) if value else None for key, value in
                                  get_closest_ver(secure_v,
                                                  version,
                                                  specification.specifier).items()}
                closest_secure = ClosestSecureVersion(**closest_secure)
                recommended = None

                if closest_secure.upper:
                    recommended = closest_secure.upper
                elif closest_secure.lower:
                    recommended = closest_secure.lower

                other_recommended = [other_v for other_v in secure_v if other_v != str(recommended)]

                remed_more_info_url = dependency.more_info_url

                if remed_more_info_url:
                    remed_more_info_url = build_remediation_info_url(
                        base_url=remed_more_info_url, version=version,
                        spec=str(specification.specifier),
                        target_version=recommended)

                if not remed_more_info_url:
                    remed_more_info_url = "-"

                vulns_found = sum(1 for vuln in specification.vulnerabilities if not vuln.ignored)

                specification.remediation = RemediationModel(vulnerabilities_found=vulns_found,
                                                   more_info_url=remed_more_info_url,
                                                   closest_secure=closest_secure if recommended else None,
                                                   recommended=recommended,
                                                   other_recommended=other_recommended)
