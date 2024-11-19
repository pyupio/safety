import itertools
import json
import logging
import os
import sys
import time
from abc import ABC, abstractmethod
from collections import defaultdict, namedtuple
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Union

from dparse import parse
from filelock import FileLock
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version
from requests import PreparedRequest
from safety_schemas.models import (
    ClosestSecureVersion,
    ConfigModel,
    DependencyResultModel,
    Ecosystem,
    FileType,
    IgnoreCodes,
    IgnoredItemDetail,
    IgnoredItems,
    PythonDependency,
    PythonSpecification,
    RemediationModel,
    Vulnerability,
    VulnerabilitySeverityLabels,
)
from typer import FileTextWrite

NOT_IMPLEMENTED = "Not implemented function"
DIR_NAME = ".safety"
JSON_SCHEMA_VERSION = "2.0.0"
IGNORE_UNPINNED_REQ_REASON = (
    "This vulnerability is being ignored due to the 'ignore-unpinned-requirements' flag (default True). "
    "To change this, set 'ignore-unpinned-requirements' to False under 'security' in your policy file. "
    "See https://docs.pyup.io/docs/safety-20-policy-file for more information."
)


def get_user_dir() -> Path:
    """
    Get the user directory for the safety configuration.

    Returns:
        Path: The user directory path.
    """
    path = Path("~", DIR_NAME).expanduser()
    return path


USER_CONFIG_DIR = get_user_dir()
CACHE_FILE_DIR = USER_CONFIG_DIR / f"{JSON_SCHEMA_VERSION.replace('.', '')}"
DB_CACHE_FILE = CACHE_FILE_DIR / "cache.json"
LOG = logging.getLogger(__name__)


class Inspectable(ABC):
    """
    Abstract base class defining the interface for objects that can be inspected for dependencies.
    """

    @abstractmethod
    def inspect(self, config: ConfigModel) -> DependencyResultModel:
        """
        Inspects the object and returns the result of the dependency analysis.

        Args:
            config (ConfigModel): The configuration model for inspection.

        Returns:
            DependencyResultModel: The result of the dependency inspection.
        """
        return NotImplementedError(NOT_IMPLEMENTED)  # type:ignore


class Remediable(ABC):
    """
    Abstract base class defining the interface for objects that can be remediated.
    """

    @abstractmethod
    def remediate(self):
        """
        Remediates the object to address any detected issues.
        """
        return NotImplementedError(NOT_IMPLEMENTED)


class InspectableFile(Inspectable):
    """
    Represents an inspectable file within a specific ecosystem and file type.
    """

    def __init__(self, file: FileTextWrite):
        """
        Initializes an InspectableFile instance.

        Args:
            file (FileTextWrite): The file to be inspected.
        """
        self.file = file
        self.ecosystem: Ecosystem
        self.file_type: FileType
        self.dependency_results: DependencyResultModel = DependencyResultModel(
            dependencies=[]
        )


def get_from_cache(
    db_name: str, cache_valid_seconds: int = 0, skip_time_verification: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Retrieves the database from the cache if it is valid.

    Args:
        db_name (str): The name of the database.
        cache_valid_seconds (int): The validity period of the cache in seconds.
        skip_time_verification (bool): Whether to skip time verification.

    Returns:
        Optional[[Dict[str, Any]]: The cached database if available and valid, otherwise False.
    """

    cache_file_lock = f"{DB_CACHE_FILE}.lock"
    os.makedirs(os.path.dirname(cache_file_lock), exist_ok=True)
    lock = FileLock(cache_file_lock, timeout=10)
    with lock:
        if os.path.exists(DB_CACHE_FILE):
            with open(DB_CACHE_FILE) as f:
                try:
                    data = json.loads(f.read())
                    if db_name in data:
                        if "cached_at" in data[db_name]:
                            if (
                                data[db_name]["cached_at"] + cache_valid_seconds
                                > time.time()
                                or skip_time_verification
                            ):
                                LOG.debug(
                                    "Getting the database from cache at %s, cache setting: %s",
                                    data[db_name]["cached_at"],
                                    cache_valid_seconds,
                                )

                                try:
                                    data[db_name]["db"]["meta"][
                                        "base_domain"
                                    ] = "https://data.safetycli.com"
                                except KeyError as e:
                                    pass

                                return data[db_name]["db"]

                            LOG.debug(
                                "Cached file is too old, it was cached at %s",
                                data[db_name]["cached_at"],
                            )
                        else:
                            LOG.debug(
                                "There is not the cached_at key in %s database",
                                data[db_name],
                            )

                except json.JSONDecodeError:
                    LOG.debug("JSONDecodeError trying to get the cached database.")
        else:
            LOG.debug("Cache file doesn't exist...")
    return None


def get_vulnerabilities(
    pkg: str, spec: str, db: Dict[str, Any]
) -> Iterator[Dict[str, Any]]:
    """
    Retrieves vulnerabilities for a package from the database.

    Args:
        pkg (str): The package name.
        spec (str): The specifier set.
        db (Dict[str, Any]): The database.

    Returns:
        Iterator[Dict[str, Any]]: An iterator of vulnerabilities.
    """
    for entry in db["vulnerable_packages"][pkg]:
        for entry_spec in entry["specs"]:
            if entry_spec == spec:
                yield entry


cve_nmt = namedtuple("Cve", ["name", "cvssv2", "cvssv3"])
severity_nmt = namedtuple("Severity", ["source", "cvssv2", "cvssv3"])


class DictConverter(object):
    """
    A class to convert objects to dictionaries.
    """

    def to_dict(self, **kwargs: Any) -> Dict:  # type:ignore
        pass


class CVE(cve_nmt, DictConverter):
    """
    A class representing a CVE.
    """

    def to_dict(self) -> Dict:
        """
        Convert the CVE to a dictionary.

        Returns:
            Dict: The dictionary representation of the CVE.
        """
        return {"name": self.name, "cvssv2": self.cvssv2, "cvssv3": self.cvssv3}


def get_cve_from(data: Dict[str, Any], db_full: Dict[str, Any]) -> Optional[CVE]:
    """
    Retrieves the CVE object from the provided data.

    Args:
        data (Dict[str, Any]): The vulnerability data.
        db_full (Dict[str, Any]): The full database.

    Returns:
        Optional[CVE]: The CVE object if found, otherwise None.
    """
    try:
        xve_id: str = str(
            next(
                filter(
                    lambda i: i.get("type", None) in ["cve", "pve"], data.get("ids", [])
                )
            ).get("id", "")
        )
    except StopIteration:
        xve_id: str = ""

    if not xve_id:
        return None

    cve_meta = db_full.get("meta", {}).get("severities", {}).get(xve_id, {})
    return CVE(
        name=xve_id,
        cvssv2=cve_meta.get("cvssv2", None),
        cvssv3=cve_meta.get("cvssv3", None),
    )


def ignore_vuln_if_needed(
    dependency: PythonDependency,
    file_type: FileType,
    vuln_id: str,
    cve,
    ignore_vulns,
    ignore_unpinned: bool,
    ignore_environment: bool,
    specification: PythonSpecification,
    ignore_severity: List[VulnerabilitySeverityLabels] = [],
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
        if (
            not ignore_vulns[vuln_id].expires
            or ignore_vulns[vuln_id].expires > datetime.utcnow().date()
        ):
            return

        del ignore_vulns[vuln_id]

    if ignore_environment and file_type is FileType.VIRTUAL_ENVIRONMENT:
        reason = "Ignored environment by rule in policy file."
        ignore_vulns[vuln_id] = IgnoredItemDetail(
            code=IgnoreCodes.environment_dependency, reason=reason
        )
        return

    severity_label = VulnerabilitySeverityLabels.UNKNOWN

    if cve:
        if cve.cvssv3 and cve.cvssv3.get("base_severity", None):
            severity_label = VulnerabilitySeverityLabels(
                cve.cvssv3["base_severity"].lower()
            )

    if severity_label in ignore_severity:
        reason = f"{severity_label.value.capitalize()} severity ignored by rule in policy file."
        ignore_vulns[vuln_id] = IgnoredItemDetail(
            code=IgnoreCodes.cvss_severity, reason=reason
        )
        return

    spec_ignored: bool = False

    if (
        vuln_id in ignore_vulns.keys()
        and str(specification.specifier) in ignore_vulns[vuln_id].specifications
    ):
        spec_ignored = True

    if (not spec_ignored) and (ignore_unpinned and not specification.is_pinned()):
        reason = IGNORE_UNPINNED_REQ_REASON
        specifications = set()
        specifications.add(str(specification.specifier))
        ignore_vulns[vuln_id] = IgnoredItemDetail(
            code=IgnoreCodes.unpinned_specification,
            reason=reason,
            specifications=specifications,
        )


class Severity(severity_nmt, DictConverter):
    """
    A class representing the severity of a vulnerability.
    """

    def to_dict(self) -> Dict:
        """
        Convert the severity to a dictionary.

        Returns:
            Dict: The dictionary representation of the severity.
        """
        result = {"severity": {"source": self.source}}

        result["severity"]["cvssv2"] = self.cvssv2
        result["severity"]["cvssv3"] = self.cvssv3

        return result


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
    severities = [VulnerabilitySeverityLabels.NONE, VulnerabilitySeverityLabels.UNKNOWN]

    if vulnerability.severity and vulnerability.severity.cvssv3:
        base_severity = vulnerability.severity.cvssv3.get("base_severity")

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
    vuln_id: str,
    cve,
    data,
    specifier,
    db,
    name,
    ignore_vulns: IgnoredItems,
    affected: PythonSpecification,
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
    base_domain = db.get("meta", {}).get("base_domain")
    unpinned_ignored = (
        ignore_vulns[vuln_id].specifications if vuln_id in ignore_vulns.keys() else None
    )
    should_ignore = not unpinned_ignored or str(affected.specifier) in unpinned_ignored
    ignored: bool = bool(ignore_vulns and vuln_id in ignore_vulns and should_ignore)
    more_info_url = f"{base_domain}{data.get('more_info_path', '')}"
    severity = None

    if cve and (cve.cvssv2 or cve.cvssv3):
        severity = Severity(source=cve.name, cvssv2=cve.cvssv2, cvssv3=cve.cvssv3)

    analyzed_requirement = affected
    analyzed_version = (
        next(iter(analyzed_requirement.specifier)).version
        if affected.is_pinned()
        else None
    )

    vulnerable_spec = set()
    vulnerable_spec.add(specifier)

    reason = None
    expires = None
    ignore_code = None

    if ignored:
        reason = ignore_vulns[vuln_id].reason
        expires = (
            str(ignore_vulns[vuln_id].expires)
            if ignore_vulns[vuln_id].expires
            else None
        )
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
        closest_versions_without_known_vulnerabilities=data.get(
            "closest_secure_versions", []
        ),
        resources=data.get("vulnerability_resources"),
        CVE=cve,
        severity=severity,
        affected_versions=data.get("affected_versions", []),
        more_info_url=more_info_url,
    )


def build_remediation_info_url(
    base_url: str, version: Optional[str], spec: str, target_version: Optional[str] = ""
) -> Optional[str]:
    """
    Build the remediation info URL.

    Args:
        base_url (str): The base URL.
        version (Optional[str]): The current version.
        spec (str): The specification.
        target_version (Optional[str]): The target version.

    Returns:
        str: The remediation info URL.
    """

    params = {"from": version, "to": target_version}

    # No pinned version
    if not version:
        params = {"spec": spec}

    req = PreparedRequest()
    req.prepare_url(base_url, params)

    return req.url


def parse_requirement(dep: str, found: Optional[str]) -> PythonSpecification:
    """
    Parses a requirement and creates a PythonSpecification object.

    Args:
        dep (str): The dependency string.
        found (Optional[str]): The found path.

    Returns:
        PythonSpecification: The parsed requirement.
    """
    req = PythonSpecification(dep)
    req.found = Path(found).resolve() if found else None

    if req.specifier == SpecifierSet(""):
        req.specifier = SpecifierSet(">=0")

    return req


def is_pinned_requirement(spec: SpecifierSet) -> bool:
    """
    Checks if a requirement is pinned.

    Args:
        spec (SpecifierSet): The version specifier set.

    Returns:
        bool: True if the requirement is pinned, False otherwise.
    """
    if not spec or len(spec) != 1:
        return False

    specifier = next(iter(spec))

    return (
        specifier.operator == "==" and "*" != specifier.version[-1]
    ) or specifier.operator == "==="


def find_version(requirements: List[PythonSpecification]) -> Optional[str]:
    """
    Finds the version of a requirement.

    Args:
        requirements (List[PythonSpecification]): The list of requirements.

    Returns:
        Optional[str]: The version if found, otherwise None.
    """
    ver = None

    if len(requirements) != 1:
        return ver

    specs = requirements[0].specifier

    if is_pinned_requirement(specs):
        ver = next(iter(requirements[0].specifier)).version

    return ver


def read_dependencies(
    fh, resolve: bool = True
) -> Generator[PythonDependency, None, None]:
    """
    Reads dependencies from a file-like object.

    Args:
        fh: The file-like object to read from.
        resolve (bool): Whether to resolve referenced files.

    Returns:
        Generator[PythonDependency, None, None]: A generator of PythonDependency objects.
    """
    path = fh.name
    absolute_path = Path(path).resolve()
    found = absolute_path

    content = fh.read()
    dependency_file = parse(content, path=path, resolve=resolve)

    reqs_pkg = defaultdict(list)

    for req in dependency_file.resolved_dependencies:
        reqs_pkg[canonicalize_name(req.name)].append(req)

    for pkg, reqs in reqs_pkg.items():
        specifications = list(
            map(lambda req: parse_requirement(req, str(absolute_path)), reqs)
        )
        version = find_version(specifications)

        yield PythonDependency(
            name=pkg,
            version=version,
            specifications=specifications,
            found=found,
            absolute_path=absolute_path,
            insecure_versions=[],
            secure_versions=[],
            latest_version=None,
            latest_version_without_known_vulnerabilities=None,
            more_info_url=None,
        )


def read_virtual_environment_dependencies(
    f: InspectableFile,
) -> Generator[PythonDependency, None, None]:
    """
    Reads dependencies from a virtual environment.

    Args:
        f (InspectableFile): The inspectable file representing the virtual environment.

    Returns:
        Generator[PythonDependency, None, None]: A generator of PythonDependency objects.
    """

    env_path = Path(f.file.name).resolve().parent

    if sys.platform.startswith("win"):
        site_pkgs_path = env_path / Path("Lib/site-packages/")
    else:
        site_pkgs_path = Path("lib/")
        try:
            site_pkgs_path = next((env_path / site_pkgs_path).glob("*/site-packages/"))
        except StopIteration:
            # Unable to find packages for foo env
            return

    if not site_pkgs_path.resolve().exists():
        # Unable to find packages for foo env
        return

    dep_paths = site_pkgs_path.glob("*/METADATA")

    for path in dep_paths:
        if not path.is_file():
            continue

        dist_info_folder = path.parent
        dep_name, dep_version = dist_info_folder.name.replace(".dist-info", "").split(
            "-"
        )

        yield PythonDependency(
            name=dep_name,
            version=dep_version,
            specifications=[
                PythonSpecification(f"{dep_name}=={dep_version}", found=site_pkgs_path)
            ],
            found=site_pkgs_path,
            insecure_versions=[],
            secure_versions=[],
            latest_version=None,
            latest_version_without_known_vulnerabilities=None,
            more_info_url=None,
        )


def get_dependencies(f: InspectableFile) -> List[PythonDependency]:
    """
    Gets the dependencies for the given inspectable file.

    Args:
        f (InspectableFile): The inspectable file.

    Returns:
        List[PythonDependency]: A list of PythonDependency objects.
    """
    if not f.file_type:
        return []

    if f.file_type in [
        FileType.REQUIREMENTS_TXT,
        FileType.POETRY_LOCK,
        FileType.PIPENV_LOCK,
        FileType.PYPROJECT_TOML,
    ]:
        return list(read_dependencies(f.file, resolve=True))

    if f.file_type == FileType.VIRTUAL_ENVIRONMENT:
        return list(read_virtual_environment_dependencies(f))

    return []


def get_closest_ver(
    versions: List[str], version: Optional[str], spec: SpecifierSet
) -> dict:
    """
    Gets the closest version to the specified version within a list of versions.

    Args:
        versions (List[str]): The list of versions.
        version (Optional[str]): The target version.
        spec (SpecifierSet): The version specifier set.

    Returns:
        dict: A dictionary containing the upper and lower closest versions.
    """
    results = {"upper": None, "lower": None}

    if (not version and not spec) or not versions:
        return results

    sorted_versions = sorted(versions, key=lambda ver: parse_version(ver), reverse=True)

    if not version:
        sorted_versions = spec.filter(sorted_versions, prereleases=False)

        upper = None
        lower = None

        try:
            sorted_versions = list(sorted_versions)
            upper = sorted_versions[0]
            lower = sorted_versions[-1]
            results["upper"] = upper
            results["lower"] = lower if upper != lower else None
        except IndexError:
            pass

        return results

    current_v = parse_version(version)

    for v in sorted_versions:
        index = parse_version(v)

        if index > current_v:
            results["upper"] = index

        if index < current_v:
            results["lower"] = index
            break

    return results


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

    def __find_dependency_vulnerabilities__(
        self, dependencies: List[PythonDependency], config: ConfigModel
    ) -> None:
        """
        Finds vulnerabilities in the dependencies.

        Args:
            dependencies (List[PythonDependency]): The list of dependencies.
            config (ConfigModel): The configuration model.
        """
        ignored_vulns_data = {}
        ignore_vulns = (
            {}
            if not config.depedendency_vulnerability.ignore_vulnerabilities
            else config.depedendency_vulnerability.ignore_vulnerabilities
        )

        ignore_severity = config.depedendency_vulnerability.ignore_cvss_severity
        ignore_unpinned = (
            config.depedendency_vulnerability.python_ignore.unpinned_specifications
        )
        ignore_environment = (
            config.depedendency_vulnerability.python_ignore.environment_results
        )

        db = get_from_cache(db_name="insecure.json", skip_time_verification=True)
        if not db:
            LOG.debug("Cache data for insecure.json is not available or is invalid.")
            return
        db_full = None
        vulnerable_packages = frozenset(db.get("vulnerable_packages", []))
        found_dependencies = {}
        specifications = iter([])

        for dependency in dependencies:
            specifications = itertools.chain(dependency.specifications, specifications)
            found_dependencies[canonicalize_name(dependency.name)] = dependency

        # Let's report by req, pinned in environment will be ==version
        for spec in specifications:
            vuln_per_req = {}
            name = canonicalize_name(spec.name)
            dependency: PythonDependency = found_dependencies.get(name, None)
            if not dependency:
                continue

            if not dependency.version:
                if not db_full:
                    db_full = get_from_cache(
                        db_name="insecure_full.json", skip_time_verification=True
                    )
                    if not db_full:
                        LOG.debug(
                            "Cache data for insecure_full.json is not available or is invalid."
                        )
                        return
                dependency.refresh_from(db_full)

            if name in vulnerable_packages:
                # we have a candidate here, build the spec set
                for specifier in db["vulnerable_packages"][name]:
                    spec_set = SpecifierSet(specifiers=specifier)

                    if spec.is_vulnerable(spec_set, dependency.insecure_versions):
                        if not db_full:
                            db_full = get_from_cache(
                                db_name="insecure_full.json",
                                skip_time_verification=True,
                            )
                            if not db_full:
                                LOG.debug(
                                    "Cache data for insecure_full.json is not available or is invalid."
                                )
                                return
                        if not dependency.latest_version:
                            dependency.refresh_from(db_full)

                        for data in get_vulnerabilities(
                            pkg=name, spec=specifier, db=db_full
                        ):
                            try:
                                vuln_id: str = str(
                                    next(
                                        filter(
                                            lambda i: i.get("type", None) == "pyup",
                                            data.get("ids", []),
                                        )
                                    ).get("id", "")
                                )
                            except StopIteration:
                                vuln_id: str = ""

                            if vuln_id in vuln_per_req:
                                vuln_per_req[vuln_id].vulnerable_spec.add(specifier)
                                continue

                            cve = get_cve_from(data, db_full)

                            ignore_vuln_if_needed(
                                dependency=dependency,
                                file_type=self.file_type,
                                vuln_id=vuln_id,
                                cve=cve,
                                ignore_vulns=ignore_vulns,
                                ignore_severity=ignore_severity,
                                ignore_unpinned=ignore_unpinned,
                                ignore_environment=ignore_environment,
                                specification=spec,
                            )

                            include_ignored = True
                            vulnerability = get_vulnerability(
                                vuln_id,
                                cve,
                                data,
                                specifier,
                                db_full,
                                name,
                                ignore_vulns,
                                spec,
                            )  # type:ignore

                            should_add_vuln = not (
                                vulnerability.is_transitive
                                and dependency.found
                                and dependency.found.parts[-1]
                                == FileType.VIRTUAL_ENVIRONMENT.value
                            )

                            if vulnerability.ignored:
                                ignored_vulns_data[
                                    vulnerability.vulnerability_id
                                ] = vulnerability

                            if (
                                not self.dependency_results.failed
                                and not vulnerability.ignored
                            ):
                                self.dependency_results.failed = should_fail(
                                    config, vulnerability
                                )

                            if (
                                include_ignored
                                or vulnerability.vulnerability_id not in ignore_vulns
                            ) and should_add_vuln:
                                vuln_per_req[
                                    vulnerability.vulnerability_id
                                ] = vulnerability
                                spec.vulnerabilities.append(vulnerability)

            # TODO: dep_result Save if it should fail the JOB

        self.dependency_results.dependencies = [
            dep for _, dep in found_dependencies.items()
        ]
        self.dependency_results.ignored_vulns = ignore_vulns  # type:ignore
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

        self.__find_dependency_vulnerabilities__(
            dependencies=dependencies, config=config
        )

    def __get_secure_specifications_for_user__(
        self, dependency: PythonDependency, db_full, secure_vulns_by_user=None
    ) -> Optional[List[str]]:
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

        for vuln in db_full.get("vulnerable_packages", {}).get(dependency.name, []):
            vuln_id: str = str(
                next(
                    filter(lambda i: i.get("type", None) == "pyup", vuln.get("ids", []))
                ).get("id", "")
            )
            if vuln_id and vuln_id not in secure_vulns_by_user:
                affected_versions += vuln.get("affected_versions", [])

        affected_v = set(affected_versions)
        sec_ver_for_user = list(versions.difference(affected_v))

        return sorted(
            sec_ver_for_user, key=lambda ver: parse_version(ver), reverse=True
        )

    def remediate(self) -> None:
        """
        Remediates the vulnerabilities in the file.
        """
        db_full = get_from_cache(
            db_name="insecure_full.json", skip_time_verification=True
        )
        if not db_full:
            return

        for dependency in self.dependency_results.get_affected_dependencies():
            secure_versions = dependency.secure_versions

            if not secure_versions:
                secure_versions = []

            secure_vulns_by_user = set(self.dependency_results.ignored_vulns.keys())
            if not secure_vulns_by_user:
                secure_v = sorted(
                    secure_versions, key=lambda ver: parse_version(ver), reverse=True
                )
            else:
                secure_v = self.__get_secure_specifications_for_user__(
                    dependency=dependency,
                    db_full=db_full,
                    secure_vulns_by_user=secure_vulns_by_user,
                )

            for specification in dependency.specifications:
                if len(specification.vulnerabilities) <= 0:
                    continue

                version = None
                if is_pinned_requirement(specification.specifier):
                    version = next(iter(specification.specifier)).version
                closest_secure = {
                    key: str(value) if value else None
                    for key, value in get_closest_ver(
                        secure_v, version, specification.specifier
                    ).items()
                }
                closest_secure = ClosestSecureVersion(**closest_secure)
                recommended = None

                if closest_secure.upper:
                    recommended = closest_secure.upper
                elif closest_secure.lower:
                    recommended = closest_secure.lower

                other_recommended = [
                    other_v for other_v in secure_v if other_v != str(recommended)
                ]

                remed_more_info_url = dependency.more_info_url

                if remed_more_info_url:
                    remed_more_info_url = build_remediation_info_url(
                        base_url=remed_more_info_url,
                        version=version,
                        spec=str(specification.specifier),
                        target_version=recommended,
                    )

                if not remed_more_info_url:
                    remed_more_info_url = "-"

                vulns_found = sum(
                    1 for vuln in specification.vulnerabilities if not vuln.ignored
                )

                specification.remediation = RemediationModel(
                    vulnerabilities_found=vulns_found,
                    more_info_url=remed_more_info_url,
                    closest_secure=closest_secure if recommended else None,
                    recommended=recommended,
                    other_recommended=other_recommended,
                )


class InspectableFileContext:
    """
    Context manager for handling the lifecycle of an inspectable file.

    This class ensures that the file is properly opened and closed, handling any
    exceptions that may occur during the process.
    """

    def __init__(self, file_path: Path, file_type: FileType) -> None:
        """
        Initializes the InspectableFileContext.

        Args:
            file_path (Path): The path to the file.
            file_type (FileType): The type of the file.
        """
        self.file_path = file_path
        self.inspectable_file = None
        self.file_type = file_type

    def __enter__(self):  # TODO: Handle permission issue /Applications/...
        """
        Enters the runtime context related to this object.

        Opens the file and creates the appropriate inspectable file object based on the file type.

        Returns:
            The inspectable file object.
        """
        try:
            file: FileTextWrite = open(self.file_path, mode="r+")  # type: ignore
            self.inspectable_file = TargetFile.create(
                file_type=self.file_type, file=file
            )
        except Exception as e:
            # TODO: Report this
            pass

        return self.inspectable_file

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exits the runtime context related to this object.

        Ensures that the file is properly closed.
        """
        if self.inspectable_file:
            self.inspectable_file.file.close()


class TargetFile:
    """
    Factory class for creating inspectable file objects based on the file type and ecosystem.
    """

    @classmethod
    def create(cls, file_type: FileType, file: FileTextWrite):
        """
        Creates an inspectable file object based on the file type and ecosystem.

        Args:
            file_type (FileType): The type of the file.
            file (FileTextWrite): The file object.

        Returns:
            An instance of the appropriate inspectable file class.

        Raises:
            ValueError: If the ecosystem or file type is unsupported.
        """
        if file_type.ecosystem == Ecosystem.PYTHON:
            return PythonFile(file=file, file_type=file_type)

        raise ValueError(
            "Unsupported ecosystem or file type: "
            f"{file_type.ecosystem}:{file_type.value}"
        )
