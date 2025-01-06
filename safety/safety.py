# -*- coding: utf-8 -*-
from dataclasses import asdict
import errno
import itertools
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, Optional, List, Any, Union, Iterator

import click
import requests
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version, Version
from pydantic.json import pydantic_encoder
from filelock import FileLock

from safety_schemas.models import Ecosystem, FileType



from .constants import (API_MIRRORS, DB_CACHE_FILE, OPEN_MIRRORS, REQUEST_TIMEOUT, DATA_API_BASE_URL, JSON_SCHEMA_VERSION,
                        IGNORE_UNPINNED_REQ_REASON)
from .errors import (DatabaseFetchError, DatabaseFileNotFoundError, InvalidCredentialError,
                     TooManyRequestsError, NetworkConnectionError,
                     RequestTimeoutError, ServerError, MalformedDatabase)
from .models import Vulnerability, CVE, Severity, Fix, is_pinned_requirement, SafetyRequirement
from .output_utils import print_service, get_applied_msg, prompt_service, get_skipped_msg, get_fix_opt_used_msg, \
    is_using_api_key, get_specifier_range_info
from .util import build_remediation_info_url, pluralize, read_requirements, Package, build_telemetry_data, sync_safety_context, \
    SafetyContext, validate_expiration_date, is_a_remote_mirror, get_requirements_content, SafetyPolicyFile, \
    get_terminal_size, is_ignore_unpinned_mode, get_hashes

LOG = logging.getLogger(__name__)


def get_from_cache(db_name: str, cache_valid_seconds: int = 0, skip_time_verification: bool = False) -> Optional[Dict[str, Any]]:
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
                            if data[db_name]["cached_at"] + cache_valid_seconds > time.time() or skip_time_verification:
                                LOG.debug('Getting the database from cache at %s, cache setting: %s',
                                        data[db_name]["cached_at"], cache_valid_seconds)

                                try:
                                    data[db_name]["db"]["meta"]["base_domain"] = "https://data.safetycli.com"
                                except KeyError as e:
                                    pass

                                return data[db_name]["db"]

                            LOG.debug('Cached file is too old, it was cached at %s', data[db_name]["cached_at"])
                        else:
                            LOG.debug('There is not the cached_at key in %s database', data[db_name])

                except json.JSONDecodeError:
                    LOG.debug('JSONDecodeError trying to get the cached database.')
        else:
            LOG.debug("Cache file doesn't exist...")
    return None


def write_to_cache(db_name: str, data: Dict[str, Any]) -> None:
    """
    Writes the database to the cache.

    Args:
        db_name (str): The name of the database.
        data (Dict[str, Any]): The database data to be cached.
    """
    # cache is in: ~/safety/cache.json
    # and has the following form:
    # {
    #   "insecure.json": {
    #       "cached_at": 12345678
    #       "db": {}
    #   },
    #   "insecure_full.json": {
    #       "cached_at": 12345678
    #       "db": {}
    #   },
    # }
    if not os.path.exists(os.path.dirname(DB_CACHE_FILE)):
        try:
            os.makedirs(os.path.dirname(DB_CACHE_FILE))
            with open(DB_CACHE_FILE, "w") as _:
                _.write(json.dumps({}))
                LOG.debug('Cache file created')
        except OSError as exc:  # Guard against race condition
            LOG.debug('Unable to create the cache file because: %s', exc.errno)
            if exc.errno != errno.EEXIST:
                raise

    cache_file_lock = f"{DB_CACHE_FILE}.lock"
    lock = FileLock(cache_file_lock, timeout=10)
    with lock:
        if os.path.exists(DB_CACHE_FILE):
            with open(DB_CACHE_FILE, "r") as f:
                try:
                    cache = json.loads(f.read())
                except json.JSONDecodeError:
                    LOG.debug('JSONDecodeError in the local cache, dumping the full cache file.')
                    cache = {}
        else:
            cache = {}

        with open(DB_CACHE_FILE, "w") as f:
            cache[db_name] = {
                "cached_at": time.time(),
                "db": data
            }
            f.write(json.dumps(cache))
            LOG.debug('Safety updated the cache file for %s database.', db_name)


def fetch_database_url(
    session: requests.Session,
    mirror: str,
    db_name: str,
    cached: int,
    telemetry: bool = True,
    ecosystem: Ecosystem = Ecosystem.PYTHON,
    from_cache: bool = True
) -> Dict[str, Any]:
    """
    Fetches the database from a URL.

    Args:
        session (requests.Session): The requests session.
        mirror (str): The URL of the mirror.
        db_name (str): The name of the database.
        cached (int): The cache validity in seconds.
        telemetry (bool): Whether to include telemetry data.
        ecosystem (Ecosystem): The ecosystem.
        from_cache (bool): Whether to fetch from cache.

    Returns:
        Dict[str, Any]: The fetched database.
    """
    headers = {'schema-version': JSON_SCHEMA_VERSION, 'ecosystem': ecosystem.value}

    if cached and from_cache:
        cached_data = get_from_cache(db_name=db_name, cache_valid_seconds=cached)
        if cached_data:
            LOG.info('Database %s returned from cache.', db_name)
            return cached_data
    url = mirror + db_name


    telemetry_data = {
        'telemetry': json.dumps(build_telemetry_data(telemetry=telemetry),
                                default=pydantic_encoder)}

    try:
        r = session.get(url=url, timeout=REQUEST_TIMEOUT,
                        headers=headers, params=telemetry_data)
    except requests.exceptions.ConnectionError:
        raise NetworkConnectionError()
    except requests.exceptions.Timeout:
        raise RequestTimeoutError()
    except requests.exceptions.RequestException:
        raise DatabaseFetchError()

    if r.status_code == 403:
        raise InvalidCredentialError(credential=session.get_credential(), reason=r.text)

    if r.status_code == 429:
        raise TooManyRequestsError(reason=r.text)

    if r.status_code != 200:
        raise ServerError(reason=r.reason)

    try:
        data = r.json()
    except json.JSONDecodeError as e:
        raise MalformedDatabase(reason=e)

    if cached:
        LOG.info('Writing %s to cache because cached value was %s', db_name, cached)
        write_to_cache(db_name, data)

    return data


def fetch_policy(session: requests.Session) -> Dict[str, Any]:
    """
    Fetches the policy from the server.

    Args:
        session (requests.Session): The requests session.

    Returns:
        Dict[str, Any]: The fetched policy.
    """
    url = f"{DATA_API_BASE_URL}policy/"

    try:
        LOG.debug(f'Getting policy')
        r = session.get(url=url, timeout=REQUEST_TIMEOUT)
        LOG.debug(r.text)
        return r.json()
    except Exception:
        LOG.exception("Error fetching policy")

        return {"safety_policy": "", "audit_and_monitor": False}


def post_results(session: requests.Session, safety_json: str, policy_file: str) -> Dict[str, Any]:
    """
    Posts the scan results to the server.

    Args:
        session (requests.Session): The requests session.
        safety_json (str): The scan results in JSON format.
        policy_file (str): The policy file.

    Returns:
        Dict[str, Any]: The server response.
    """
    url = f"{DATA_API_BASE_URL}result/"

    # safety_json is in text form already. policy_file is a text YAML
    audit_report = {
        "safety_json": json.loads(safety_json),
        "policy_file": policy_file
    }

    try:
        LOG.debug(f'Posting results to: {url}')
        LOG.debug(f'Posting results: {audit_report}')
        r = session.post(url=url, timeout=REQUEST_TIMEOUT, json=audit_report)
        LOG.debug(r.text)

        return r.json()
    except:
        LOG.exception("Error posting results")
        click.secho(
            "Warning: couldn't upload results to safetycli.com.",
            fg="yellow",
            file=sys.stderr
        )

        return {}


def fetch_database_file(path: str, db_name: str, cached: int = 0, ecosystem: Optional[Ecosystem] = None) -> Dict[str, Any]:
    """
    Fetches the database from a local file.

    Args:
        path (str): The path to the local file.
        db_name (str): The name of the database.
        cached (int): The cache validity in seconds.
        ecosystem (Optional[Ecosystem]): The ecosystem.

    Returns:
        Dict[str, Any]: The fetched database.
    """
    full_path = (Path(path) / (ecosystem.value if ecosystem else '') / db_name).expanduser().resolve()

    if not full_path.exists():
        raise DatabaseFileNotFoundError(db=path)

    with open(full_path) as f:
        data = json.loads(f.read())

    if cached:
        LOG.info('Writing %s to cache because cached value was %s', db_name, cached)
        write_to_cache(db_name, data)

    return data


def is_valid_database(db: Dict[str, Any]) -> bool:
    """
    Checks if the database is valid.

    Args:
        db (Dict[str, Any]): The database.

    Returns:
        bool: True if the database is valid, False otherwise.
    """
    try:
        if db['meta']['schema_version'] == JSON_SCHEMA_VERSION:
            return True
    except Exception:
        return False

    return False


def fetch_database(
    session: requests.Session,
    full: bool = False,
    db: Union[Optional[str], bool] = False,
    cached: int = 0,
    telemetry: bool = True,
    ecosystem: Optional[Ecosystem] = None,
    from_cache: bool = True
) -> Dict[str, Any]:
    """
    Fetches the database from a mirror or a local file.

    Args:
        session (requests.Session): The requests session.
        full (bool): Whether to fetch the full database.
        db (Optional[str]): The path to the local database file.
        cached (int): The cache validity in seconds.
        telemetry (bool): Whether to include telemetry data.
        ecosystem (Optional[Ecosystem]): The ecosystem.
        from_cache (bool): Whether to fetch from cache.

    Returns:
        Dict[str, Any]: The fetched database.
    """
    if session.is_using_auth_credentials():
        mirrors = API_MIRRORS
    elif db:
        mirrors = [db]
    else:
        mirrors = OPEN_MIRRORS

    db_name = "insecure_full.json" if full else "insecure.json"
    for mirror in mirrors:
        # mirror can either be a local path or a URL
        if is_a_remote_mirror(mirror):
            if ecosystem is None:
                ecosystem = Ecosystem.PYTHON
            data = fetch_database_url(session, mirror, db_name=db_name, cached=cached,
                                      telemetry=telemetry, ecosystem=ecosystem, from_cache=from_cache)
        else:
            data = fetch_database_file(mirror, db_name=db_name, cached=cached,
                                       ecosystem=ecosystem)
        if data:
            if is_valid_database(data):
                return data
            raise MalformedDatabase(fetched_from=mirror,
                                    reason=f'Not supported schema version. '
                                           f'This Safety version supports only schema version {JSON_SCHEMA_VERSION}')

    raise DatabaseFetchError()


def get_vulnerabilities(pkg: str, spec: str, db: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    """
    Retrieves vulnerabilities for a package from the database.

    Args:
        pkg (str): The package name.
        spec (str): The specifier set.
        db (Dict[str, Any]): The database.

    Returns:
        Iterator[Dict[str, Any]]: An iterator of vulnerabilities.
    """
    for entry in db['vulnerable_packages'][pkg]:
        for entry_spec in entry["specs"]:
            if entry_spec == spec:
                yield entry


def get_vulnerability_from(
    vuln_id: str,
    cve: Optional[CVE],
    data: Dict[str, Any],
    specifier: str,
    db: Dict[str, Any],
    name: str,
    pkg: Package,
    ignore_vulns: Dict[str, Any],
    affected: SafetyRequirement
) -> Vulnerability:
    """
    Constructs a Vulnerability object from the provided data.

    Args:
        vuln_id (str): The vulnerability ID.
        cve (Optional[CVE]): The CVE object.
        data (Dict[str, Any]): The vulnerability data.
        specifier (str): The specifier set.
        db (Dict[str, Any]): The database.
        name (str): The package name.
        pkg (Package): The Package object.
        ignore_vulns (Dict[str, Any]): The ignored vulnerabilities.
        affected (SafetyRequirement): The affected requirement.

    Returns:
        Vulnerability: The constructed Vulnerability object.
    """
    base_domain = db.get('meta', {}).get('base_domain')
    unpinned_ignored = ignore_vulns.get(vuln_id, {}).get('requirements', None)
    should_ignore = not unpinned_ignored or str(affected.specifier) in unpinned_ignored

    ignored = (ignore_vulns and vuln_id in ignore_vulns and should_ignore and (
            not ignore_vulns[vuln_id]['expires'] or ignore_vulns[vuln_id]['expires'] > datetime.utcnow()))
    more_info_url = f"{base_domain}{data.get('more_info_path', '')}"
    severity = None

    if cve and (cve.cvssv2 or cve.cvssv3):
        severity = Severity(source=cve.name, cvssv2=cve.cvssv2, cvssv3=cve.cvssv3)

    analyzed_requirement = affected
    analyzed_version = next(iter(analyzed_requirement.specifier)).version if is_pinned_requirement(
        analyzed_requirement.specifier) else None

    vulnerable_spec = set()
    vulnerable_spec.add(specifier)

    return Vulnerability(
        vulnerability_id=vuln_id,
        package_name=name,
        pkg=pkg,
        ignored=ignored,
        ignored_reason=ignore_vulns.get(vuln_id, {}).get('reason', None) if ignore_vulns else None,
        ignored_expires=ignore_vulns.get(vuln_id, {}).get('expires', None) if ignore_vulns else None,
        vulnerable_spec=vulnerable_spec,
        all_vulnerable_specs=data.get("specs", []),
        analyzed_version=analyzed_version,
        analyzed_requirement=analyzed_requirement,
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
            next(filter(lambda i: i.get('type', None) in ['cve', 'pve'], data.get('ids', []))).get('id', ''))
    except StopIteration:
        xve_id: str = ''

    if not xve_id:
        return None

    cve_meta = db_full.get("meta", {}).get("severities", {}).get(xve_id, {})
    return CVE(name=xve_id, cvssv2=cve_meta.get("cvssv2", None),
               cvssv3=cve_meta.get("cvssv3", None))


def ignore_vuln_if_needed(
    pkg: Package,
    vuln_id: str,
    cve: Optional[CVE],
    ignore_vulns: Dict[str, Any],
    ignore_severity_rules: Dict[str, Any],
    req: SafetyRequirement
) -> None:
    """
    Determines if a vulnerability should be ignored based on severity rules and updates the ignore_vulns dictionary.

    Args:
        pkg (Package): The package.
        vuln_id (str): The vulnerability ID.
        cve (Optional[CVE]): The CVE object.
        ignore_vulns (Dict[str, Any]): The ignored vulnerabilities.
        ignore_severity_rules (Dict[str, Any]): The severity rules for ignoring vulnerabilities.
        req (SafetyRequirement): The affected requirement.
    """
    if not ignore_severity_rules:
        ignore_severity_rules = {}

    if not isinstance(ignore_vulns, dict):
        return

    severity = None

    if cve:
        if cve.cvssv2 and cve.cvssv2.get("base_score", None):
            severity = cve.cvssv2.get("base_score", None)

        if cve.cvssv3 and cve.cvssv3.get("base_score", None):
            severity = cve.cvssv3.get("base_score", None)

    ignore_severity_below = float(ignore_severity_rules.get('ignore-cvss-severity-below', 0.0))
    ignore_unknown_severity = bool(ignore_severity_rules.get('ignore-cvss-unknown-severity', False))

    if severity:
        if float(severity) < ignore_severity_below:
            reason = 'Ignored by severity rule in policy file, {0} < {1}'.format(float(severity), ignore_severity_below)
            ignore_vulns[vuln_id] = {'reason': reason, 'expires': None}
    elif ignore_unknown_severity:
        reason = 'Unknown CVSS severity, ignored by severity rule in policy file.'
        ignore_vulns[vuln_id] = {'reason': reason, 'expires': None}

    version = next(iter(req.specifier)).version if is_pinned_requirement(req.specifier) else pkg.version

    is_prev_not_ignored: bool = vuln_id not in ignore_vulns
    is_req_not_ignored: bool = 'requirements' in ignore_vulns.get(vuln_id, {}) and str(req.specifier) not in ignore_vulns.get(vuln_id, {}).get('requirements', set())

    if (is_prev_not_ignored or is_req_not_ignored) and is_ignore_unpinned_mode(version):
        reason = IGNORE_UNPINNED_REQ_REASON
        requirements = set()
        requirements.add(str(req.specifier))
        ignore_vulns[vuln_id] = {'reason': reason, 'expires': None, 'requirements': requirements}


def is_vulnerable(vulnerable_spec: SpecifierSet, requirement: SafetyRequirement, package: Package) -> bool:
    """
    Checks if a package version is vulnerable.

    Args:
        vulnerable_spec (SpecifierSet): The specifier set for vulnerable versions.
        requirement (SafetyRequirement): The package requirement.
        package (Package): The package.

    Returns:
        bool: True if the package version is vulnerable, False otherwise.
    """
    if is_pinned_requirement(requirement.specifier):
        try:
            return vulnerable_spec.contains(next(iter(requirement.specifier)).version)
        except Exception:
            # Ugly for now...
            message = f'Version {requirement.specifier} for {package.name} is invalid and is ignored by Safety. Please See PEP 440.'
            if message not in [a['message'] for a in SafetyContext.local_announcements]:
                SafetyContext.local_announcements.append(
                    {'message': message,
                    'type': 'warning', 'local': True})
            return False

    return any(requirement.specifier.filter(vulnerable_spec.filter(package.insecure_versions, prereleases=True),
                                            prereleases=True))


@sync_safety_context
def check(
    *,
    session: requests.Session,
    packages: List[Package] = [],
    db_mirror: Union[Optional[str], bool] = False,
    cached: int = 0,
    ignore_vulns: Optional[Dict[str, Any]] = None,
    ignore_severity_rules: Optional[Dict[str, Any]] = None,
    proxy: Optional[Dict[str, Any]] = None,
    include_ignored: bool = False,
    is_env_scan: bool = True,
    telemetry: bool = True,
    params: Optional[Dict[str, Any]] = None,
    project: Optional[str] = None
) -> tuple:
    """
    Performs a vulnerability check on the provided packages.

    Args:
        session (requests.Session): The requests session.
        packages (List[Package]): The list of packages to check.
        db_mirror (Union[Optional[str], bool]): The database mirror.
        cached (int): The cache validity in seconds.
        ignore_vulns (Optional[Dict[str, Any]]): The ignored vulnerabilities.
        ignore_severity_rules (Optional[Dict[str, Any]]): The severity rules for ignoring vulnerabilities.
        proxy (Optional[Dict[str, Any]]): The proxy settings.
        include_ignored (bool): Whether to include ignored vulnerabilities.
        is_env_scan (bool): Whether it is an environment scan.
        telemetry (bool): Whether to include telemetry data.
        params (Optional[Dict[str, Any]]): Additional parameters.
        project (Optional[str]): The project name.

    Returns:
        tuple: A tuple containing the list of vulnerabilities and the full database.
    """
    SafetyContext().command = 'check'
    db = fetch_database(session, db=db_mirror, cached=cached, telemetry=telemetry)
    db_full = None
    vulnerable_packages = frozenset(db.get('vulnerable_packages', []))
    vulnerabilities = []
    found_pkgs = {}
    requirements = iter([])

    for p in packages:
        requirements = itertools.chain(p.requirements, requirements)
        found_pkgs[canonicalize_name(p.name)] = p

    # Let's report by req, pinned in environment will be ==version
    for req in requirements:
        vuln_per_req = {}
        name = canonicalize_name(req.name)

        pkg = found_pkgs.get(name, None)

        if not pkg.version:
            if not db_full:
                db_full = fetch_database(session, full=True, db=db_mirror, cached=cached,
                                         telemetry=telemetry)
            pkg.refresh_from(db_full)

        if name in vulnerable_packages:
            # we have a candidate here, build the spec set
            for specifier in db['vulnerable_packages'][name]:
                spec_set = SpecifierSet(specifiers=specifier)

                if is_vulnerable(spec_set, req, pkg):
                    if not db_full:
                        db_full = fetch_database(session, full=True, db=db_mirror, cached=cached,
                                                 telemetry=telemetry)
                    if not pkg.latest_version:
                        pkg.refresh_from(db_full)

                    for data in get_vulnerabilities(pkg=name, spec=specifier, db=db_full):
                        try:
                            vuln_id: str = str(next(filter(lambda i: i.get('type', None) == 'pyup', data.get('ids', []))).get('id', ''))
                        except StopIteration:
                            vuln_id: str = ''

                        if vuln_id in vuln_per_req:
                            vuln_per_req[vuln_id].vulnerable_spec.add(specifier)
                            continue

                        cve = get_cve_from(data, db_full)

                        ignore_vuln_if_needed(pkg, vuln_id, cve, ignore_vulns, ignore_severity_rules, req)

                        vulnerability = get_vulnerability_from(vuln_id, cve, data, specifier, db_full, name, pkg,
                                                               ignore_vulns, req)

                        should_add_vuln = not (vulnerability.is_transitive and is_env_scan)

                        if (include_ignored or vulnerability.vulnerability_id not in ignore_vulns) and should_add_vuln:
                            vuln_per_req[vulnerability.vulnerability_id] = vulnerability
                            vulnerabilities.append(vulnerability)

    return vulnerabilities, db_full


def precompute_remediations(
    remediations: Dict[str, Dict[str, Any]],
    packages: Dict[str, Package],
    vulns: List[Vulnerability],
    secure_vulns_by_user: set
) -> None:
    """
    Precomputes the remediations for the given vulnerabilities.

    Args:
        remediations (Dict[str, Dict[str, Any]]): The remediations dictionary.
        packages (Dict[str, Package]): The packages dictionary.
        vulns (List[Vulnerability]): The list of vulnerabilities.
        secure_vulns_by_user (set): The set of vulnerabilities secured by the user.
    """
    for vuln in vulns:

        if vuln.ignored and vuln.ignored_reason != IGNORE_UNPINNED_REQ_REASON:
            secure_vulns_by_user.add(vuln.vulnerability_id)
            continue

        if vuln.package_name in remediations.keys() and str(vuln.analyzed_requirement.specifier) in remediations[vuln.package_name]:
            spec = remediations[vuln.package_name][str(vuln.analyzed_requirement.specifier)]
            spec['vulnerabilities_found'] = spec.get('vulnerabilities_found', 0) + 1
        else:
            version = None
            is_pinned = is_pinned_requirement(vuln.analyzed_requirement.specifier)

            if is_pinned:
                version = next(iter(vuln.analyzed_requirement.specifier)).version

            if not is_pinned and is_ignore_unpinned_mode(version):
                # Let's ignore this requirement
                continue

            vulns_count = 1
            packages[vuln.package_name] = vuln.pkg

            remediations[vuln.package_name][str(vuln.analyzed_requirement.specifier)] = {
                'vulnerabilities_found': vulns_count,
                'version': version,
                'requirement': vuln.analyzed_requirement,
                'more_info_url': vuln.pkg.more_info_url}


def get_closest_ver(
    versions: List[str],
    version: Optional[str],
    spec: SpecifierSet
) -> Dict[str, Optional[Union[str, Version]]]:
    """
    Retrieves the closest versions for the given version and specifier set.

    Args:
        versions (List[str]): The list of versions.
        version (Optional[str]): The current version.
        spec (SpecifierSet): The specifier set.

    Returns:
        Dict[str, Optional[Union[str, Version]]]: The closest versions.
    """
    results: Dict[str, Optional[Union[str, Version]]] = {'upper': None, 'lower': None}

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
            results['upper'] = upper
            results['lower'] = lower if upper != lower else None
        except IndexError:
            pass

        return results

    current_v = parse_version(version)

    for v in sorted_versions:
        index = parse_version(v)

        if index > current_v:
            results['upper'] = index

        if index < current_v:
            results['lower'] = index
            break

    return results


def compute_sec_ver_for_user(
    package: Package,
    secure_vulns_by_user: set,
    db_full: Dict[str, Any]
) -> List[str]:
    """
    Computes the secure versions for the user.

    Args:
        package (Package): The package.
        secure_vulns_by_user (set): The set of vulnerabilities secured by the user.
        db_full (Dict[str, Any]): The full database.

    Returns:
        List[str]: The list of secure versions.
    """
    versions = package.get_versions(db_full)
    affected_versions = []

    for vuln in db_full.get('vulnerable_packages', {}).get(package.name, []):
        vuln_id: str = str(next(filter(lambda i: i.get('type', None) == 'pyup', vuln.get('ids', []))).get('id', ''))
        if vuln_id and vuln_id not in secure_vulns_by_user:
            affected_versions += vuln.get('affected_versions', [])

    affected_v = set(affected_versions)
    sec_ver_for_user = list(versions.difference(affected_v))

    return sorted(sec_ver_for_user, key=lambda ver: parse_version(ver), reverse=True)


def compute_sec_ver(
    remediations: Dict[str, Dict[str, Any]],
    packages: Dict[str, Package],
    secure_vulns_by_user: set,
    db_full: Dict[str, Any]
) -> None:
    """
    Computes the secure versions and the closest secure version for each remediation.

    Uses the affected_versions of each no ignored vulnerability of the same package, there is only a remediation for each package.

    Args:
        remediations (Dict[str, Dict[str, Any]]): The remediations dictionary.
        packages (Dict[str, Package]): The packages dictionary.
        secure_vulns_by_user (set): The set of vulnerabilities secured by the user.
        db_full (Dict[str, Any]): The full database.
    """
    for pkg_name in remediations.keys():
        pkg: Package = packages.get(pkg_name, None)

        secure_versions = []

        if pkg:
            secure_versions = pkg.secure_versions

        analyzed = set(remediations[pkg_name].keys())

        if not is_using_api_key():
            continue

        for analyzed_requirement in analyzed:
            rem = remediations[pkg_name][analyzed_requirement]
            spec = rem.get('requirement').specifier
            version = rem['version']

            if not secure_vulns_by_user:
                secure_v = sorted(secure_versions, key=lambda ver: parse_version(ver), reverse=True)
            else:
                secure_v = compute_sec_ver_for_user(package=pkg, secure_vulns_by_user=secure_vulns_by_user, db_full=db_full)

            rem['closest_secure_version'] = get_closest_ver(secure_v, version, spec)

            upgrade = rem['closest_secure_version'].get('upper', None)
            downgrade = rem['closest_secure_version'].get('lower', None)
            recommended_version = None

            if upgrade:
                recommended_version = upgrade
            elif downgrade:
                recommended_version = downgrade

            rem['recommended_version'] = recommended_version
            rem['other_recommended_versions'] = [other_v for other_v in secure_v if
                                                                    other_v != str(recommended_version)]

            # Refresh the URL with the recommended version.

            spec = str(rem['requirement'].specifier)
            if is_using_api_key():
                rem['more_info_url'] = \
                    build_remediation_info_url(base_url=rem['more_info_url'], version=version,
                                           spec=spec,
                                           target_version=recommended_version)


def calculate_remediations(
    vulns: List[Vulnerability],
    db_full: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    """
    Calculates the remediations for the given vulnerabilities.

    Args:
        vulns (List[Vulnerability]): The list of vulnerabilities.
        db_full (Dict[str, Any]): The full database.

    Returns:
        Dict[str, Dict[str, Any]]: The calculated remediations.
    """
    remediations = defaultdict(dict)
    package_metadata = {}
    secure_vulns_by_user = set()

    if not db_full:
        return remediations

    precompute_remediations(remediations, package_metadata, vulns, secure_vulns_by_user)
    compute_sec_ver(remediations, package_metadata, secure_vulns_by_user, db_full)

    return remediations


def should_apply_auto_fix(
    from_ver: Optional[Version],
    to_ver: Version,
    allowed_automatic: List[str]
) -> bool:
    """
    Determines if an automatic fix should be applied.

    Args:
        from_ver (Optional[Version]): The current version.
        to_ver (Version): The target version.
        allowed_automatic (List[str]): The allowed automatic update types.

    Returns:
        bool: True if an automatic fix should be applied, False otherwise.
    """
    if not from_ver:
        return False

    if 'major' in allowed_automatic:
        return True

    major_change = to_ver.major - from_ver.major
    minor_change = to_ver.minor - from_ver.minor

    if 'minor' in allowed_automatic:
        if major_change != 0:
            return False

        return True

    if 'patch' in allowed_automatic:
        if major_change != 0 or minor_change != 0:
            return False

        return True

    return False


def get_update_type(from_ver: Optional[Version], to_ver: Version) -> str:
    """
    Determines the update type.

    Args:
        from_ver (Optional[Version]): The current version.
        to_ver (Version): The target version.

    Returns:
        str: The update type.
    """
    if not from_ver or (to_ver.major - from_ver.major) != 0:
        return 'major'

    if (to_ver.minor - from_ver.minor) != 0:
        return 'minor'

    return 'patch'


def process_fixes(
    files: List[str],
    remediations: Dict[str, Dict[str, Any]],
    auto_remediation_limit: List[str],
    output: str,
    no_output: bool = True,
    prompt: bool = False
) -> List[Fix]:
    """
    Processes the fixes for the given files and remediations.

    Args:
        files (List[str]): The list of files.
        remediations (Dict[str, Dict[str, Any]]): The remediations dictionary.
        auto_remediation_limit (List[str]): The automatic remediation limits.
        output (str): The output format.
        no_output (bool): Whether to suppress output.
        prompt (bool): Whether to prompt for confirmation.

    Returns:
        List[Fix]: The list of applied fixes.
    """
    req_remediations = itertools.chain.from_iterable(rem.values() for pkg_name, rem in remediations.items())
    requirements = compute_fixes_per_requirements(files, req_remediations, auto_remediation_limit, prompt=prompt)
    fixes = apply_fixes(requirements, output, no_output, prompt)
    return fixes


def process_fixes_scan(
    file_to_fix: SafetyPolicyFile,
    to_fix_spec: List[SafetyRequirement],
    auto_remediation_limit: List[str],
    output: str,
    no_output: bool = True,
    prompt: bool = False
) -> List[Fix]:
    """
    Processes the fixes for the given file and specifications in scan mode.

    Args:
        file_to_fix (SafetyPolicyFile): The file to fix.
        to_fix_spec (List[SafetyRequirement]): The specifications to fix.
        auto_remediation_limit (List[str]): The automatic remediation limits.
        output (str): The output format.
        no_output (bool): Whether to suppress output.
        prompt (bool): Whether to prompt for confirmation.

    Returns:
        List[Fix]: The list of applied fixes.
    """
    to_fix_remediations =  []

    def get_remmediation_from(spec):
        upper = None
        lower = None
        recommended = None

        try:
            upper = Version(spec.remediation.closest_secure.upper) if spec.remediation.closest_secure.upper else None
        except Exception as e:
            LOG.error(f'Error getting upper remediation version, ignoring', exc_info=True)

        try:
            lower = Version(spec.remediation.closest_secure.lower) if spec.remediation.closest_secure.lower else None
        except Exception as e:
            LOG.error(f'Error getting lower remediation version, ignoring', exc_info=True)

        try:
            recommended = Version(spec.remediation.recommended)
        except Exception as e:
            LOG.error(f'Error getting recommended version for remediation, ignoring', exc_info=True)

        return {
            "vulnerabilities_found": spec.remediation.vulnerabilities_found,
            "version": next(iter(spec.specifier)).version if spec.is_pinned() else None,
            "requirement": spec,
            "more_info_url": spec.remediation.more_info_url,
            "closest_secure_version": {
                'upper': upper,
                'lower': lower
                },
            "recommended_version": recommended,
            "other_recommended_versions": spec.remediation.other_recommended
        }

    req_remediations = iter(get_remmediation_from(spec) for spec in to_fix_spec)
    SUPPORTED_FILE_TYPES = [FileType.REQUIREMENTS_TXT]

    if file_to_fix.file_type in SUPPORTED_FILE_TYPES:
        files = (open(file_to_fix.location),)
        requirements = compute_fixes_per_requirements(files, req_remediations, auto_remediation_limit, prompt=prompt)
    else:
        requirements = {
            'files': {str(file_to_fix.location): {'content': None, 'fixes': {'TO_SKIP': [], 'TO_APPLY': [], 'TO_CONFIRM': []}, 'supported': False, 'filename': file_to_fix.location.name}},
            'dependencies': defaultdict(dict),
        }

    fixes = apply_fixes(requirements, output, no_output, prompt, scan_flow=True, auto_remediation_limit=auto_remediation_limit)

    return fixes


def compute_fixes_per_requirements(
    files: List[str],
    req_remediations: Iterator[Dict[str, Any]],
    auto_remediation_limit: List[str],
    prompt: bool = False
) -> Dict[str, Any]:
    """
    Computes the fixes per requirements.

    Args:
        files (List[str]): The list of files.
        req_remediations (Iterator[Dict[str, Any]]): The remediations iterator.
        auto_remediation_limit (List[str]): The automatic remediation limits.
        prompt (bool): Whether to prompt for confirmation.

    Returns:
        Dict[str, Any]: The computed requirements with fixes.
    """
    requirements_files = get_requirements_content(files)

    from dparse.parser import parse, filetypes
    from packaging.version import Version, InvalidVersion

    requirements = {
        'files': {},
        'dependencies': defaultdict(dict),
    }

    for name, contents in requirements_files.items():
        dependency_file = parse(contents, path=name, file_type=filetypes.requirements_txt, resolve=True)
        dependency_files = dependency_file.resolved_files + [dependency_file]
        empty_spec = SpecifierSet('')
        default_spec = SpecifierSet('>=0')

        # Support recursive requirements in the multiple requirement files provided
        for resolved_f in dependency_files:
            if not resolved_f or isinstance(resolved_f, str):
                continue
            file = {'content': resolved_f.content, 'fixes': {'TO_SKIP': [], 'TO_APPLY': [], 'TO_CONFIRM': []}}
            requirements['files'][resolved_f.path] = file

            for d in resolved_f.dependencies:
                if d.specs == empty_spec:
                    d.specs = default_spec

                requirements['dependencies'][d.name][str(d.specs)] = (d, resolved_f.path)

    for remediation in req_remediations:
        req: SafetyRequirement = remediation.get('requirement')
        pkg: str = req.name

        dry_fix = Fix(package=pkg, more_info_url=remediation.get('more_info_url', ''),
                      previous_spec=str(req.specifier),
                      other_options=remediation.get('other_recommended_versions', []))
        from_ver: Optional[str] = remediation.get('version', None)

        if pkg not in requirements['dependencies'] or dry_fix.previous_spec not in requirements['dependencies'][pkg]:
            # Let's attach it to the first file scanned.
            file = next(iter(requirements['files']))
            # Let's use the no parsed version.
            dry_fix.previous_version = from_ver
            dry_fix.status = 'AUTOMATICALLY_SKIPPED_NOT_FOUND_IN_FILE'
            dry_fix.applied_at = file
            requirements['files'][file]['fixes']['TO_SKIP'].append(dry_fix)
            continue

        dependency, name = requirements['dependencies'][pkg][dry_fix.previous_spec]
        dry_fix.applied_at = name

        fixes = requirements['files'][name]['fixes']

        to_ver: Version = remediation['recommended_version']

        try:
            from_ver = parse_version(from_ver)
        except (InvalidVersion, TypeError):

            if not dry_fix.previous_spec:
                dry_fix.status = 'AUTOMATICALLY_SKIPPED_INVALID_VERSION'
                fixes['TO_SKIP'].append(dry_fix)
                continue

        dry_fix.previous_version = str(from_ver) if from_ver else from_ver

        if remediation['recommended_version'] is None:
            dry_fix.status = 'AUTOMATICALLY_SKIPPED_NO_RECOMMENDED_VERSION'
            fixes['TO_SKIP'].append(dry_fix)
            continue

        dry_fix.updated_version = str(to_ver)

        is_fixed = from_ver == to_ver

        if is_fixed:
            dry_fix.status = 'AUTOMATICALLY_SKIPPED_ALREADY_FIXED'
            fixes['TO_SKIP'].append(dry_fix)
            continue

        update_type = get_update_type(from_ver, to_ver)
        dry_fix.update_type = update_type
        dry_fix.dependency = dependency

        auto_fix = should_apply_auto_fix(from_ver, to_ver, auto_remediation_limit)

        TARGET = 'TO_APPLY'

        if auto_fix:
            dry_fix.status = 'PENDING_TO_APPLY'
            dry_fix.fix_type = 'AUTOMATIC'
        elif prompt:
            TARGET = 'TO_CONFIRM'
            dry_fix.status = 'PENDING_TO_CONFIRM'
            dry_fix.fix_type = 'MANUAL'
        else:
            TARGET = 'TO_SKIP'
            dry_fix.status = 'AUTOMATICALLY_SKIPPED_UNABLE_TO_CONFIRM'

        fixes[TARGET].append(dry_fix)

    return requirements


def apply_fixes(
    requirements: Dict[str, Any],
    out_type: str,
    no_output: bool,
    prompt: bool,
    scan_flow: bool = False,
    auto_remediation_limit: List[str] = None
) -> List[Fix]:
    """
    Applies the fixes to the requirements.

    Args:
        requirements (Dict[str, Any]): The requirements with fixes.
        out_type (str): The output format.
        no_output (bool): Whether to suppress output.
        prompt (bool): Whether to prompt for confirmation.
        scan_flow (bool): Whether it is in scan flow mode.
        auto_remediation_limit (List[str]): The automatic remediation limits.

    Returns:
        List[Fix]: The list of applied fixes.
    """

    from dparse.updater import RequirementsTXTUpdater

    skip = []
    apply = []
    confirm = []

    brief = []

    if not no_output:
        style_kwargs = {}

        if not scan_flow:
            brief.append(('', {}))
            brief.append((f"Safety fix running", style_kwargs))
        print_service(brief, out_type)

    for name, data in requirements['files'].items():
        output = [('', {}),
                  (f"Analyzing {name}... [{get_fix_opt_used_msg(auto_remediation_limit)} limit]", {'styling': {'bold': True}, 'start_line_decorator': '->', 'indent': ' '})]

        r_skip = data['fixes']['TO_SKIP']
        r_apply = data['fixes']['TO_APPLY']
        r_confirm = data['fixes']['TO_CONFIRM']

        if data.get('supported', True):
            new_content = data['content']

            updated: bool = False

            for f in r_apply:
                new_content = RequirementsTXTUpdater.update(content=new_content, version=f.updated_version,
                                                            dependency=f.dependency, hashes=get_hashes(f.dependency))
                f.status = 'APPLIED'
                updated = True
                output.append(('', {}))
                output.append((f'- {get_applied_msg(f, mode="auto")}', {}))

            for f in r_skip:
                output.append(('', {}))
                output.append((f'- {get_skipped_msg(f)}', {}))

            if not no_output:
                print_service(output, out_type)

            if prompt and not no_output:
                for f in r_confirm:
                    options = [f"({index}) =={option}" for index, option in enumerate(f.other_options)]
                    input_hint = f'Enter “y” to update to {f.package}=={f.updated_version}, “n” to skip this package upgrade'

                    if len(options) > 0:
                        input_hint += f', or enter the index from these secure versions to upgrade to that version: {", ".join(options)}'

                    print_service([('', {})], out_type)
                    confirmed: str = prompt_service(
                        (f'- {f.package}{f.previous_spec} requires at least a {f.update_type} version update. Do you want to update {f.package} from {f.previous_spec} to =={f.updated_version}, which is the closest secure version? {input_hint}', {}),
                        out_type
                    ).lower()

                    try:
                        index: int = int(confirmed)
                        if index <= len(f.other_options):
                            confirmed = 'y'
                    except ValueError:
                        index = -1

                    if confirmed == 'y' or index > -1:
                        f.status = 'APPLIED'
                        updated = True

                        if index > -1:
                            f.updated_version = f.other_options[index]

                        new_content = RequirementsTXTUpdater.update(content=new_content, version=f.updated_version,
                                                                    dependency=f.dependency,
                                                                    hashes=get_hashes(f.dependency))
                        output.append((get_applied_msg(f, mode="manual"), {'indent': ' ' * 5}))
                    else:
                        f.status = 'MANUALLY_SKIPPED'
                        output.append((get_skipped_msg(f), {'indent': ' ' * 5}))

                    if not no_output:
                        print_service(output, out_type)

            if updated:
                output.append(('', {}))
                output.append((f"Updating {name}...", {}))
                with open(name, mode="w") as r_file:
                    r_file.write(new_content)
                output.append((f"Changes applied to {name}.", {}))
                count = len(r_apply) + len([1 for fix in r_confirm if fix.status == 'APPLIED'])
                output.append((f"{count} package {pluralize('version', count)} {pluralize('has', count)} been updated to secure versions in {Path(name).name}", {}))
                output.append(("Always check for breaking changes after updating packages.", {}))
            else:
                output.append((f"No fixes to be made in {name}.", {}))
                output.append(('', {}))
        else:
            not_supported_filename = data.get('filename', name)
            output.append(
                (f"{not_supported_filename} updates not supported: Please update these dependencies using your package manager.",
                 {'start_line_decorator': ' -', 'indent': ' '}))
            output.append(('', {}))

        if not no_output:
            print_service(output, out_type)

        skip.extend(r_skip)
        apply.extend(r_apply)
        confirm.extend(r_confirm)

    # The scan flow will handle the header and divider, because the scan flow can be called multiple times.
    if not no_output and not scan_flow:
        divider = f'{"=" * 78}' if out_type == 'text' else f'{"=" * (get_terminal_size().columns - 2)}'
        format_text = {'start_line_decorator': '+', 'end_line_decorator': '+', 'indent': ''}
        print_service([(divider, {})], out_type, format_text=format_text)

    return skip + apply + confirm


def find_vulnerabilities_fixed(
    vulnerabilities: Dict[str, Any],
    fixes: List[Fix]
) -> List[Vulnerability]:
    """
    Finds the vulnerabilities that have been fixed.

    Args:
        vulnerabilities (Dict[str, Any]): The dictionary of vulnerabilities.
        fixes (List[Fix]): The list of applied fixes.

    Returns:
        List[Vulnerability]: The list of fixed vulnerabilities.
    """
    fixed_specs = set(fix.previous_spec for fix in fixes)

    if not fixed_specs:
        return []

    return [vulnerability for vulnerability in vulnerabilities if
            str(vulnerability['analyzed_requirement'].specifier) in fixed_specs]


@sync_safety_context
def review(
    *,
    report: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None
) -> tuple:
    """
    Reviews the report and returns the vulnerabilities and remediations.

    Args:
        report (Optional[Dict[str, Any]]): The report.
        params (Optional[Dict[str, Any]]): Additional parameters.

    Returns:
        tuple: A tuple containing the list of vulnerabilities, the remediations, and the found packages.
    """
    SafetyContext().command = 'review'
    vulnerable = []
    vulnerabilities = report.get('vulnerabilities', []) + report.get('ignored_vulnerabilities', [])
    remediations = defaultdict(dict)

    for key, pkg_rem in report.get('remediations', {}).items():
        analyzed = set(pkg_rem['requirements'].keys())

        for req in analyzed:
            req_rem = pkg_rem['requirements'][req]
            recommended = req_rem.get('recommended_version', None)
            secure_v = req_rem.get('other_recommended_versions', [])

            remediations[key][req] = {'vulnerabilities_found': req_rem.get('vulnerabilities_found', 0),
                                      'version': req_rem.get('version'),
                                      'requirement': SafetyRequirement(req_rem['requirement']['raw']),
                                      'other_recommended_versions': secure_v,
                                      'recommended_version': parse_version(recommended) if recommended else None,
                                      # minor isn't supported in review
                                      'more_info_url': req_rem.get('more_info_url')}

    packages = report.get('scanned_packages', [])
    pkgs = {}

    for name, values in packages.items():
        requirements = [SafetyRequirement(r['raw']) for r in values.get('requirements', [])]
        values.update({'requirements': requirements})
        pkgs[name] = Package(**values)

    ctx = SafetyContext()
    found_packages = list(pkgs.values())
    ctx.packages = found_packages
    ctx.review = report.get('report_meta', [])
    ctx.key = ctx.review.get('api_key', False)
    cvssv2 = None
    cvssv3 = None

    for vuln in vulnerabilities:
        vuln['pkg'] = pkgs.get(vuln.get('package_name', None))
        XVE_ID = vuln.get('CVE', None)  # Trying to get first the CVE ID

        severity = vuln.get('severity', None)
        if severity and severity.get('source', False):
            cvssv2 = severity.get('cvssv2', None)
            cvssv3 = severity.get('cvssv3', None)
            # Trying to get the PVE ID if it exists, otherwise it will be the same CVE ID of above
            XVE_ID = severity.get('source', False)
            vuln['severity'] = Severity(source=XVE_ID, cvssv2=cvssv2, cvssv3=cvssv3)
        else:
            vuln['severity'] = None

        ignored_expires = vuln.get('ignored_expires', None)

        if ignored_expires:
            vuln['ignored_expires'] = validate_expiration_date(ignored_expires)

        vuln['CVE'] = CVE(name=XVE_ID, cvssv2=cvssv2, cvssv3=cvssv3) if XVE_ID else None
        vuln['analyzed_requirement'] = SafetyRequirement(vuln['analyzed_requirement']['raw'])

        vulnerable.append(Vulnerability(**vuln))

    return vulnerable, remediations, found_packages


@sync_safety_context
def get_licenses(
    *,
    session: requests.Session,
    db_mirror: Union[Optional[str], bool] = False,
    cached: int = 0,
    telemetry: bool = True
) -> Dict[str, Any]:
    """
    Retrieves the licenses from the database.

    Args:
        session (requests.Session): The requests session.
        db_mirror (Union[Optional[str], bool]): The database mirror.
        cached (int): The cache validity in seconds.
        telemetry (bool): Whether to include telemetry data.

    Returns:
        Dict[str, Any]: The licenses dictionary.
    """
    if db_mirror:
        mirrors = [db_mirror]
    else:
        mirrors = API_MIRRORS

    db_name = "licenses.json"

    for mirror in mirrors:
        # mirror can either be a local path or a URL
        if is_a_remote_mirror(mirror):
            licenses = fetch_database_url(session, mirror, db_name=db_name, cached=cached,
                                          telemetry=telemetry)
        else:
            licenses = fetch_database_file(mirror, db_name=db_name, ecosystem=None)
        if licenses:
            return licenses
    raise DatabaseFetchError()


def add_local_notifications(
    packages: List[Package],
    ignore_unpinned_requirements: Optional[bool]
) -> List[Dict[str, str]]:
    """
    Adds local notifications for unpinned packages.

    Args:
        packages (List[Package]): The list of packages.
        ignore_unpinned_requirements (Optional[bool]): Whether to ignore unpinned requirements.

    Returns:
        List[Dict[str, str]]: The list of notifications.
    """
    announcements = []
    unpinned_packages: List[str] = [f"{pkg.name}" for pkg in packages if pkg.has_unpinned_req()]

    if unpinned_packages and ignore_unpinned_requirements is not False:
        found = len(unpinned_packages)
        and_msg = ''

        if found >= 2:
            last = unpinned_packages.pop()
            and_msg = f' and {last}'

        pkgs: str = f"{', '.join(unpinned_packages)}{and_msg} {'are' if found > 1 else 'is'}"
        doc_msg: str = get_specifier_range_info(style=False, pin_hint=True)

        if ignore_unpinned_requirements is None:
            msg = f'Warning: {pkgs} unpinned. Safety by default does not ' \
                  f'report on potential vulnerabilities in unpinned packages. {doc_msg}'
        else:
            msg = f'Warning: {pkgs} unpinned and potential vulnerabilities are ' \
                  f'being ignored given `ignore-unpinned-requirements` is True in your config. {doc_msg}'

        announcements.append({'message': msg, 'type': 'warning', 'local': True})

    announcements.extend(SafetyContext().local_announcements)

    return announcements


def get_announcements(
    session: requests.Session,
    telemetry: bool = True,
    with_telemetry: Any = None
) -> List[Dict[str, str]]:
    """
    Retrieves announcements from the server.

    Args:
        session (requests.Session): The requests session.
        telemetry (bool): Whether to include telemetry data.
        with_telemetry (Optional[Dict[str, Any]]): The telemetry data.

    Returns:
        List[Dict[str, str]]: The list of announcements.
    """
    LOG.info('Getting announcements')

    announcements = []

    url = f"{DATA_API_BASE_URL}announcements/"
    method = 'post'
    telemetry_data = with_telemetry if with_telemetry else build_telemetry_data(telemetry=telemetry)
    data = asdict(telemetry_data)
    request_kwargs = {'timeout': 3}
    data_keyword = 'json'

    source = os.environ.get('SAFETY_ANNOUNCEMENTS_URL', None)

    if source:
        LOG.debug(f'Getting the announcement from a different source: {source}')
        url = source
        method = 'get'
        data = {
            'telemetry': json.dumps(data)}
        data_keyword = 'params'

    request_kwargs[data_keyword] = data
    request_kwargs['url'] = url

    LOG.debug(f'Telemetry data sent: {data}')

    try:
        request_func = getattr(session, method)
        r = request_func(**request_kwargs)
        LOG.debug(r.text)
    except Exception as e:
        LOG.info('Unexpected but HANDLED Exception happened getting the announcements: %s', e)
        return announcements

    if r.status_code == 200:
        try:
            announcements = r.json()
            if 'announcements' in announcements.keys():
                announcements = announcements.get('announcements', [])
            else:
                LOG.info('There is not announcements key in the JSON response, is this a wrong structure?')
                announcements = []

        except json.JSONDecodeError as e:
            LOG.info('Unexpected but HANDLED Exception happened decoding the announcement response: %s', e)

    LOG.info('Announcements fetched')

    return announcements



def get_packages(files: Optional[List[str]] = None, stdin: bool = False) -> List[Package]:
    """
    Retrieves the packages from the given files or standard input.

    Args:
        files (Optional[List[str]]): The list of files.
        stdin (bool): Whether to read from standard input.

    Returns:
        List[Package]: The list of packages.
    """
    if files:
        return list(itertools.chain.from_iterable(read_requirements(f, resolve=True) for f in files))

    if stdin:
        return list(read_requirements(sys.stdin))

    # TODO: Migrate away from pkg_resources and use importlib
    import pkg_resources

    def allowed_version(pkg: str, version: str) -> bool:
        try:
            parse_version(version)
        except Exception:
            SafetyContext.local_announcements.append(
                {'message': f'Version {version} for {pkg} is invalid and is ignored by Safety. Please See PEP 440.',
                 'type': 'warning', 'local': True})
            return False

        return True

    w_set = pkg_resources.working_set

    SafetyContext().scanned_full_path.extend(w_set.entry_keys.keys())

    return [
        Package(name=d.key, version=d.version,
                requirements=[SafetyRequirement(f'{d.key}=={d.version}', found=d.location)],
                found=d.location, insecure_versions=[],
                secure_versions=[], latest_version=None, latest_version_without_known_vulnerabilities=None,
                more_info_url=None) for d in
        w_set
        if d.key not in {"python", "wsgiref", "argparse"} and allowed_version(d.key, d.version)
    ]


def read_vulnerabilities(fh: Any) -> Dict[str, Any]:
    """
    Reads vulnerabilities from a file handle.

    Args:
        fh (Any): The file handle.

    Returns:
        Dict[str, Any]: The vulnerabilities data.
    """
    try:
        data = json.load(fh)
    except json.JSONDecodeError as e:
        raise MalformedDatabase(reason=e, fetched_from=fh.name)
    except TypeError as e:
        raise MalformedDatabase(reason=e, fetched_from=fh.name)

    return data


def get_server_policies(
    session: requests.Session,
    policy_file: SafetyPolicyFile,
    proxy_dictionary: Dict[str, str]
) -> tuple:
    """
    Retrieves the server policies.

    Args:
        session (requests.Session): The requests session.
        policy_file (SafetyPolicyFile): The policy file.
        proxy_dictionary (Dict[str, str]): The proxy dictionary.

    Returns:
        tuple: A tuple containing the policy file and the audit and monitor flag.
    """
    if session.api_key:
        server_policies = fetch_policy(session)
        server_audit_and_monitor = server_policies["audit_and_monitor"]
        server_safety_policy = server_policies["safety_policy"]
    else:
        server_audit_and_monitor = False
        server_safety_policy = ""

    if server_safety_policy and policy_file:
        click.secho(
            "Warning: both a local policy file '{policy_filename}' and a server sent policy are present. "
            "Continuing with the local policy file.".format(policy_filename=policy_file['filename']),
            fg="yellow",
            file=sys.stderr
        )
    elif server_safety_policy:
        with tempfile.NamedTemporaryFile(prefix='server-safety-policy-') as tmp:
            tmp.write(server_safety_policy.encode('utf-8'))
            tmp.seek(0)

            policy_file = SafetyPolicyFile().convert(tmp.name, param=None, ctx=None)
            LOG.info('Using server side policy file')

    return policy_file, server_audit_and_monitor


def save_report(
    path: str,
    default_name: str,
    report: str
) -> None:
    """
    Saves the report to a file.

    Args:
        path (str): The path to save the report.
        default_name (str): The default name of the report file.
        report (str): The report content.
    """
    if path:
        save_at = path

        if os.path.isdir(path):
            save_at = os.path.join(path, default_name)

        with open(save_at, 'w+') as report_file:
            report_file.write(report)
