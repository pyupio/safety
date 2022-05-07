# -*- coding: utf-8 -*-
import errno
import itertools
import json
import logging
import os
import sys
import time
from datetime import datetime

import click
import requests
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version, Version, LegacyVersion, parse

from .constants import (API_MIRRORS, CACHE_FILE, CACHE_LICENSES_VALID_SECONDS, CACHE_VALID_SECONDS, OPEN_MIRRORS,
                        REQUEST_TIMEOUT, API_BASE_URL)
from .errors import (DatabaseFetchError, DatabaseFileNotFoundError,
                     InvalidKeyError, TooManyRequestsError, NetworkConnectionError,
                     RequestTimeoutError, ServerError, MalformedDatabase)
from .models import Vulnerability, CVE
from .util import RequirementFile, read_requirements, Package, build_telemetry_data

session = requests.session()

LOG = logging.getLogger(__name__)


def get_from_cache(db_name):
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            try:
                data = json.loads(f.read())
                if db_name in data:
                    if "cached_at" in data[db_name]:
                        if 'licenses.json' in db_name:
                            # Getting the specific cache time for the licenses db.
                            cache_valid_seconds = CACHE_LICENSES_VALID_SECONDS
                        else:
                            cache_valid_seconds = CACHE_VALID_SECONDS

                        if data[db_name]["cached_at"] + cache_valid_seconds > time.time():
                            return data[db_name]["db"]
            except json.JSONDecodeError:
                pass
    return False


def write_to_cache(db_name, data):
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
    if not os.path.exists(os.path.dirname(CACHE_FILE)):
        try:
            os.makedirs(os.path.dirname(CACHE_FILE))
            with open(CACHE_FILE, "w") as _:
                _.write(json.dumps({}))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    with open(CACHE_FILE, "w+") as f:
        try:
            cache = json.loads(f.read())
        except json.JSONDecodeError:
            cache = {}

    with open(CACHE_FILE, "w") as f:
        cache[db_name] = {
            "cached_at": time.time(),
            "db": data
        }
        f.write(json.dumps(cache))


def fetch_database_url(mirror, db_name, key, cached, proxy, telemetry=True):
    headers = {}
    if key:
        headers["X-Api-Key"] = key

    if cached:
        cached_data = get_from_cache(db_name=db_name)
        if cached_data:
            return cached_data
    url = mirror + db_name

    telemetry_data = {'telemetry': json.dumps(build_telemetry_data(telemetry=telemetry))}

    try:
        r = session.get(url=url, timeout=REQUEST_TIMEOUT, headers=headers, proxies=proxy, params=telemetry_data)
    except requests.exceptions.ConnectionError:
        raise NetworkConnectionError()
    except requests.exceptions.Timeout:
        raise RequestTimeoutError()
    except requests.exceptions.RequestException:
        raise DatabaseFetchError()

    if r.status_code == 403:
        raise InvalidKeyError(key=key)

    if r.status_code == 429:
        raise TooManyRequestsError()

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


def fetch_database_file(path, db_name):
    full_path = os.path.join(path, db_name)
    if not os.path.exists(full_path):
        raise DatabaseFileNotFoundError(db=path)
    with open(full_path) as f:
        return json.loads(f.read())


def fetch_database(full=False, key=False, db=False, cached=False, proxy={}, telemetry=True):
    if db:
        mirrors = [db]
    else:
        mirrors = API_MIRRORS if key else OPEN_MIRRORS

    db_name = "insecure_full.json" if full else "insecure.json"
    for mirror in mirrors:
        # mirror can either be a local path or a URL
        if mirror.startswith("http://") or mirror.startswith("https://"):
            data = fetch_database_url(mirror, db_name=db_name, key=key, cached=cached, proxy=proxy, telemetry=telemetry)
        else:
            data = fetch_database_file(mirror, db_name=db_name)
        if data:
            return data
    raise DatabaseFetchError()


def get_vulnerabilities(pkg, spec, db):
    for entry in db[pkg]:
        for entry_spec in entry["specs"]:
            if entry_spec == spec:
                yield entry


def get_vulnerability_from(vuln_id, cve, data, specifier, db, name, pkg, ignore_vulns):
    base_domain = db.get('$meta', {}).get('base_domain')
    pkg_meta = db.get('$meta', {}).get('packages', {}).get(name, {})
    insecure_versions = pkg_meta.get("insecure_versions", [])
    secure_versions = pkg_meta.get("secure_versions", [])
    latest_version_without_known_vulnerabilities = pkg_meta.get("latest_secure_version", None)
    latest_version = pkg_meta.get("latest_version", None)
    pkg_refreshed = pkg._replace(insecure_versions=insecure_versions, secure_versions=secure_versions,
                                 latest_version_without_known_vulnerabilities=latest_version_without_known_vulnerabilities,
                                 latest_version=latest_version,
                                 more_info_url=f"{base_domain}{pkg_meta.get('more_info_path', '')}")

    ignored = (vuln_id in ignore_vulns and (not ignore_vulns[vuln_id]['expires'] or ignore_vulns[vuln_id]['expires'] > datetime.utcnow()))
    more_info_url = f"{base_domain}{data.get('more_info_path', '')}"

    return Vulnerability(
        name=name,
        pkg=pkg_refreshed,
        ignored=ignored,
        reason=ignore_vulns.get(vuln_id, {}).get('reason', ''),
        expires=ignore_vulns.get(vuln_id, {}).get('expires', ''),
        vulnerable_spec=specifier,
        all_vulnerable_specs=data.get("specs", []),
        analyzed_version=pkg_refreshed.version,
        advisory=data.get("advisory"),
        vulnerability_id=vuln_id,
        is_transitive=data.get("transitive", False),
        published_date=data.get("published_date"),
        fixed_versions=data.get("fixed_versions"),
        closest_versions_without_known_vulnerabilities=data.get("closest_secure_versions", []),
        resources=data.get("vulnerability_resources"),
        CVE=cve,
        affected_versions=data.get("affected_versions", []),
        more_info_url=more_info_url
    )


def get_cve_from(data, db_full):
    cve_id = data.get("cve", '').split(",")[0].strip()
    cve_meta = db_full.get("$meta", {}).get("cve", {}).get(cve_id, {})
    return CVE(name=cve_id, cvssv2=cve_meta.get("cvssv2", None), cvssv3=cve_meta.get("cvssv3", None))


def ignore_vuln_if_needed(vuln_id, cve, ignore_vulns, ignore_severity_rules):

    if not ignore_severity_rules:
        return

    severity = None

    if cve.cvssv2 and cve.cvssv2.get("base_score", None):
        severity = cve.cvssv2.get("base_score", None)

    if cve.cvssv3 and cve.cvssv3.get("base_score", None):
        severity = cve.cvssv3.get("base_score", None)

    ignore_severity_below = float(ignore_severity_rules.get('ignore-cvss-severity-below', 0.0))
    ignore_unknown_severity = bool(ignore_severity_rules.get('ignore-cvss-unknown-severity', False))

    if severity:
        if float(severity) < ignore_severity_below:
            reason = 'Ignored by severity rule in policy file, {0} < {1}'.format(float(severity),
                                                                                  ignore_severity_below)
            ignore_vulns[vuln_id] = {'reason': reason, 'expires': None}
    elif ignore_unknown_severity:
        reason = 'Unknown CVSS severity, ignored by severity rule in policy file.'
        ignore_vulns[vuln_id] = {'reason': reason, 'expires': None}


def check(packages, key, db_mirror, cached, ignore_vulns, ignore_severity_rules, proxy, include_ignored=False,
          is_env_scan=True, telemetry=True):
    key = key if key else os.environ.get("SAFETY_API_KEY", False)
    db = fetch_database(key=key, db=db_mirror, cached=cached, proxy=proxy, telemetry=telemetry)
    db_full = None
    vulnerable_packages = frozenset(db.keys())
    vulnerabilities = []

    for pkg in packages:
        # Ignore recursive files not resolved
        if isinstance(pkg, RequirementFile):
            continue

        # normalize the package name, the safety-db is converting underscores to dashes and uses
        # lowercase
        name = canonicalize_name(pkg.name)

        if name in vulnerable_packages:
            # we have a candidate here, build the spec set
            for specifier in db[name]:
                spec_set = SpecifierSet(specifiers=specifier)
                if spec_set.contains(pkg.version):
                    if not db_full:
                        db_full = fetch_database(full=True, key=key, db=db_mirror, cached=cached, proxy=proxy,
                                                 telemetry=telemetry)
                    for data in get_vulnerabilities(pkg=name, spec=specifier, db=db_full):
                        vuln_id = data.get("id").replace("pyup.io-", "")
                        cve = get_cve_from(data, db_full)

                        ignore_vuln_if_needed(vuln_id, cve, ignore_vulns, ignore_severity_rules)

                        vulnerability = get_vulnerability_from(vuln_id, cve, data, specifier, db, name, pkg,
                                                               ignore_vulns)

                        should_add_vuln = not (vulnerability.is_transitive and is_env_scan)

                        if (include_ignored or vulnerability.vulnerability_id not in ignore_vulns) and should_add_vuln:
                            vulnerabilities.append(vulnerability)

    return vulnerabilities, db_full


def precompute_remediations(remediations, package_metadata, vulns,
                            ignored_vulns):
    for vuln in vulns:
        if vuln.ignored:
            ignored_vulns.add(vuln.vulnerability_id)
            continue

        if vuln.name in remediations.keys():
            remediations[vuln.name]['vulns_found'] = remediations[vuln.name].get('vulns_found', 0) + 1
        else:
            vulns_count = 1
            package_metadata[vuln.name] = {'insecure_versions': vuln.pkg.insecure_versions,
                                           'secure_versions': vuln.pkg.secure_versions, 'version': vuln.pkg.version}
            remediations[vuln.name] = {'vulns_found': vulns_count, 'version': vuln.pkg.version,
                                       'more_info_url': vuln.pkg.more_info_url}


def get_closest_ver(versions, version):
    results = {'minor': None, 'major': None}
    if not version or not versions:
        return results

    sorted_versions = sorted(versions, key=lambda ver: parse_version(ver), reverse=True)

    for v in sorted_versions:
        index = parse_version(v)
        current_v = parse_version(version)

        if index > current_v:
            results['major'] = index

        if index < current_v:
            results['minor'] = index
            break

    return results


def compute_sec_ver_for_user(package, ignored_vulns, db_full):
    pkg_meta = db_full.get('$meta', {}).get('packages', {}).get(package, {})
    versions = set(pkg_meta.get("insecure_versions", []) + pkg_meta.get("secure_versions", []))
    affected_versions = []

    for vuln in db_full.get(package, []):
        vuln_id = vuln.get('id', None)
        if vuln_id and vuln_id not in ignored_vulns:
            affected_versions += vuln.get('affected_versions', [])

    affected_v = set(affected_versions)
    sec_ver_for_user = list(versions.difference(affected_v))

    return sorted(sec_ver_for_user, key=lambda ver: parse_version(ver), reverse=True)


def compute_sec_ver(remediations, package_metadata, ignored_vulns, db_full):
    """
    Compute the secure_versions and the closest_secure_version for each remediation using the affected_versions
    of each no ignored vulnerability of the same package, there is only a remediation for each package.
    """
    for pkg_name in remediations.keys():
        pkg = package_metadata.get(pkg_name, {})

        if not ignored_vulns:
            secure_v = pkg.get('secure_versions', [])
        else:
            secure_v = compute_sec_ver_for_user(package=pkg_name, ignored_vulns=ignored_vulns, db_full=db_full)

        remediations[pkg_name]['secure_versions'] = secure_v
        remediations[pkg_name]['closest_secure_version'] = get_closest_ver(secure_v,
                                                                           pkg.get('version', None))


def calculate_remediations(vulns, db_full):
    remediations = {}
    package_metadata = {}
    ignored_vulns = set()

    if not db_full:
        return remediations

    precompute_remediations(remediations, package_metadata, vulns, ignored_vulns)
    compute_sec_ver(remediations, package_metadata, ignored_vulns, db_full)

    return remediations


def review(report):
    vulnerable = []
    vulnerabilities = report.get('vulnerabilities', []) + report.get('ignored_vulnerabilities', [])
    remediations = {}

    for key, value in report.get('remediations', {}).items():
        recommended = value.get('recommended', None)
        secure_v = value.get('other_recommended_versions', [])
        major = None
        if recommended:
            secure_v.append(recommended)
            major = parse(recommended)

        remediations[key] = {'vulns_found': value.get('vulns_found', 0),
                             'version': value.get('version'),
                             'secure_versions': secure_v,
                             'closest_secure_version': {'major': major, 'minor': None},
                             # minor isn't supported in review
                             'more_info_url': value.get('more_info_url')}

    packages = report.get('scanned_packages', [])
    pkgs = {pkg_name: Package(**pkg_values) for pkg_name, pkg_values in packages.items()}
    click.get_current_context().obj = pkgs.values()
    click.get_current_context().review = report.get('report', [])

    for vuln in vulnerabilities:
        vuln['pkg'] = pkgs.get(vuln.get('name', None))
        CVE_ID = vuln.get('CVE', {}).get('name', None)
        vuln['CVE'] = CVE(name=CVE_ID, cvssv2=vuln.get('cvssv2', None),
                          cvssv3=vuln.get('cvssv3', None)) if CVE_ID else None

        vulnerable.append(Vulnerability(**vuln))

    return vulnerable, remediations, pkgs


def get_licenses(key, db_mirror, cached, proxy, telemetry=True):
    key = key if key else os.environ.get("SAFETY_API_KEY", False)

    if not key and not db_mirror:
        raise InvalidKeyError(message="The API-KEY was not provided.")
    if db_mirror:
        mirrors = [db_mirror]
    else:
        mirrors = API_MIRRORS

    db_name = "licenses.json"

    for mirror in mirrors:
        # mirror can either be a local path or a URL
        if mirror.startswith("http://") or mirror.startswith("https://"):
            licenses = fetch_database_url(mirror, db_name=db_name, key=key, cached=cached, proxy=proxy,
                                          telemetry=telemetry)
        else:
            licenses = fetch_database_file(mirror, db_name=db_name)
        if licenses:
            return licenses
    raise DatabaseFetchError()


def get_announcements(key, proxy, telemetry=True):
    LOG.info('Getting announcements')

    body = build_telemetry_data(telemetry=telemetry)

    announcements = []
    headers = {}

    if key:
        headers["X-Api-Key"] = key

    url = "{API_BASE_URL}{endpoint}".format(API_BASE_URL=API_BASE_URL, endpoint='announcements/')

    LOG.debug(f'Telemetry body sent: {body}')

    try:
        r = session.post(url=url, json=body, headers=headers, timeout=2, proxies=proxy)
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


def get_packages(files=False, stdin=False):

    if files:
        return list(itertools.chain.from_iterable(read_requirements(f, resolve=True) for f in files))

    if stdin:
        return list(read_requirements(sys.stdin))

    import pkg_resources

    return [
        Package(name=d.key, version=d.version, found=d.location, insecure_versions=[], secure_versions=[],
                latest_version=None, latest_version_without_known_vulnerabilities=None, more_info_url=None) for d in
        pkg_resources.working_set
        if d.key not in {"python", "wsgiref", "argparse"}
    ]


def read_vulnerabilities(fh):
    try:
        data = json.load(fh)
    except json.JSONDecodeError as e:
        raise MalformedDatabase(reason=e, fetched_from=fh.name)
    except TypeError as e:
        raise MalformedDatabase(reason=e, fetched_from=fh.name)

    return data
