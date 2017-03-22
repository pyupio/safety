# -*- coding: utf-8 -*-
import click
import pip
import requests
from packaging.specifiers import SpecifierSet
from .errors import DatabaseFetchError, InvalidKeyError, DatabaseFileNotFoundError
from .constants import OPEN_MIRRORS, API_MIRRORS, REQUEST_TIMEOUT
from collections import namedtuple
import os
import json

class Vulnerability(namedtuple("Vulnerability",
                               ["name", "spec", "version", "advisory", "vuln_id"])):
    pass


def fetch_database_url(mirror, db_name, key):
    headers = {}
    if key:
        headers["X-Api-Key"] = key

    url = mirror + db_name
    r = requests.get(url=url, timeout=REQUEST_TIMEOUT, headers=headers)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 403:
        raise InvalidKeyError()


def fetch_database_file(path, db_name):
    full_path = os.path.join(path, db_name)
    if not os.path.exists(full_path):
        raise DatabaseFileNotFoundError()
    with open(full_path) as f:
        return json.loads(f.read())


def fetch_database(full=False, key=False, db=False):

    if db:
        mirrors = [db]
    else:
        mirrors = API_MIRRORS if key else OPEN_MIRRORS

    db_name = "insecure_full.json" if full else "insecure.json"
    for mirror in mirrors:
        # mirror can either be a local path or a URL
        if mirror.startswith("http://") or mirror.startswith("https://"):
            data = fetch_database_url(mirror, db_name=db_name, key=key)
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


def check(packages, key, db_mirror):

    db = fetch_database(key=key, db=db_mirror)
    db_full = None
    vulnerable_packages = frozenset(db.keys())
    vulnerable = []
    found_ids = set()
    for pkg in packages:
        # normalize the package name, the safety-db is converting underscores to dashes and uses
        # lowercase
        name = pkg.key.replace("_", "-").lower()

        if name in vulnerable_packages:
            # we have a candidate here, build the spec set
            for specifier in db[name]:
                spec_set = SpecifierSet(specifiers=specifier)
                if spec_set.contains(pkg.version):
                    if not db_full:
                        db_full = fetch_database(full=True, key=key, db=db_mirror)
                    for data in get_vulnerabilities(pkg=name, spec=specifier, db=db_full):
                        if data.get("id") not in found_ids:
                            vulnerable.append(
                                Vulnerability(
                                    name=name,
                                    spec=specifier,
                                    version=pkg.version,
                                    advisory=data.get("advisory"),
                                    vuln_id=data.get("id")
                                )
                            )
                            found_ids.add(data.get("id"))
    return vulnerable
