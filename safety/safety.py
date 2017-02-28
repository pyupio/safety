# -*- coding: utf-8 -*-
import click
import pip
import requests
from packaging.specifiers import SpecifierSet
from .errors import DatabaseFetchError
from .constants import DATABASE_MIRRORS, REQUEST_TIMEOUT
from collections import namedtuple


class Vulnerability(namedtuple("Vulnerability", ["name", "spec", "version"])):
    pass


def fetch_database(full=False):
    for mirror in DATABASE_MIRRORS:
        db_name = "insecure_full.json" if full else "insecure.json"
        url = mirror + db_name
        r = requests.get(url=url, timeout=REQUEST_TIMEOUT)
        return r.json()
    raise DatabaseFetchError()


def get_vulnerabilities(pkg, spec, db):
    for entry in db[pkg]:
        if spec == entry["v"]:
            yield entry


def check(packages):
    db = fetch_database()
    vulnerable_packages = frozenset(db.keys())
    vulnerable = []
    for pkg in packages:
        # normalize the package name, the safety-db is converting underscores to dashes and uses
        # lowercase
        name = pkg.key.replace("_", "-").lower()

        if name in vulnerable_packages:
            # we have a candidate here, build the spec set
            for specifier in db[name]:
                spec_set = SpecifierSet(specifiers=specifier)
                if spec_set.contains(pkg.version):
                    vulnerable.append(
                        Vulnerability(name=name, spec=specifier, version=pkg.version)
                    )
    return vulnerable
