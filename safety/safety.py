# -*- coding: utf-8 -*-
import click
import pip
import requests
from packaging.specifiers import SpecifierSet
from .errors import DatabaseFetchError
from .constants import DATABASE_MIRRORS, REQUEST_TIMEOUT
from collections import namedtuple


class Vulnerability(namedtuple("Vulnerability", ["name", "spec", "version", "data"])):

    @property
    def source(self):
        return self.cve_id if self.is_cve else "changelog"

    @property
    def is_cve(self):
        return "cve" in self.data

    @property
    def is_changelog(self):
        return "changelog" in self.data

    @property
    def cve_id(self):
        return self.data["cve"]

    @property
    def description(self):
        return self.data["description"] if self.is_cve else self.data["changelog"]


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


def check():
    db = fetch_database()
    db_full = None
    packages = frozenset(db.keys())
    vulnerable = []
    for pkg in pip.get_installed_distributions():
        # normalize the package name, the safety-db is converting underscores to dashes and uses
        # lowercase
        name = pkg.key.replace("_", "-").lower()

        if name in packages:
            # we have a candidate here, build the spec set
            for specifier in db[name]:
                spec_set = SpecifierSet(specifiers=specifier)
                if spec_set.contains(pkg.version):
                    if not db_full:
                        db_full = fetch_database(full=True)
                    for data in get_vulnerabilities(pkg=name, spec=specifier, db=db_full):
                        vulnerable.append(
                            Vulnerability(name=name, spec=specifier, version=pkg.version, data=data)
                        )
    return vulnerable
