# -*- coding: utf-8 -*-
import platform
import sys
import json
import os
import textwrap

from packaging.version import parse as parse_version
from .util import RequirementFile, get_license_name_by_id

# python 2.7 compat
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

try:
    system = platform.system()
    python_version = ".".join([str(i) for i in sys.version_info[0:2]])
    # get_terminal_size exists on Python 3.4 but isn't working on windows
    if system == "Windows" and python_version in ["3.4"]:
        raise ImportError
    from shutil import get_terminal_size
except ImportError:
    # fallback for python < 3
    import subprocess
    from collections import namedtuple

    def get_terminal_size():
        size = namedtuple("_", ["rows", "columns"])
        try:
            rows, columns = subprocess.check_output(
                ['stty', 'size'],
                stderr=subprocess.STDOUT
            ).split()
            return size(rows=int(rows), columns=int(columns))
        # this won't work
        # - on windows (FileNotFoundError/OSError)
        # - python 2.6 (AttributeError)
        # - if the output is somehow mangled (ValueError)
        except (ValueError, FileNotFoundError, OSError,
                AttributeError, subprocess.CalledProcessError):
            return size(rows=0, columns=0)


def get_advisory(vuln):
    return vuln.advisory if vuln.advisory else "No advisory found for this vulnerability."


class SheetReport(object):
    REPORT_BANNER = r"""
+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
    """.strip()

    TABLE_HEADING = r"""
+============================+===========+==========================+==========+
| package                    | installed | affected                 | ID       |
+============================+===========+==========================+==========+
    """.strip()

    TABLE_HEADING_LICENSES = r"""
+=========================================================+====================+
| package                                                 | license            |
+=========================================================+====================+
    """.strip()

    REPORT_HEADING = r"""
| REPORT                                                                       |
    """.strip()

    REPORT_SECTION = r"""
+==============================================================================+
    """.strip()

    REPORT_FOOTER = r"""
+==============================================================================+
    """.strip()

    @staticmethod
    def render(vulns, full, checked_packages, used_db):
        db_format_str = '{: <' + str(51 - len(str(checked_packages))) + '}'
        status = "| checked {packages} packages, using {db} |".format(
            packages=checked_packages,
            db=db_format_str.format(used_db),
            section=SheetReport.REPORT_SECTION
        )
        if vulns:
            table = []
            for n, vuln in enumerate(vulns):
                table.append("| {:26} | {:9} | {:24} | {:8} |".format(
                    vuln.name[:26],
                    vuln.version[:9],
                    vuln.spec[:24],
                    vuln.vuln_id
                ))
                if full:
                    table.append(SheetReport.REPORT_SECTION)

                    descr = get_advisory(vuln)

                    for pn, paragraph in enumerate(descr.replace('\r', '').split('\n\n')):
                        if pn:
                            table.append("| {:76} |".format(''))
                        for line in textwrap.wrap(paragraph, width=76):
                            try:
                                table.append("| {:76} |".format(line.encode('utf-8')))
                            except TypeError:
                                table.append("| {:76} |".format(line))
                    # append the REPORT_SECTION only if this isn't the last entry
                    if n + 1 < len(vulns):
                        table.append(SheetReport.REPORT_SECTION)
            return "\n".join(
                [SheetReport.REPORT_BANNER, SheetReport.REPORT_HEADING, status, SheetReport.TABLE_HEADING,
                 "\n".join(table), SheetReport.REPORT_FOOTER]
            )
        else:
            content = "| {:76} |".format("No known security vulnerabilities found.")
            return "\n".join(
                    [SheetReport.REPORT_BANNER, SheetReport.REPORT_HEADING, status, SheetReport.REPORT_SECTION,
                     content, SheetReport.REPORT_FOOTER]
                )

    @staticmethod
    def render_licenses(packages, licenses):
        heading = SheetReport.REPORT_HEADING.replace(" ", "", 12).replace(
            "REPORT", " Packages licenses"
        )
        if not licenses:
            content = "| {:76} |".format("No packages licenses found.")
            return "\n".join(
                    [SheetReport.REPORT_BANNER, heading, SheetReport.REPORT_SECTION,
                     content, SheetReport.REPORT_FOOTER]
                )

        table = []
        iteration = 1
        for package, license in licenses.items():
            max_char = last_char = 55  # defines a limit for package name.
            current_line = 1
            license_line = int(int(len(package) / max_char) / 2) + 1  # Calc to get which line to add the license info.

            table.append("| {:55} | {:18} |".format(
                package[:max_char],
                license[:18] if current_line == license_line else "",
            ))

            long_name = True if len(package[max_char:]) > 0 else False
            while long_name:  # If the package has a long name, break it into multiple lines.
                current_line += 1
                table.append("| {:55} | {:18} |".format(
                    package[last_char:last_char+max_char],
                    license[:18] if current_line == license_line else "",
                ))
                last_char = last_char+max_char
                long_name = True if len(package[last_char:]) > 0 else False

            if iteration != len(licenses):  # Do not add dashes "----" for last package.
                table.append("|" + ("-" * 78) + "|")
            iteration += 1
        return "\n".join(
            [SheetReport.REPORT_BANNER, heading, SheetReport.TABLE_HEADING_LICENSES,
                "\n".join(table), SheetReport.REPORT_FOOTER]
        )

class BasicReport(object):
    """Basic report, intented to be used for terminals with < 80 columns"""

    @staticmethod
    def render(vulns, full, checked_packages, used_db):
        table = [
            "safety report",
            "checked {packages} packages, using {db}".format(
                packages=checked_packages,
                db=used_db
            ),
            "---"
        ]
        if vulns:

            for vuln in vulns:
                table.append("-> {}, installed {}, affected {}, id {}".format(
                    vuln.name,
                    vuln.version[:13],
                    vuln.spec[:27],
                    vuln.vuln_id
                ))
                if full:
                    table.append(get_advisory(vuln))
                    table.append("--")
        else:
            table.append("No known security vulnerabilities found.")
        return "\n".join(
            table
        )

    @staticmethod
    def render_licenses(packages, licenses):
        table = [
            "safety",
            "packages licenses",
            "---"
        ]
        if not licenses:
            table.append("No packages licenses found.")
            return "\n".join(table)
        
        for package, license in licenses.items():
            table.append(package + ": " + license + "\n")
        
        return "\n".join(table)

class JsonReport(object):
    """Json report, for when the output is input for something else"""

    @staticmethod
    def render(vulns, full):
        return json.dumps(vulns, indent=4, sort_keys=True)


class BareReport(object):
    """Bare report, for command line tools"""
    @staticmethod
    def render(vulns, full):
        return " ".join(set([v.name for v in vulns]))


def get_used_db(key, db):
    key = key if key else os.environ.get("SAFETY_API_KEY", False)
    if key:
        return "pyup.io's DB"
    if db == '':
        return 'default DB'
    return "local DB"


def report(vulns, full=False, json_report=False, bare_report=False, checked_packages=0, db=None, key=None):
    if bare_report:
        return BareReport.render(vulns, full=full)
    if json_report:
        return JsonReport.render(vulns, full=full)
    size = get_terminal_size()
    used_db = get_used_db(key=key, db=db)
    if size.columns >= 80:
        return SheetReport.render(vulns, full=full, checked_packages=checked_packages, used_db=used_db)
    return BasicReport.render(vulns, full=full, checked_packages=checked_packages, used_db=used_db)


def license_report(packages, licenses_db):
    size = get_terminal_size()
    packages_licenses = licenses_db.get('packages', {})
    licenses = {}
    import pdb; pdb.set_trace()
    for pkg in packages:
        # Ignore recursive files not resolved
        if isinstance(pkg, RequirementFile):
            continue
        # normalize the package name
        pkg_name = pkg.key.replace("_", "-").lower()
        # packages may have different licenses depending their version.
        pkg_licenses = packages_licenses.get(pkg_name, [])
        version_requested = parse_version(pkg.version)
        license_id = None
        license_name = None
        for pkg_version in pkg_licenses:
            license_start_version = parse_version(pkg_version['start_version'])
            # Stops and return the previous stored license when a new
            # license starts on a version above the requested one.
            if version_requested >= license_start_version:
                license_id = pkg_version['license_id']
            else:
                # We found the license for the version requested
                break
        if license_id:
            license_name = get_license_name_by_id(license_id, licenses_db)
        if not license_id or not license_name:
            license_name = "N/A"
        
        # TODO: Add pkg version to the report table
        # licenses[pkg_name] = {
        #     "version": pkg.version,
        #     "license_name": license_name
        # }
        licenses[pkg_name] = license_name
    if size.columns >= 80:
        return SheetReport.render_licenses(packages, licenses)
    return BasicReport.render_licenses(packages, licenses)
