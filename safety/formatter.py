# -*- coding: utf-8 -*-
import platform
import sys

# python 2.7 compat
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

try:
    system = platform.system()
    python_version = ".".join([str(i) for i in sys.version_info[0:2]])
    # get_terminal_size exists on Python 3.3 and 3.4 but isn't working on windows
    if system == "Windows" and python_version in ["3.3", "3.4"]:
        raise ImportError
    from shutil import get_terminal_size
except ImportError:
    # fallback for python < 3
    import subprocess
    from collections import namedtuple

    def get_terminal_size():
        size = namedtuple("_", ["rows", "columns"])
        try:
            rows, columns = subprocess.check_output(['stty', 'size']).split()
            return size(rows=int(rows), columns=int(columns))
        # this won't work
        # - on windows (FileNotFoundError)
        # - python 2.6 (AttributeError)
        # - if the output is somehow mangled (ValueError)
        except (ValueError, FileNotFoundError, AttributeError):
            return size(rows=0, columns=0)


def get_advisory(vuln):
    return vuln.advisory if vuln.advisory else "No advisory found for this vulnerability."


class SheetReport(object):
    REPORT_BANNER = """
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                              │
│                               /$$$$$$            /$$                         │
│                              /$$__  $$          | $$                         │
│           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           │
│          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           │
│         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           │
│          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           │
│          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           │
│         |_______/  \_______/|__/     \_______/   \___/   \____  $$           │
│                                                          /$$  | $$           │
│                                                         |  $$$$$$/           │
│  by pyup.io                                              \______/            │
│                                                                              │
╞══════════════════════════════════════════════════════════════════════════════╡
    """.strip()

    TABLE_HEADING = """
╞════════════════════════════════╤═══════════════╤═════════════════════════════╡
│ package                        │ installed     │ affected                    │
╞════════════════════════════════╧═══════════════╧═════════════════════════════╡
    """.strip()

    TABLE_FOOTER = """
╘════════════════════════════════╧═══════════════╧═════════════════════════════╛
    """.strip()

    TABLE_BREAK = """
╞════════════════════════════════╡═══════════════╡═════════════════════════════╡
    """.strip()

    REPORT_HEADING = """
│ REPORT                                                                       │
    """.strip()

    REPORT_SECTION = """
╞══════════════════════════════════════════════════════════════════════════════╡
    """.strip()

    REPORT_FOOTER = """
╘══════════════════════════════════════════════════════════════════════════════╛
    """.strip()

    @staticmethod
    def render(vulns, full):
        if vulns:
            table = []
            for n, vuln in enumerate(vulns):
                table.append("│ {:30} │ {:13} │ {:27} │".format(
                    vuln.name[:30],
                    vuln.version[:13],
                    vuln.spec[:27]
                ))
                if full:
                    table.append(SheetReport.REPORT_SECTION)

                    descr = get_advisory(vuln)

                    for chunk in [descr[i:i + 76] for i in range(0, len(descr), 76)]:

                        for line in chunk.splitlines():
                            table.append("│ {:76} │".format(line))
                    # append the REPORT_SECTION only if this isn't the last entry
                    if n + 1 < len(vulns):
                        table.append(SheetReport.REPORT_SECTION)
            table = "\n".join(table)
            return "\n".join(
                [SheetReport.REPORT_BANNER, SheetReport.REPORT_HEADING, SheetReport.TABLE_HEADING,
                 table, SheetReport.REPORT_FOOTER]
            )
        else:
            content = "│ {:76} │".format("No known security vulnerabilities found.")
            return "\n".join(
                [SheetReport.REPORT_BANNER, SheetReport.REPORT_HEADING, SheetReport.REPORT_SECTION,
                 content, SheetReport.REPORT_FOOTER]
            )


class BasicReport(object):
    """Basic report, intented to be used for terminals with < 80 columns"""

    @staticmethod
    def render(vulns, full):
        table = ["safety report", "---"]
        if vulns:

            for vuln in vulns:
                table.append("-> {}, installed {}, affected {}".format(
                    vuln.name,
                    vuln.version[:13],
                    vuln.spec[:27]
                ))
                if full:
                    table.append(get_advisory(vuln))
                    table.append("--")
        else:
            table.append("No known security vulnerabilities found.")
        return "\n".join(
            table
        )


def report(vulns, full=False):
    size = get_terminal_size()
    if size.columns >= 80:
        return SheetReport.render(vulns, full=full)
    return BasicReport.render(vulns, full=full)
