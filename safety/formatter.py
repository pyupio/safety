# -*- coding: utf-8 -*-
try:
    from shutil import get_terminal_size
except ImportError:
    # fallback for python < 3
    import subprocess
    from collections import namedtuple

    def get_terminal_size():
        size = namedtuple("_", "rows", "columns")
        try:
            rows, columns = subprocess.check_output(['stty', 'size']).split()
            return size(rows=int(rows), columns=int(columns))
        except (ValueError, FileNotFoundError):
            return size(rows=0, columns=0)


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
    def render(vulns):
        if vulns:
            table = []
            for vuln in vulns:
                table.append("│ {:30} │ {:13} │ {:27} │".format(
                    vuln.name[:30],
                    vuln.version[:13],
                    vuln.spec[:27]
                ))
            table = "\n".join(table)
            return "\n".join(
                [SheetReport.REPORT_BANNER, SheetReport.REPORT_HEADING, SheetReport.TABLE_HEADING,
                 table, SheetReport.TABLE_FOOTER]
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
    def render(vulns):
        table = ["safety report", "---"]
        if vulns:

            for vuln in vulns:
                table.append("-> {}, installed {}, affected {}".format(
                    vuln.name,
                    vuln.version[:13],
                    vuln.spec[:27]
                ))
        else:
            table.append("No known security vulnerabilities found.")
        return "\n".join(
            table
        )


def report(vulns):
    size = get_terminal_size()
    if size.columns >= 80:
        return SheetReport.render(vulns)
    return BasicReport.render(vulns)
