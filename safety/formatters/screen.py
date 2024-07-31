import click

from safety.formatter import FormatterAPI
from safety.output_utils import build_announcements_section_content, format_long_text, \
    add_empty_line, format_vulnerability, get_final_brief, \
    build_report_brief_section, format_license, get_final_brief_license, build_remediation_section, \
    build_primary_announcement, get_specifier_range_info, format_unpinned_vulnerabilities
from safety.util import get_primary_announcement, get_basic_announcements, get_terminal_size, \
    is_ignore_unpinned_mode
from collections import defaultdict
from typing import List, Dict, Any, Tuple

class ScreenReport(FormatterAPI):
    DIVIDER_SECTIONS = '+' + '=' * (get_terminal_size().columns - 2) + '+'

    REPORT_BANNER = DIVIDER_SECTIONS + '\n' + r"""
                               /$$$$$$            /$$
                              /$$__  $$          | $$
           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$
          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$
         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$
          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$
          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$
         |_______/  \_______/|__/     \_______/   \___/   \____  $$
                                                          /$$  | $$
                                                         |  $$$$$$/
  by safetycli.com                                        \______/

""" + DIVIDER_SECTIONS

    ANNOUNCEMENTS_HEADING = format_long_text(click.style('ANNOUNCEMENTS', bold=True))

    def __build_announcements_section(self, announcements: List[Dict]) -> List[str]:
        """
        Build the announcements section of the report.

        Args:
            announcements (List[Dict]): List of announcement dictionaries.

        Returns:
            List[str]: Formatted announcements section.
        """
        announcements_section = []

        basic_announcements = get_basic_announcements(announcements)

        if basic_announcements:
            announcements_content = build_announcements_section_content(basic_announcements)
            announcements_section = [add_empty_line(), self.ANNOUNCEMENTS_HEADING, add_empty_line(),
                                     announcements_content, add_empty_line(), self.DIVIDER_SECTIONS]

        return announcements_section

    def render_vulnerabilities(self, announcements: List[Dict], vulnerabilities: List[Dict], remediations: Dict[str, Any],
                               full: bool, packages: List[Dict], fixes: Tuple = ()) -> str:
        """
        Render the vulnerabilities section of the report.

        Args:
            announcements (List[Dict]): List of announcement dictionaries.
            vulnerabilities (List[Dict]): List of vulnerability dictionaries.
            remediations (Dict[str, Any]): Remediation data.
            full (bool): Flag indicating full report.
            packages (List[Dict]): List of package dictionaries.
            fixes (Tuple, optional): Iterable of fixes.

        Returns:
            str: Rendered vulnerabilities report.
        """
        announcements_section = self.__build_announcements_section(announcements)
        primary_announcement = get_primary_announcement(announcements)
        remediation_section = build_remediation_section(remediations)
        end_content = []

        if primary_announcement:
            end_content = [add_empty_line(),
                           build_primary_announcement(primary_announcement, columns=get_terminal_size().columns),
                           self.DIVIDER_SECTIONS]

        table = []
        ignored = {}
        total_ignored = 0

        unpinned_packages = defaultdict(list)
        styled_vulns = []

        for n, vuln in enumerate(vulnerabilities):
            if vuln.ignored:
                total_ignored += 1
                ignored[vuln.package_name] = ignored.get(vuln.package_name, 0) + 1
                if is_ignore_unpinned_mode(version=vuln.analyzed_version) and not full:
                    unpinned_packages[vuln.package_name].append(vuln)
                    continue
            styled_vulns.append(format_vulnerability(vuln, full))

        table.extend(format_unpinned_vulnerabilities(unpinned_packages))
        table.extend(styled_vulns)

        report_brief_section = build_report_brief_section(primary_announcement=primary_announcement, report_type=1,
                                                          vulnerabilities_found=max(0, len(vulnerabilities)-total_ignored),
                                                          vulnerabilities_ignored=total_ignored,
                                                          remediations_recommended=remediations)

        if vulnerabilities:
            # Add a space between warning and brief, when all the vulnerabilities are ignored.
            if not styled_vulns:
                table.append('')

            final_brief = get_final_brief(len(vulnerabilities), remediations, ignored, total_ignored)

            return "\n".join(
                [ScreenReport.REPORT_BANNER] + announcements_section + [report_brief_section,
                                                                        add_empty_line(),
                                                                        self.DIVIDER_SECTIONS,
                                                                        format_long_text(
                                                                            click.style('VULNERABILITIES REPORTED',
                                                                                        bold=True)),
                                                                        self.DIVIDER_SECTIONS,
                                                                        add_empty_line(),
                                                                        "\n\n".join(table),
                                                                        add_empty_line(),
                                                                        self.DIVIDER_SECTIONS] +
                remediation_section + ['', final_brief, '', self.DIVIDER_SECTIONS] + end_content
            )
        else:
            content = format_long_text(click.style("No known security vulnerabilities reported.", bold=True, fg='green'))
            return "\n".join(
                [ScreenReport.REPORT_BANNER] + announcements_section + [report_brief_section,
                                                                        self.DIVIDER_SECTIONS,
                                                                        add_empty_line(),
                                                                        content,
                                                                        add_empty_line(),
                                                                        self.DIVIDER_SECTIONS] +
                end_content
            )

    def render_licenses(self, announcements: List[Dict], licenses: List[Dict]) -> str:
        """
        Render the licenses section of the report.

        Args:
            announcements (List[Dict]): List of announcement dictionaries.
            licenses (List[Dict]): List of license dictionaries.

        Returns:
            str: Rendered licenses report.
        """
        unique_license_types = set([lic['license'] for lic in licenses])

        report_brief_section = build_report_brief_section(primary_announcement=get_primary_announcement(announcements),
                                                          report_type=2, licenses_found=len(unique_license_types))
        announcements_section = self.__build_announcements_section(announcements)

        if not licenses:
            content = format_long_text(click.style("No packages licenses found.", bold=True, fg='red'))
            return "\n".join(
                [ScreenReport.REPORT_BANNER] + announcements_section + [report_brief_section,
                                                                        self.DIVIDER_SECTIONS,
                                                                        add_empty_line(),
                                                                        content,
                                                                        add_empty_line(),
                                                                        self.DIVIDER_SECTIONS]
            )

        table = []
        for license in licenses:
            table.append(format_license(license))

        final_brief = get_final_brief_license(unique_license_types)

        return "\n".join(
            [ScreenReport.REPORT_BANNER] + announcements_section + [report_brief_section,
                                                                    add_empty_line(),
                                                                    self.DIVIDER_SECTIONS,
                                                                    format_long_text(
                                                                        click.style('LICENSES FOUND',
                                                                                    bold=True, fg='yellow')),
                                                                    self.DIVIDER_SECTIONS,
                                                                    add_empty_line(),
                                                                    "\n".join(table),
                                                                    final_brief,
                                                                    add_empty_line(),
                                                                    self.DIVIDER_SECTIONS]
        )

    def render_announcements(self, announcements: List[Dict]) -> List[str]:
        """
        Render the announcements section of the report.

        Args:
            announcements (List[Dict]): List of announcement dictionaries.

        Returns:
            str: Rendered announcements section.
        """
        return self.__build_announcements_section(announcements)



