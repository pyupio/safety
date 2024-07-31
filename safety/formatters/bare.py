from collections import namedtuple
from typing import List, Dict, Any, Optional, Tuple

from safety.formatter import FormatterAPI
from safety.util import get_basic_announcements


class BareReport(FormatterAPI):
    """
    Bare report, for command line tools.
    """

    def render_vulnerabilities(self, announcements: List[Dict[str, Any]], vulnerabilities: List[Any],
                               remediations: Any, full: bool, packages: List[Any], fixes: Tuple = ()) -> str:
        """
        Renders vulnerabilities in a bare format.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.
            vulnerabilities (List[Any]): List of vulnerabilities.
            remediations (Any): Remediation data.
            full (bool): Flag indicating full output.
            packages (List[Any]): List of packages.
            fixes (Tuple, optional): Tuple of fixes.

        Returns:
            str: Rendered vulnerabilities.
        """
        parsed_announcements = []
        Announcement = namedtuple("Announcement", ["name"])

        for announcement in get_basic_announcements(announcements, include_local=False):
            normalized_message = "-".join(announcement.get('message', 'none').lower().split())
            parsed_announcements.append(Announcement(name=normalized_message))

        announcements_to_render = [announcement.name for announcement in parsed_announcements]
        affected_packages = list(set([v.package_name for v in vulnerabilities if not v.ignored]))

        return " ".join(announcements_to_render + affected_packages)

    def render_licenses(self, announcements: List[Dict[str, Any]], packages_licenses: List[Dict[str, Any]]) -> str:
        """
        Renders licenses in a bare format.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.
            packages_licenses (List[Dict[str, Any]]): List of package licenses.

        Returns:
            str: Rendered licenses.
        """
        parsed_announcements = []

        for announcement in get_basic_announcements(announcements):
            normalized_message = "-".join(announcement.get('message', 'none').lower().split())
            parsed_announcements.append({'license': normalized_message})

        announcements_to_render = [announcement.get('license') for announcement in parsed_announcements]

        licenses = list(set([pkg_li.get('license') for pkg_li in packages_licenses]))
        sorted_licenses = sorted(licenses)
        return " ".join(announcements_to_render + sorted_licenses)

    def render_announcements(self, announcements: List[Dict[str, Any]]) -> None:
        """
        Renders announcements in a bare format.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.
        """
        print('render_announcements bare')
