# type: ignore
# TODO: Handle typing issues
import logging
import json as json_parser
from collections import defaultdict
from typing import Iterable, List, Dict, Any

from safety.formatter import FormatterAPI
from safety.models import SafetyEncoder
from safety.output_utils import get_report_brief_info
from safety.safety import find_vulnerabilities_fixed
from safety.util import get_basic_announcements, SafetyContext

LOG = logging.getLogger(__name__)


def build_json_report(
    announcements: List[Dict],
    vulnerabilities: List[Dict],
    remediations: Dict[str, Any],
    packages: List[Any],
) -> Dict[str, Any]:
    """
    Build a JSON report for vulnerabilities, remediations, and packages.

    Args:
        announcements (List[Dict]): List of announcements.
        vulnerabilities (List[Dict]): List of vulnerabilities.
        remediations (Dict[str, Any]): Remediation data.
        packages (List[Any]): List of packages.

    Returns:
        Dict[str, Any]: JSON report.
    """
    vulns_ignored = [vuln.to_dict() for vuln in vulnerabilities if vuln.ignored]
    vulns = [vuln.to_dict() for vuln in vulnerabilities if not vuln.ignored]

    report = get_report_brief_info(
        as_dict=True,
        report_type=1,
        vulnerabilities_found=len(vulns),
        vulnerabilities_ignored=len(vulns_ignored),
        remediations_recommended=remediations,
    )

    if "using_sentence" in report:
        del report["using_sentence"]

    remed = {}
    for k, v in remediations.items():
        if k not in remed:
            remed[k] = {"requirements": v}

        remed[k]["current_version"] = None
        remed[k]["vulnerabilities_found"] = None
        remed[k]["recommended_version"] = None
        remed[k]["other_recommended_versions"] = []
        remed[k]["more_info_url"] = None

    return {
        "report_meta": report,
        "scanned_packages": {p.name: p.to_dict(short_version=True) for p in packages},
        "affected_packages": {v.pkg.name: v.pkg.to_dict() for v in vulnerabilities},
        "announcements": [
            {"type": item.get("type"), "message": item.get("message")}
            for item in get_basic_announcements(announcements)
        ],
        "vulnerabilities": vulns,
        "ignored_vulnerabilities": vulns_ignored,
        "remediations": remed,
    }


class JsonReport(FormatterAPI):
    """Json report, for when the output is input for something else"""

    VERSIONS = ("0.5", "1.1")

    def __init__(self, version="1.1", **kwargs):
        """
        Initialize JsonReport with the specified version.

        Args:
            version (str): Report version.
        """
        super().__init__(**kwargs)
        self.version: str = version if version in self.VERSIONS else "1.1"

    def render_vulnerabilities(
        self,
        announcements: List[Dict],
        vulnerabilities: List[Dict],
        remediations: Dict[str, Any],
        full: bool,
        packages: List[Any],
        fixes: Iterable = (),
    ) -> str:
        """
        Render vulnerabilities in JSON format.

        Args:
            announcements (List[Dict]): List of announcements.
            vulnerabilities (List[Dict]): List of vulnerabilities.
            remediations (Dict[str, Any]): Remediation data.
            full (bool): Flag indicating full output.
            packages (List[Any]): List of packages.
            fixes (Iterable, optional): Iterable of fixes.

        Returns:
            str: Rendered JSON vulnerabilities report.
        """
        if self.version == "0.5":
            from safety.formatters.schemas.zero_five import VulnerabilitySchemaV05

            return json_parser.dumps(
                VulnerabilitySchemaV05().dump(obj=vulnerabilities, many=True), indent=4
            )

        remediations_recommended = len(remediations.keys())
        LOG.debug(
            "Rendering %s vulnerabilities, %s package remediations with full_report: %s",
            len(vulnerabilities),
            remediations_recommended,
            full,
        )

        report = build_json_report(
            announcements, vulnerabilities, remediations, packages
        )
        template = self.__render_fixes(report, fixes)

        return json_parser.dumps(template, indent=4, cls=SafetyEncoder)

    def render_licenses(self, announcements: List[Dict], licenses: List[Dict]) -> str:
        """
        Render licenses in JSON format.

        Args:
            announcements (List[Dict]): List of announcements.
            licenses (List[Dict]): List of licenses.

        Returns:
            str: Rendered JSON licenses report.
        """
        unique_license_types = set([lic["license"] for lic in licenses])
        report = get_report_brief_info(
            as_dict=True, report_type=2, licenses_found=len(unique_license_types)
        )

        template = {
            "report_meta": report,
            "announcements": get_basic_announcements(announcements),
            "licenses": licenses,
        }

        return json_parser.dumps(template, indent=4)

    def render_announcements(self, announcements: List[Dict]) -> str:
        """
        Render announcements in JSON format.

        Args:
            announcements (List[Dict]): List of announcements.

        Returns:
            str: Rendered JSON announcements.
        """
        return json_parser.dumps(
            {"announcements": get_basic_announcements(announcements)}, indent=4
        )

    def __render_fixes(
        self, scan_template: Dict[str, Any], fixes: Iterable
    ) -> Dict[str, Any]:
        """
        Render fixes and update the scan template with remediations information.

        Args:
            scan_template (Dict[str, Any]): Initial scan template.
            fixes (Iterable): Iterable of fixes.

        Returns:
            Dict[str, Any]: Updated scan template with remediations.
        """

        applied = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
        skipped = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))

        fixes_applied = []
        total_applied = 0

        for fix in fixes:
            if fix.status == "APPLIED":
                total_applied += 1
                applied[fix.applied_at][fix.package][fix.previous_spec] = {
                    "previous_version": str(fix.previous_version),
                    "previous_spec": str(fix.previous_spec),
                    "updated_version": str(fix.updated_version),
                    "update_type": str(fix.update_type),
                    "fix_type": fix.fix_type,
                }
                fixes_applied.append(fix)
            else:
                skipped[fix.applied_at][fix.package][fix.previous_spec] = {
                    "scanned_version": str(fix.previous_version)
                    if fix.previous_version
                    else None,
                    "scanned_spec": str(fix.previous_spec)
                    if fix.previous_spec
                    else None,
                    "skipped_reason": fix.status,
                }

        vulnerabilities = scan_template.get("vulnerabilities", {})
        remediation_mode = "NON_INTERACTIVE"

        if SafetyContext().params.get("prompt_mode", False):
            remediation_mode = "INTERACTIVE"

        scan_template["report_meta"].update(
            {
                "remediations_attempted": len(fixes),
                "remediations_completed": total_applied,
                "remediation_mode": remediation_mode,
            }
        )

        scan_template["remediations_results"] = {
            "vulnerabilities_fixed": find_vulnerabilities_fixed(
                vulnerabilities, fixes_applied
            ),
            "remediations_applied": applied,
            "remediations_skipped": skipped,
        }

        return scan_template
