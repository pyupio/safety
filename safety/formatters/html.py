import logging

from safety.formatter import FormatterAPI
from safety.output_utils import get_report_brief_info, parse_html
from safety.util import get_basic_announcements

LOG = logging.getLogger(__name__)


class HTMLReport(FormatterAPI):
    """HTML report, for when the output is input for something else"""

    def render_vulnerabilities(self, announcements, vulnerabilities, remediations, full, packages, fixes=()):
        remediations_recommended = len(remediations.keys())
        LOG.debug('Rendering %s vulnerabilities, %s remediations with full_report: %s', len(vulnerabilities),
                  remediations_recommended, full)
        vulns_ignored = [vuln.to_dict() for vuln in vulnerabilities if vuln.ignored]
        vulns = [vuln.to_dict() for vuln in vulnerabilities if not vuln.ignored]

        report = get_report_brief_info(as_dict=True, report_type=1, vulnerabilities_found=len(vulns),
                                       vulnerabilities_ignored=len(vulns_ignored),
                                       remediations_recommended=remediations_recommended)

        remed = {}
        for k, v in remediations.items():
            if k not in remed:
                remed[k] = {}

            recommended_version = str(v.get('recommended_version')) if v.get('recommended_version', None) else None
            current_version = str(v.get('version')) if v.get('version', None) else None
            current_spec = str(v.get('current_spec')) if v.get('current_spec', None) else None

            remed[k]['current_version'] = current_version
            remed[k]['current_spec'] = current_spec
            remed[k]['vulnerabilities_found'] = v.get('vulnerabilities_found', 0)
            remed[k]['recommended_version'] = recommended_version
            remed[k]['other_recommended_versions'] = v.get('other_recommended_versions', [])
            remed[k]['more_info_url'] = v.get('more_info_url', '')

        template = {
            "report_meta": report,
            "scanned_packages": {p.name: p.to_dict(short_version=True) for p in packages},
            "affected_packages": {v.pkg.name: v.pkg.to_dict() for v in vulnerabilities},
            "announcements": [{'type': item.get('type'), 'message': item.get('message')} for item in
                              get_basic_announcements(announcements)],
            "vulnerabilities": vulns,
            "ignored_vulnerabilities": vulns_ignored,
            "remediations": remed
        }

        return parse_html(template)

    def render_licenses(self, announcements, licenses):
        pass

    def render_announcements(self, announcements):
        pass
