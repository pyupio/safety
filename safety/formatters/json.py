import logging
from datetime import datetime

import json as json_parser

from safety.formatter import FormatterAPI
from safety.output_utils import get_report_brief_info
from safety.util import get_basic_announcements

LOG = logging.getLogger(__name__)


class JsonReport(FormatterAPI):
    """Json report, for when the output is input for something else"""

    def render_vulnerabilities(self, announcements, vulnerabilities, remediations, full, packages):
        LOG.debug('Rendering %s vulnerabilities, %s remediations with full_report: %s', len(vulnerabilities),
                  len(remediations.keys()), full)
        vulns_ignored = [vuln.to_dict() for vuln in vulnerabilities if vuln.ignored]
        vulns = [vuln.to_dict() for vuln in vulnerabilities if not vuln.ignored]
        report = get_report_brief_info(as_dict=True)

        remed = {}
        for k, v in remediations.items():
            if k not in remed:
                remed[k] = {}

            closest = v.get('closest_secure_version', {})
            upgrade = closest.get('major', None)
            if upgrade:
                upgrade = str(upgrade)

            remed[k]['vulns_found'] = v.get('vulns_found', 0)
            remed[k]['version'] = v.get('version', None)
            remed[k]['recommended'] = upgrade if upgrade else None
            remed[k]['other_recommended_versions'] = [other_v for other_v in v.get('secure_versions', []) if
                                                      other_v != upgrade]
            remed[k]['more_info_url'] = v.get('more_info_url', '')

        template = {
            "generated_at": str(datetime.now()),
            "report": report,
            "scanned_packages": {p.name: p.to_dict(short_version=True) for p in packages},
            "affected_packages": {v.pkg.name: v.pkg.to_dict() for v in vulnerabilities},
            "announcements": [{'type': item.get('type'), 'message': item.get('message')} for item in
                              get_basic_announcements(announcements)],
            "vulnerabilities": vulns,
            "ignored_vulnerabilities": vulns_ignored,
            "remediations": remed
        }

        return json_parser.dumps(template, indent=4)

    def render_licenses(self, announcements, licenses):

        template = {
            "generated_at": str(datetime.now()),
            "announcements": get_basic_announcements(announcements),
            "licenses": licenses,
        }

        return json_parser.dumps(template, indent=4)

    def render_announcements(self, announcements):
        return json_parser.dumps({"announcements": get_basic_announcements(announcements)}, indent=4)
