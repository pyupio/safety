import logging

from safety.formatter import FormatterAPI
from safety.formatters.json import build_json_report
from safety.output_utils import get_report_brief_info, parse_html
from safety.util import get_basic_announcements

LOG = logging.getLogger(__name__)


class HTMLReport(FormatterAPI):
    """HTML report, for when the output is input for something else"""

    def render_vulnerabilities(self, announcements, vulnerabilities, remediations, full, packages, fixes=()):
        LOG.debug(
            f'HTML Output, Rendering {len(vulnerabilities)} vulnerabilities, {len(remediations)} package '
            f'remediations with full_report: {full}')
        report = build_json_report(announcements, vulnerabilities, remediations, packages)

        return parse_html(kwargs={"json_data": report})

    def render_licenses(self, announcements, licenses):
        pass

    def render_announcements(self, announcements):
        pass
