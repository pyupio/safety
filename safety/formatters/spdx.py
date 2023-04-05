import logging

from safety.formatter import FormatterAPI
from safety.formatters.json import build_json_report
from safety.output_utils import create_spdx_document


LOG = logging.getLogger(__name__)


class SPDXReport(FormatterAPI):
    """SPDX report"""

    VERSIONS = ("2.2", "2.3")

    def __init__(self, version="2.3", **kwargs):
        super().__init__(**kwargs)
        self.version: str = version if version in self.VERSIONS else "2.3"

    def render_vulnerabilities(self, announcements, vulnerabilities, remediations, full, packages, fixes=()):
        LOG.debug(
            f'SPDX Report Output, Rendering {len(vulnerabilities)} vulnerabilities, {len(remediations)} package '
            f'remediations with full_report: {full}')
        report = build_json_report(announcements, vulnerabilities, remediations, packages)
        doc = create_spdx_document(report, self.version)
        return doc

    def render_licenses(self, announcements, licenses):
        pass

    def render_announcements(self, announcements):
        pass
