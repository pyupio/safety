import os
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from safety import cli
from safety.models import Vulnerability, CVE
from safety.util import Package


def get_vulnerability(vuln_kwargs=None, cve_kwargs=None, pkg_kwargs=None):
    vuln_kwargs = {} if vuln_kwargs is None else vuln_kwargs
    cve_kwargs = {} if cve_kwargs is None else cve_kwargs
    pkg_kwargs = {} if pkg_kwargs is None else pkg_kwargs

    p_kwargs = {'name': 'django', 'version': '2.2', 'found': '/site-packages/django', 'insecure_versions': [],
                'secure_versions': ['2.2'], 'latest_version_without_known_vulnerabilities': '2.2',
                'latest_version': '2.2', 'more_info_url': 'https://pyup.io/package/foo'}
    p_kwargs.update(pkg_kwargs)

    c_kwargs = {'name': 'bla', 'cvssv2': None, 'cvssv3': None}
    c_kwargs.update(cve_kwargs)

    cve = CVE(**c_kwargs)
    pkg = Package(**p_kwargs)

    v_kwargs = {'name': pkg.name, 'pkg': pkg, 'ignored': False, 'reason': '', 'expires': '',
                'vulnerable_spec': ">0",
                'all_vulnerable_specs': ['2.2'],
                'analyzed_version': pkg.version,
                'advisory': '',
                'vulnerability_id': 'PYUP-1234',
                'is_transitive': False,
                'published_date': '',
                'fixed_versions': [],
                'closest_versions_without_known_vulnerabilities': '',
                'resources': ["pyup.io/vuln-id"],
                'CVE': cve,
                'affected_versions': [],
                'more_info_url': 'https://pyup.io/PVE/2323'}

    v_kwargs.update(vuln_kwargs)

    return Vulnerability(**v_kwargs)


class TestSafetyCLI(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner(mix_stderr=False)
        self.output_options = ['screen', 'text', 'json', 'bare']
        self.dirname = os.path.dirname(__file__)

    def test_command_line_interface(self):
        runner = CliRunner()
        result = runner.invoke(cli.cli)
        assert result.exit_code == 0
        assert 'Usage:' in result.output

        help_result = runner.invoke(cli.cli, ['--help'])
        assert help_result.exit_code == 0
        assert '--help' in help_result.output

    @patch("safety.safety.check")
    def test_check_vulnerabilities_found_default(self, check_func):
        check_func.return_value = [get_vulnerability()], None
        EXPECTED_EXIT_CODE_VULNS_FOUND = 64
        result = self.runner.invoke(cli.cli, ['check'])
        self.assertEqual(result.exit_code, EXPECTED_EXIT_CODE_VULNS_FOUND)

    @patch("safety.safety.check")
    def test_check_vulnerabilities_not_found_default(self, check_func):
        check_func.return_value = [], None
        EXPECTED_EXIT_CODE_VULNS_NOT_FOUND = 0
        result = self.runner.invoke(cli.cli, ['check'])
        self.assertEqual(result.exit_code, EXPECTED_EXIT_CODE_VULNS_NOT_FOUND)

    @patch("safety.safety.check")
    def test_check_vulnerabilities_found_with_outputs(self, check_func):
        check_func.return_value = [get_vulnerability()], None
        EXPECTED_EXIT_CODE_VULNS_FOUND = 64

        for output in self.output_options:
            result = self.runner.invoke(cli.cli, ['check', '--output', output])
            self.assertEqual(result.exit_code, EXPECTED_EXIT_CODE_VULNS_FOUND)

    @patch("safety.safety.check")
    def test_check_vulnerabilities_not_found_with_outputs(self, check_func):
        check_func.return_value = [], None
        EXPECTED_EXIT_CODE_VULNS_NOT_FOUND = 0

        for output in self.output_options:
            result = self.runner.invoke(cli.cli, ['check', '--output', output])
            self.assertEqual(result.exit_code, EXPECTED_EXIT_CODE_VULNS_NOT_FOUND)

    @patch("safety.safety.check")
    def test_check_continue_on_error(self, check_func):
        EXPECTED_EXIT_CODE_CONTINUE_ON_ERROR = 0

        # Cover no vulns found and vulns found
        for vulns in [[get_vulnerability()], []]:
            check_func.return_value = vulns, None

            result = self.runner.invoke(cli.cli, ['check', '--continue-on-error'])
            self.assertEqual(result.exit_code, EXPECTED_EXIT_CODE_CONTINUE_ON_ERROR)

            for output in self.output_options:
                result = self.runner.invoke(cli.cli, ['check', '--output', output, '--continue-on-error'])
                self.assertEqual(result.exit_code, EXPECTED_EXIT_CODE_CONTINUE_ON_ERROR)

    @patch("safety.safety.get_announcements")
    def test_announcements_if_is_not_tty(self, get_announcements_func):
        announcement = {'type': 'error', 'message': 'Please upgrade now'}
        get_announcements_func.return_value = [announcement]
        message = f"* {announcement.get('message')}"
        result = self.runner.invoke(cli.cli, ['check'])
        self.assertTrue('ANNOUNCEMENTS' in result.stderr)
        self.assertTrue(message in result.stderr)

    @patch("safety.safety.get_announcements")
    def test_review_pass(self, mocked_announcements):
        mocked_announcements.return_value = []
        runner = CliRunner()
        dirname = os.path.dirname(__file__)
        path_to_report = os.path.join(dirname, "test_db", "report.json")
        result = runner.invoke(cli.cli, ['review', '--output', 'bare', '--file', path_to_report])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, u'insecure-package\n')
