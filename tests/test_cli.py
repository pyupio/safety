import json
import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch, Mock

import click
from click.testing import CliRunner

from safety import cli
from safety.models import Vulnerability, CVE, Severity
from safety.util import Package, SafetyContext


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
    severity = None
    if cve and cve.cvssv2 or cve.cvssv3:
        severity = Severity(source=cve.name, cvssv2=cve.cvssv2, cvssv3=cve.cvssv3)
    pkg = Package(**p_kwargs)

    v_kwargs = {'package_name': pkg.name, 'pkg': pkg, 'ignored': False, 'ignored_reason': '', 'ignored_expires': '',
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
                'severity': severity,
                'affected_versions': [],
                'more_info_url': 'https://pyup.io/PVE/2323'}

    v_kwargs.update(vuln_kwargs)

    return Vulnerability(**v_kwargs)


class TestSafetyCLI(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
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

    @patch("safety.util.SafetyContext")
    @patch("safety.safety.check")
    @patch("safety.cli.get_packages")
    def test_chained_review_pass(self, get_packages, check_func, ctx):
        expires = datetime.strptime('2022-10-21', '%Y-%m-%d')
        vulns = [get_vulnerability(), get_vulnerability(vuln_kwargs={'vulnerability_id': '25853', 'ignored': True,
                                                                     'ignored_reason': 'A basic reason',
                                                                     'ignored_expires': expires})]
        packages = [pkg for pkg in {vuln.pkg.name: vuln.pkg for vuln in vulns}.values()]
        get_packages.return_value = packages
        provided_context = SafetyContext()
        provided_context.command = 'check'
        provided_context.packages = packages
        ctx.return_value = provided_context
        check_func.return_value = vulns, None

        with tempfile.TemporaryDirectory() as tempdir:
            for output in self.output_options:
                path_to_report = os.path.join(tempdir, f'report_{output}.json')

                pre_result = self.runner.invoke(cli.cli, [
                    'check', '--key', 'foo', '-o', output,
                    '--save-json', path_to_report])

                self.assertEqual(pre_result.exit_code, 64)

            for output in self.output_options:
                filename = f'report_{output}.json'
                path_to_report = os.path.join(tempdir, filename)
                result = self.runner.invoke(cli.cli, ['review', '--output', output, '--file', path_to_report])
                self.assertEqual(result.exit_code, 0, f'Unable to load the previous saved report: {filename}')

    @patch("safety.safety.session")
    def test_license_with_file(self, requests_session):
        licenses_db = {
            "licenses": {
                "BSD-3-Clause": 2
            },
            "packages": {
                "django": [
                    {
                        "start_version": "0.0",
                        "license_id": 2
                    }
                ]
            }
        }

        mock = Mock()
        mock.json.return_value = licenses_db
        mock.status_code = 200
        requests_session.get.return_value = mock

        dirname = os.path.dirname(__file__)
        test_filename = os.path.join(dirname, "reqs_4.txt")
        result = self.runner.invoke(cli.cli, ['license', '--key', 'foo', '--file', test_filename])
        # TODO: Add test for the screen formatter, this only test that the command doesn't crash
        self.assertEqual(result.exit_code, 0)

    def test_validate_with_unsupported_argument(self):
        result = self.runner.invoke(cli.cli, ['validate', 'safety_ci'])
        msg = 'This Safety version only supports "policy_file" validation. "safety_ci" is not supported.\n'
        self.assertEqual(click.unstyle(result.stderr), msg)
        self.assertEqual(result.exit_code, 1)

    def test_validate_with_wrong_path(self):
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '--path', 'imaginary/path'])
        msg = 'The path "imaginary/path" does not exist.\n'
        self.assertEqual(click.unstyle(result.stderr), msg)
        self.assertEqual(result.exit_code, 1)

    def test_validate_with_basic_policy_file(self):
        dirname = os.path.dirname(__file__)
        path = os.path.join(dirname, "test_policy_file", "default_policy_file.yml")
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '--path', path])
        cleaned_stdout = click.unstyle(result.stdout)
        msg = 'The Safety policy file was successfully parsed with the following values:\n'
        parsed = json.dumps(
            {
                "security": {
                    "ignore-cvss-severity-below": 0,
                    "ignore-cvss-unknown-severity": False,
                    "ignore-vulnerabilities": {
                        "25853": {
                            "reason": "we don't use the vulnerable function",
                            "expires": "2022-10-21 00:00:00"
                        }
                    },
                    "continue-on-vulnerability-error": False
                },
                "filename": path
            },
            indent=4
        ) + '\n'

        self.assertEqual(msg + parsed, cleaned_stdout)
        self.assertEqual(result.exit_code, 0)

    def test_validate_with_policy_file_using_invalid_keyword(self):
        dirname = os.path.dirname(__file__)
        filename = 'default_policy_file_using_invalid_keyword.yml'
        path = os.path.join(dirname, "test_policy_file", filename)
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '--path', path])
        cleaned_stdout = click.unstyle(result.stderr)
        msg_hint = 'HINT: "security" -> "transitive" is not a valid keyword. Valid keywords in this level are: ' \
                   'ignore-cvss-severity-below, ignore-cvss-unknown-severity, ignore-vulnerabilities, ' \
                   'continue-on-vulnerability-error\n'
        msg = f'Unable to load the Safety Policy file "{path}".\n{msg_hint}'

        self.assertEqual(msg, cleaned_stdout)
        self.assertEqual(result.exit_code, 1)

    def test_validate_with_policy_file_using_invalid_typo_keyword(self):
        dirname = os.path.dirname(__file__)
        filename = 'default_policy_file_using_invalid_typo_keyword.yml'
        path = os.path.join(dirname, "test_policy_file", filename)
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '--path', path])
        cleaned_stdout = click.unstyle(result.stderr)
        msg_hint = 'HINT: "security" -> "ignore-vunerabilities" is not a valid keyword. Maybe you meant: ' \
                   'ignore-vulnerabilities\n'
        msg = f'Unable to load the Safety Policy file "{path}".\n{msg_hint}'

        self.assertEqual(msg, cleaned_stdout)
        self.assertEqual(result.exit_code, 1)

    def test_generate_pass(self):
        with tempfile.TemporaryDirectory() as tempdir:
            result = self.runner.invoke(cli.cli, ['generate', 'policy_file', '--path', tempdir])
            cleaned_stdout = click.unstyle(result.stdout)
            msg = f'A default Safety policy file has been generated! Review the file contents in the path {tempdir} ' \
                  f'in the file: .safety-policy.yml\n'
            self.assertEqual(msg, cleaned_stdout)

    def test_generate_with_unsupported_argument(self):
        result = self.runner.invoke(cli.cli, ['generate', 'safety_ci'])
        msg = 'This Safety version only supports "policy_file" generation. "safety_ci" is not supported.\n'
        self.assertEqual(click.unstyle(result.stderr), msg)
        self.assertEqual(result.exit_code, 1)

    def test_generate_with_wrong_path(self):
        result = self.runner.invoke(cli.cli, ['generate', 'policy_file', '--path', 'imaginary/path'])
        msg = 'The path "imaginary/path" does not exist.\n'
        self.assertEqual(click.unstyle(result.stderr), msg)
        self.assertEqual(result.exit_code, 1)






