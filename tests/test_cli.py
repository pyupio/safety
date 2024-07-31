import json
import logging
import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import requests
import socket
import psutil

import click
from click.testing import CliRunner
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from safety import cli
from safety.models import CVE, SafetyRequirement, Severity, Vulnerability
from safety.util import Package, SafetyContext
from safety.auth.models import Auth
from safety_schemas.models.base import AuthenticationType


def get_vulnerability(vuln_kwargs=None, cve_kwargs=None, pkg_kwargs=None):
    vuln_kwargs = {} if vuln_kwargs is None else vuln_kwargs
    cve_kwargs = {} if cve_kwargs is None else cve_kwargs
    pkg_kwargs = {} if pkg_kwargs is None else pkg_kwargs

    p_kwargs = {'name': 'django', 'version': '2.2', 'requirements': [SafetyRequirement('django==2.2')], 'found': '/site-packages/django',
                'insecure_versions': [], 'secure_versions': ['2.2'],
                'latest_version_without_known_vulnerabilities': '2.2',
                'latest_version': '2.2', 'more_info_url': 'https://pyup.io/package/foo'}
    p_kwargs.update(pkg_kwargs)

    c_kwargs = {'name': 'bla', 'cvssv2': None, 'cvssv3': None}
    c_kwargs.update(cve_kwargs)

    cve = CVE(**c_kwargs)
    severity = None
    if cve and cve.cvssv2 or cve.cvssv3:
        severity = Severity(source=cve.name, cvssv2=cve.cvssv2, cvssv3=cve.cvssv3)
    pkg = Package(**p_kwargs)

    vulnerable_spec = set()
    vulnerable_spec.add(">0")

    v_kwargs = {'package_name': pkg.name, 'pkg': pkg, 'ignored': False, 'ignored_reason': '', 'ignored_expires': '',
                'vulnerable_spec': vulnerable_spec,
                'all_vulnerable_specs': ['2.2'],
                'analyzed_version': pkg.version,
                'analyzed_requirement': pkg.requirements[0],
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
        expected = "Usage: cli [OPTIONS] COMMAND [ARGS]..."

        for option in [[], ["--help"]]:
            result = runner.invoke(cli.cli, option)
            self.assertEqual(result.exit_code, 0)
            self.assertIn(expected, click.unstyle(result.output))

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


    @patch("safety.safety.check")
    def test_check_ignore_format_backward_compatible(self, check):
        runner = CliRunner()

        check.return_value = []

        dirname = os.path.dirname(__file__)
        reqs_path = os.path.join(dirname, "reqs_4.txt")

        _ = runner.invoke(cli.cli, ['check', '--file', reqs_path, '--ignore', "123,456", '--ignore', "789"])
        try:
            check_call_kwargs = check.call_args[1]  # Python < 3.8
        except IndexError:
            check_call_kwargs = check.call_args.kwargs

        ignored_transformed = {
            '123': {'expires': None, 'reason': ''},
            '456': {'expires': None, 'reason': ''},
            '789': {'expires': None, 'reason': ''}
        }
        self.assertEqual(check_call_kwargs['ignore_vulns'], ignored_transformed)

    def test_validate_with_unsupported_argument(self):
        result = self.runner.invoke(cli.cli, ['validate', 'safety_ci'])
        msg = 'This Safety version only supports "policy_file" validation. "safety_ci" is not supported.\n'
        self.assertEqual(click.unstyle(result.stderr), msg)
        self.assertEqual(result.exit_code, 1)

    def test_validate_with_wrong_path(self):
        p = Path('imaginary/path')
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '--path', str(p)])
        msg = f'The path "{str(p)}" does not exist.\n'
        self.assertEqual(click.unstyle(result.stderr), msg)
        self.assertEqual(result.exit_code, 1)

    def test_validate_with_basic_policy_file(self):
        dirname = os.path.dirname(__file__)
        path = os.path.join(dirname, "test_policy_file", "default_policy_file.yml")
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '2.0', '--path', path])
        cleaned_stdout = click.unstyle(result.stdout)
        msg = 'The Safety policy file (Valid only for the check command) was successfully parsed with the following values:\n'
        parsed = json.dumps(
            {
                "project-id": '',
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
            indent=2
        ) + '\n'

        self.assertEqual(msg + parsed, cleaned_stdout)
        self.assertEqual(result.exit_code, 0)

        path = os.path.join(dirname, "test_policy_file", "v3_0", "default_policy_file.yml")
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '3.0', '--path', path])
        cleaned_stdout = click.unstyle(result.stdout)
        msg = 'The Safety policy (3.0) file (Used for scan and system-scan commands) was successfully parsed with the following values:\n'
        parsed = {
            "version": "3.0",
            "scan": {
                "max_depth": 6,
                "exclude": [],
                "include_files": [],
                "system": {
                "targets": []
                }
            },
            "report": {
                "dependency_vulnerabilities": {
                "enabled": True,
                "auto_ignore": {
                    "python": {
                    "ignore_environment_results": True,
                    "ignore_unpinned_requirements": True
                    },
                    "vulnerabilities": None,
                    "cvss_severity": []
                }
                }
            },
            "fail_scan": {
                "dependency_vulnerabilities": {
                    "enabled": True,
                    "fail_on_any_of": {
                        "cvss_severity": [
                            "critical",
                            "high",
                            "medium",
                        ],
                        "exploitability": [
                            "critical",
                            "high",
                            "medium",
                        ]
                    }
                }
            },
            "security_updates": {
                "dependency_vulnerabilities": {
                "auto_security_updates_limit": [
                    "patch"
                ]
                }
            }
            }

        msg_stdout, parsed_policy = cleaned_stdout.split('\n', 1)
        msg_stdout += '\n'
        parsed_policy = json.loads(parsed_policy.replace('\n', ''))

        fail_scan = parsed_policy.get("fail_scan", None)
        self.assertIsNotNone(fail_scan)
        fail_of_any = fail_scan["dependency_vulnerabilities"]["fail_on_any_of"]
        fail_of_any["cvss_severity"] = sorted(fail_of_any["cvss_severity"])
        fail_of_any["exploitability"] = sorted(fail_of_any["exploitability"])

        self.assertEqual(msg, msg_stdout)
        self.assertEqual(parsed, parsed_policy)
        self.assertEqual(result.exit_code, 0)


    def test_validate_with_policy_file_using_invalid_keyword(self):
        dirname = os.path.dirname(__file__)
        filename = 'default_policy_file_using_invalid_keyword.yml'
        path = os.path.join(dirname, "test_policy_file", filename)
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '2.0', '--path', path])
        cleaned_stdout = click.unstyle(result.stderr)
        msg_hint = 'HINT: "security" -> "transitive" is not a valid keyword. Valid keywords in this level are: ' \
                   'ignore-cvss-severity-below, ignore-cvss-unknown-severity, ignore-vulnerabilities, ' \
                   'continue-on-vulnerability-error, ignore-unpinned-requirements\n'
        msg = f'Unable to load the Safety Policy file "{path}".\n{msg_hint}'

        self.assertEqual(msg, cleaned_stdout)
        self.assertEqual(result.exit_code, 1)

        path = os.path.join(dirname, "test_policy_file", "v3_0", filename)
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '3.0', '--path', path])
        cleaned_stdout = click.unstyle(result.stderr)
        msg = f'Unable to load the Safety Policy file ("{path}"), this command only supports version 3.0, details: 1 validation error for Config'

        self.assertIn(msg, cleaned_stdout)
        self.assertEqual(result.exit_code, 1)


    def test_validate_with_policy_file_using_invalid_typo_keyword(self):
        dirname = os.path.dirname(__file__)
        filename = 'default_policy_file_using_invalid_typo_keyword.yml'
        path = os.path.join(dirname, "test_policy_file", filename)
        result = self.runner.invoke(cli.cli, ['validate', 'policy_file', '2.0', '--path', path])
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
        p = Path('imaginary/path')
        result = self.runner.invoke(cli.cli, ['generate', 'policy_file', '--path', str(p)])
        msg = f'The path "{str(p)}" does not exist.\n'
        self.assertEqual(click.unstyle(result.stderr), msg)
        self.assertEqual(result.exit_code, 1)

    def test_check_with_fix_does_verify_api_key(self):
        dirname = os.path.dirname(__file__)
        req_file = os.path.join(dirname, "test_fix", "basic", "reqs_simple.txt")
        result = self.runner.invoke(cli.cli, ['check', '-r', req_file, '--apply-security-updates'])
        self.assertEqual(click.unstyle(result.stderr),
                         "The --apply-security-updates option needs authentication. See https://docs.safetycli.com/safety-docs/support/invalid-api-key-error.\n")
        self.assertEqual(result.exit_code, 65)

    def test_check_with_fix_only_works_with_files(self):
        result = self.runner.invoke(cli.cli, ['check', '--key', 'TEST-API_KEY', '--apply-security-updates'])
        self.assertEqual(click.unstyle(result.stderr),
                         '--apply-security-updates only works with files; use the "-r" option to specify files to remediate.\n')
        self.assertEqual(result.exit_code, 1)

    @patch("safety.util.SafetyContext")
    @patch("safety.safety.check")
    @patch("safety.safety.calculate_remediations")
    @patch("safety.cli.get_packages")
    def test_check_with_fix(self, get_packages, calculate_remediations, check_func, ctx):
        vulns = [get_vulnerability()]
        packages = [pkg for pkg in {vuln.pkg.name: vuln.pkg for vuln in vulns}.values()]
        get_packages.return_value = packages
        provided_context = SafetyContext()
        provided_context.command = 'check'
        provided_context.packages = packages
        ctx.return_value = provided_context
        check_func.return_value = vulns, None
        target = Version("1.9")
        calculate_remediations.return_value = {
            "django": {
                "==1.8": {
                    "version": "1.8",
                    "vulnerabilities_found": 1,
                    "recommended_version": target,
                    "requirement": SafetyRequirement('django==1.8'),
                    "secure_versions": [],
                    "closest_secure_version": {"minor": None, "major": target},
                    "more_info_url": "https://pyup.io/p/pypi/django/52d/"}
            }}

        dirname = os.path.dirname(__file__)
        source_req = os.path.join(dirname, "test_fix", "basic", "reqs_simple.txt")

        with tempfile.TemporaryDirectory() as tempdir:
            req_file = os.path.join(tempdir, 'reqs_simple_minor.txt')
            shutil.copy(source_req, req_file)

            self.runner.invoke(cli.cli, ['check', '-r', req_file, '--key', 'TEST-API_KEY',
                                             '--apply-security-updates'])

            with open(req_file) as f:
                self.assertEqual("django==1.8\nsafety==2.3.0\nflask==0.87.0", f.read())

            self.runner.invoke(cli.cli, ['check', '-r', req_file, '--key', 'TEST-API_KEY', '--apply-security-updates',
                                         '--auto-security-updates-limit', 'minor'])

            with open(req_file) as f:
                self.assertEqual("django==1.9\nsafety==2.3.0\nflask==0.87.0", f.read())

            target = Version("2.0")
            calculate_remediations.return_value = {
                "django": {
                    "==1.9": {
                        "version": "1.9",
                        "vulnerabilities_found": 1,
                        "recommended_version": target,
                        "requirement": SafetyRequirement('django==1.9'),
                        "secure_versions": [],
                        "closest_secure_version": {"minor": None, "major": target},
                        "more_info_url": "https://pyup.io/p/pypi/django/52d/"}}
            }

            self.runner.invoke(cli.cli, ['check', '-r', req_file, '--key', 'TEST-API_KEY', '--apply-security-updates',
                                         '-asul', 'minor', '--json'])
            with open(req_file) as f:
                self.assertEqual("django==1.9\nsafety==2.3.0\nflask==0.87.0", f.read())

            self.runner.invoke(cli.cli, ['check', '-r', req_file, '--key', 'TEST-API_KEY', '--apply-security-updates',
                                         '-asul', 'major', '--output', 'bare'])

            with open(req_file) as f:
                self.assertEqual("django==2.0\nsafety==2.3.0\nflask==0.87.0", f.read())

    def test_check_ignore_unpinned_requirements(self):
        dirname = os.path.dirname(__file__)
        db = os.path.join(dirname, "test_db")
        reqs_unpinned = os.path.join(dirname, "reqs_unpinned.txt")

        # If not set (default None) then show local announcement and reported in group and ignored.
        result = self.runner.invoke(cli.cli, ['check', '-r', reqs_unpinned, '--db', db, '--output', 'text'])

        announcement = "\n\n ANNOUNCEMENTS\n\n  " \
                       "* Warning: django and numpy are unpinned. Safety by default does not report \n  " \
                       "  on potential vulnerabilities in unpinned packages. It is recommended to pin \n  " \
                       "  your dependencies unless this is a library meant for distribution. To learn \n  " \
                       "  more about reporting these, specifier range handling, and options for \n  " \
                       "  scanning unpinned packages visit https://docs.pyup.io/docs/safety-range- \n  " \
                       "  specs \n\n"
        self.assertIn(announcement, result.stdout)

        unpinned_vulns = "-> Warning: 2 known vulnerabilities match the django versions that could be \n" \
                         "   installed from your specifier: django>=0 (unpinned). These vulnerabilities \n" \
                         "   are not reported by default. To report these vulnerabilities set 'ignore- \n" \
                         "   unpinned-requirements' to False under 'security' in your policy file. See \n" \
                         "   https://docs.pyup.io/docs/safety-20-policy-file for more information. \n" \
                         "   It is recommended to pin your dependencies unless this is a library meant \n" \
                         "   for distribution. To learn more about reporting these, specifier range \n" \
                         "   handling, and options for scanning unpinned packages visit \n" \
                         "   https://docs.pyup.io/docs/safety-range-specs \n\n"

        self.assertIn(unpinned_vulns, result.stdout)

        # If true then
        result = self.runner.invoke(cli.cli, ['check', '-r', reqs_unpinned, '--ignore-unpinned-requirements',
                                              '--db', db, '--output', 'text'])

        announcement = "\n\n ANNOUNCEMENTS\n\n  " \
                       "* Warning: django and numpy are unpinned and potential vulnerabilities are \n  " \
                       "  being ignored given `ignore-unpinned-requirements` is True in your config. \n  " \
                       "  It is recommended to pin your dependencies unless this is a library meant \n  " \
                       "  for distribution. To learn more about reporting these, specifier range \n  " \
                       "  handling, and options for scanning unpinned packages visit \n  " \
                       "  https://docs.pyup.io/docs/safety-range-specs \n\n"

        self.assertIn(announcement, result.stdout)
        self.assertIn(unpinned_vulns, result.stdout)

        # If false then
        result = self.runner.invoke(cli.cli, ['check', '-r', reqs_unpinned, '--check-unpinned-requirements', '--db', db,
                                              '--output', 'text'])

        self.assertNotIn("ANNOUNCEMENTS", result.stdout)
        self.assertNotIn("-> Warning: 2 known vulnerabilities match the django versions", result.stdout)
        self.assertIn("-> Vulnerability may be present given that your django install specifier is >=0", result.stdout)
        self.assertIn("Scan was completed. 2 vulnerabilities were reported.", result.stdout)

        result = self.runner.invoke(cli.cli, ['check', '-r', reqs_unpinned, '--db', db, '--json', '-i', 'some id',
                                              '--check-unpinned-requirements'])

        ignored = json.loads(result.stdout).get('ignored_vulnerabilities', [])
        self.assertEqual(1, len(ignored), 'Unexpected size for the ignored vulnerabilities list.')

        reason = ignored[0].get('ignored_reason', None)
        self.assertEqual("", reason, "Reason should be empty as this was ignored without a message.")

    def test_basic_html_output_pass(self):
        dirname = os.path.dirname(__file__)
        db = os.path.join(dirname, "test_db")
        reqs_unpinned = os.path.join(dirname, "reqs_unpinned.txt")

        result = self.runner.invoke(cli.cli, ['check', '-r', reqs_unpinned, '--db', db, '--output', 'html'])

        ignored = "<p>Found vulnerabilities that were ignored: 2</p>"
        announcement = "Warning: django and numpy are unpinned."
        self.assertIn(ignored, result.stdout)
        self.assertIn(announcement, result.stdout)
        self.assertNotIn("remediations-suggested", result.stdout)

        reqs_affected = os.path.join(dirname, "reqs_pinned_affected.txt")

        result = self.runner.invoke(cli.cli, ['check', '-r', reqs_affected, '--db', db, '--output', 'html'])

        self.assertIn("remediations-suggested", result.stdout)
        self.assertIn("Use API Key", result.stdout)

    @patch('safety.safety.fetch_database_url')
    def test_license_with_file(self, fetch_database_url):
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
        mock.return_value = licenses_db

        dirname = os.path.dirname(__file__)
        test_filename = os.path.join(dirname, "reqs_4.txt")
        result = self.runner.invoke(cli.cli, ['license', '--key', 'foo', '--file', test_filename])
        print(result.stdout)
        self.assertEqual(result.exit_code, 0)

    @patch('safety.auth.cli.get_auth_info', return_value={'email': 'test@test.com'})
    @patch.object(Auth, 'is_valid', return_value=True)
    @patch('safety.auth.utils.SafetyAuthSession.get_authentication_type', return_value=AuthenticationType.TOKEN)
    @patch('builtins.input', lambda *args: '')
    @patch('safety.safety.fetch_database', return_value={'vulnerable_packages': []})
    def test_debug_flag(self, mock_get_auth_info, mock_is_valid, mock_get_auth_type, mock_fetch_database):
        result = self.runner.invoke(cli.cli, ['--debug', 'scan'])
        assert result.exit_code == 0, f"CLI exited with code {result.exit_code} and output: {result.output} and error: {result.stderr}"
        assert "for known security issues using default" in result.output

    @patch('safety.auth.cli.get_auth_info', return_value={'email': 'test@test.com'})
    @patch.object(Auth, 'is_valid', return_value=True)
    @patch('safety.auth.utils.SafetyAuthSession.get_authentication_type', return_value=AuthenticationType.TOKEN)
    @patch('builtins.input', lambda *args: '')
    @patch('safety.safety.fetch_database', return_value={'vulnerable_packages': []})
    def test_debug_flag_with_value_1(self, mock_get_auth_info, mock_is_valid, mock_get_auth_type, mock_fetch_database):
        sys.argv = ['safety', '--debug', '1', 'scan']

        @cli.preprocess_args
        def dummy_function():
            pass

        # Extract the preprocessed arguments from sys.argv
        preprocessed_args = sys.argv[1:]  # Exclude the script name 'safety'

        # Assert the preprocessed arguments
        assert preprocessed_args == ['--debug', 'scan'], f"Preprocessed args: {preprocessed_args}"

    @patch('safety.auth.cli.get_auth_info', return_value={'email': 'test@test.com'})
    @patch.object(Auth, 'is_valid', return_value=True)
    @patch('safety.auth.utils.SafetyAuthSession.get_authentication_type', return_value=AuthenticationType.TOKEN)
    @patch('builtins.input', lambda *args: '')
    @patch('safety.safety.fetch_database', return_value={'vulnerable_packages': []})
    def test_debug_flag_with_value_true(self, mock_get_auth_info, mock_is_valid, mock_get_auth_type, mock_fetch_database):
        sys.argv = ['safety', '--debug', 'true', 'scan']

        @cli.preprocess_args
        def dummy_function():
            pass

        # Extract the preprocessed arguments from sys.argv
        preprocessed_args = sys.argv[1:]  # Exclude the script name 'safety'

        # Assert the preprocessed arguments
        assert preprocessed_args == ['--debug', 'scan'], f"Preprocessed args: {preprocessed_args}"

class TestNetworkTelemetry(unittest.TestCase):

    @patch('psutil.net_io_counters')
    @patch('psutil.net_if_addrs')
    @patch('psutil.net_connections')
    @patch('psutil.net_if_stats')
    @patch('requests.get')
    def test_get_network_telemetry(self, mock_requests_get, mock_net_if_stats, mock_net_connections, mock_net_if_addrs, mock_net_io_counters):
        # Setup mocks
        mock_net_io_counters.return_value = Mock(bytes_sent=1000, bytes_recv=2000, packets_sent=10, packets_recv=20)
        mock_net_if_addrs.return_value = {'eth0': [Mock(family=socket.AF_INET, address='192.168.1.1')]}
        mock_net_connections.return_value = [Mock(fd=1, family=socket.AF_INET, type=socket.SOCK_STREAM,
                                                  laddr=Mock(ip='192.168.1.1', port=8080),
                                                  raddr=Mock(ip='93.184.216.34', port=80),
                                                  status='ESTABLISHED')]
        mock_net_if_stats.return_value = {'eth0': Mock(isup=True, duplex=2, speed=1000, mtu=1500)}

        mock_response = Mock()
        mock_response.content = b'a' * 1000  # Mock content length
        mock_requests_get.return_value = mock_response

        # Run the function
        result = cli.get_network_telemetry()

        # Assert the network telemetry data
        self.assertEqual(result['bytes_sent'], 1000)
        self.assertEqual(result['bytes_recv'], 2000)
        self.assertEqual(result['packets_sent'], 10)
        self.assertEqual(result['packets_recv'], 20)
        self.assertIsNotNone(result['download_speed'])
        self.assertEqual(result['interfaces'], {'eth0': ['192.168.1.1']})
        self.assertEqual(result['connections'][0]['laddr'], '192.168.1.1:8080')
        self.assertEqual(result['connections'][0]['raddr'], '93.184.216.34:80')
        self.assertEqual(result['connections'][0]['status'], 'ESTABLISHED')
        self.assertEqual(result['interface_stats']['eth0']['isup'], True)
        self.assertEqual(result['interface_stats']['eth0']['duplex'], 2)
        self.assertEqual(result['interface_stats']['eth0']['speed'], 1000)
        self.assertEqual(result['interface_stats']['eth0']['mtu'], 1500)

    @patch('requests.get', side_effect=requests.RequestException('Network error'))
    def test_get_network_telemetry_request_exception(self, mock_requests_get):
        # Run the function
        result = cli.get_network_telemetry()

        # Assert the download_speed is None and error is captured
        self.assertIsNone(result['download_speed'])
        self.assertIn('error', result)

    @patch('psutil.net_io_counters', side_effect=psutil.AccessDenied('Access denied'))
    def test_get_network_telemetry_access_denied(self, mock_net_io_counters):
        # Run the function
        result = cli.get_network_telemetry()

        # Assert the error is captured
        self.assertIn('error', result)
        self.assertIn('Access denied', result['error'])

class TestConfigureLogger(unittest.TestCase):

    @patch('configparser.ConfigParser.read')
    @patch('safety.cli.get_network_telemetry')
    def test_configure_logger_debug(self, mock_get_network_telemetry, mock_config_read):
        mock_get_network_telemetry.return_value = {'dummy_key': 'dummy_value'}
        mock_config_read.return_value = None

        ctx = Mock()
        param = Mock()
        debug = True

        with patch('sys.argv', ['--debug', 'true']), \
        patch('logging.basicConfig') as mock_basicConfig, \
        patch('configparser.ConfigParser.items', return_value=[('key', 'value')]), \
        patch('configparser.ConfigParser.sections', return_value=['section']):
            cli.configure_logger(ctx, param, debug)
            mock_basicConfig.assert_called_with(format='%(asctime)s %(name)s => %(message)s', level=logging.DEBUG)

        # Check if network telemetry logging was called
        mock_get_network_telemetry.assert_called_once()

    @patch('configparser.ConfigParser.read')
    def test_configure_logger_non_debug(self, mock_config_read):
        mock_config_read.return_value = None

        ctx = Mock()
        param = Mock()
        debug = False

        with patch('logging.basicConfig') as mock_basicConfig:
            cli.configure_logger(ctx, param, debug)
            mock_basicConfig.assert_called_with(format='%(asctime)s %(name)s => %(message)s', level=logging.CRITICAL)