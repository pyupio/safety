import os
import unittest
from datetime import datetime
from unittest.mock import Mock, patch

import click
from packaging.version import parse

from safety.models import Package
from safety.output_utils import format_vulnerability, get_printable_list_of_scanned_items, build_remediation_section, \
    get_final_brief_license
from tests.test_cli import get_vulnerability


class TestOutputUtils(unittest.TestCase):

    def setUp(self) -> None:
        self.maxDiff = None

    def test_format_vulnerability(self):
        numpy_pkg = {'name': 'numpy', 'version': '1.22.0', 'secure_versions': ['1.22.3'],
                     'insecure_versions': ['1.22.2', '1.22.1', '1.22.0', '1.22.0rc3', '1.21.5']}
        severity = {
            "cvssv2": {
                "base_score": 4.3,
                "impact_score": 2.9,
                "vector_string": "AV:N/AC:M/Au:N/C:N/I:P/A:N"
            },
            "cvssv3": {
                "base_score": 6.1,
                "impact_score": 2.7,
                "base_severity": "MEDIUM",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
            }}

        vulnerability = get_vulnerability(pkg_kwargs=numpy_pkg,
                                          vuln_kwargs={'affected_versions': ['1.22.0', '1.21.5']},
                                          cve_kwargs=severity)
        columns = 80

        output = format_vulnerability(vulnerability, full_mode=True, only_text=True, columns=columns)

        lines = [
            '-> Vulnerability found in numpy version 1.22.0',
            '   Vulnerability ID: PYUP-1234',
            '   Affected spec: >0',
            '   ADVISORY: ',
            '   Fixed versions: No known fix',
            '   bla is MEDIUM SEVERITY => CVSS v3, BASE SCORE 6.1, IMPACT',
            '   SCORE 2.7, VECTOR STRING CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
            '   CVSS v2, BASE SCORE 4.3, IMPACT SCORE 2.9, VECTOR STRING',
            '   AV:N/AC:M/Au:N/C:N/I:P/A:N',
            '   For more information, please visit https://pyup.io/PVE/2323\n',
        ]

        EXPECTED = '\n'.join(lines)
        self.assertEqual(output, EXPECTED)

    def test_format_vulnerability_with_ignored_vulnerability(self):
        numpy_pkg = {'name': 'numpy', 'version': '1.22.0', 'secure_versions': ['1.22.3'],
                     'insecure_versions': ['1.22.2', '1.22.1', '1.22.0', '1.22.0rc3', '1.21.5']}

        vulnerability = get_vulnerability(pkg_kwargs=numpy_pkg,
                                          vuln_kwargs={'ignored': True})
        columns = 80

        output = format_vulnerability(vulnerability, full_mode=True, only_text=True, columns=columns)

        lines = [
            '-> Vulnerability found in numpy version 1.22.0',
            '   Vulnerability ID: PYUP-1234',
            '   This vulnerability is being ignored.',
            '   For more information, please visit https://pyup.io/PVE/2323\n',
        ]

        EXPECTED = '\n'.join(lines)
        self.assertEqual(output, EXPECTED)

        reason = 'We do not use that feature'
        vulnerability = get_vulnerability(pkg_kwargs=numpy_pkg,
                                          vuln_kwargs={'ignored': True,
                                                       'ignored_reason': reason})

        output = format_vulnerability(vulnerability, full_mode=True, only_text=True, columns=columns)

        lines = [
            '-> Vulnerability found in numpy version 1.22.0',
            '   Vulnerability ID: PYUP-1234',
            '   This vulnerability is being ignored.',
           f'   Reason: {reason}',
            '   For more information, please visit https://pyup.io/PVE/2323\n',
        ]

        EXPECTED = '\n'.join(lines)
        self.assertEqual(output, EXPECTED)

        reason = 'We do not think this vuln is a security issue'
        expires = datetime.strptime('2022-06-21', '%Y-%m-%d')
        vulnerability = get_vulnerability(pkg_kwargs=numpy_pkg,
                                          vuln_kwargs={'ignored': True,
                                                       'ignored_reason': reason,
                                                       'ignored_expires': expires})

        expires = '2022-06-21 00:00:00 UTC'
        output = format_vulnerability(vulnerability, full_mode=True, only_text=True, columns=120)

        lines = [
            '-> Vulnerability found in numpy version 1.22.0',
            '   Vulnerability ID: PYUP-1234',
           f'   This vulnerability is being ignored until {expires}. See your configurations.',
           f'   Reason: {reason}',
            '   For more information, please visit https://pyup.io/PVE/2323\n'
        ]

        EXPECTED = '\n'.join(lines)
        self.assertEqual(output, EXPECTED)

    @patch("safety.output_utils.SafetyContext")
    def test_get_printable_list_of_scanned_items_stdin(self, ctx):
        ctx.return_value = Mock(packages=[])
        output = get_printable_list_of_scanned_items('stdin')

        EXPECTED = (
            [[{'styled': False, 'value': 'No found packages in stdin'}]],
            ['No found packages in stdin'])

        self.assertTupleEqual(output, EXPECTED)

        p_kwargs = {'name': 'django', 'version': '2.2', 'found': '/site-packages/django', 'insecure_versions': [],
                    'secure_versions': ['2.2'], 'latest_version_without_known_vulnerabilities': '2.2',
                    'latest_version': '2.2', 'more_info_url': 'https://pyup.io/package/foo'}
        ctx.return_value = Mock(packages=[Package(**p_kwargs)])
        output = get_printable_list_of_scanned_items('stdin')

        EXPECTED = (
            [[{'styled': False, 'value': 'django'}]],
            ['django'])

        self.assertTupleEqual(output, EXPECTED)

    @patch("safety.output_utils.SafetyContext")
    def test_get_printable_list_of_scanned_items_environment(self, ctx):
        ctx.return_value = Mock(packages=[])
        output = get_printable_list_of_scanned_items('environment')

        no_locations = 'No locations found in the environment'

        EXPECTED = (
            [[{'styled': False, 'value': no_locations}]],
            [no_locations])

        self.assertTupleEqual(output, EXPECTED)

    @patch("safety.output_utils.SafetyContext")
    def test_get_printable_list_of_scanned_items_files(self, ctx):
        dirname = os.path.dirname(__file__)
        file_a = open(os.path.join(dirname, "reqs_1.txt"), mode='r')
        file_b = open(os.path.join(dirname, "reqs_4.txt"), mode='r')

        ctx.return_value = Mock(params={'files': [file_a, file_b]})
        output = get_printable_list_of_scanned_items('files')

        EXPECTED = ([
                        [{'styled': False, 'value': f'-> {file_a.name}'}],
                        [{'styled': False, 'value': f'-> {file_b.name}'}]
                    ],
                    [file_a.name, file_b.name])

        self.assertTupleEqual(output, EXPECTED)

    @patch("safety.output_utils.SafetyContext")
    def test_get_printable_list_of_scanned_items_file(self, ctx):
        # Used by the review command
        report = open(os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_db",
            "report.json"
        ), mode='r')

        ctx.return_value = Mock(params={'file': report})
        output = get_printable_list_of_scanned_items('file')

        EXPECTED = (
            [[{'styled': False, 'value': f'-> {report.name}'}]],
            [report.name])

        self.assertTupleEqual(output, EXPECTED)

    @patch("safety.output_utils.is_using_api_key")
    def test_build_remediation_section_with_api_key(self, is_using_api_key):
        is_using_api_key.return_value = True

        remediations = {
            'django': {'vulns_found': 1, 'version': '4.0.1', 'secure_versions': ['2.2.28', '3.2.13', '4.0.4'],
                       'closest_secure_version': {'major': parse('4.0.4'),
                                                  'minor': None},
                       'more_info_url': 'https://pyup.io/packages/pypi/django/'}}

        EXPECTED = ['   REMEDIATIONS',
                    '\n-> django version 4.0.1 was found, which has 1 vulnerability'
                    '\n   The closest version with no known vulnerabilities is 4.0.4'
                    '\n                                                                              '
                    '\n   We recommend upgrading to version 4.0.4 of django. Other versions'
                    '\n   without known vulnerabilities are: 2.2.28, 3.2.13'
                    '\n   For more information, please visit https://pyup.io/packages/pypi/django/'
                    '\n   Always check for breaking changes when upgrading packages.'
                    '\n                                                                              ',
                    '+==============================================================================+']

        rem_text_section = build_remediation_section(remediations=remediations, only_text=True, columns=80)
        self.assertEqual(rem_text_section, EXPECTED)

    @patch("safety.output_utils.is_using_api_key")
    def test_build_remediation_section_without_api_key(self, is_using_api_key):
        is_using_api_key.return_value = False

        remediations = {
            'django': {'vulns_found': 1, 'version': '4.0.1', 'secure_versions': ['2.2.28', '3.2.13', '4.0.4'],
                       'closest_secure_version': {'major': parse('4.0.4'),
                                                  'minor': None},
                       'more_info_url': 'https://pyup.io/packages/pypi/django/'}}

        # Start & End line decorator in format_long_text affects this output
        EXPECTED = ['   REMEDIATIONS',
                    '\n  1 vulnerability was found in 1 package. For detailed remediation & fix \n'
                    '  recommendations, upgrade to a commercial license. \n',
                    '+==============================================================================+']

        rem_text_section = build_remediation_section(remediations=remediations, only_text=True, columns=80)

        self.assertEqual(rem_text_section, EXPECTED)

    def test_get_final_brief_license(self):
        licenses = set(["MIT"])
        EXPECTED = f' The following software licenses were present in your system: {", ".join(licenses)} '
        brief = get_final_brief_license(licenses)
        self.assertEqual(EXPECTED, brief)

        licenses = set([])
        EXPECTED = '  Scan was completed. '
        brief = get_final_brief_license(licenses)
        self.assertEqual(EXPECTED, brief)

