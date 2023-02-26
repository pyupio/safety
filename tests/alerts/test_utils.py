import unittest
from unittest.mock import patch, MagicMock, mock_open

from safety.alerts import utils
from tests.test_cli import get_vulnerability


class TestUtils(unittest.TestCase):
    def setUp(self):
        self.pkg = "requests"
        severity_kwargs = [
            {'name': 'CVE-2014-0474', 'cvssv2': None, 'cvssv3': None},
            {'name': 'CVE-2019-3498',
             'cvssv2': {"base_score": 4.3, "impact_score": 2.9,
                        "vector_string": "AV:N/AC:M/Au:N/C:N/I:P/A:N"},
             'cvssv3': {"base_score": 6.5, "impact_score": 3.6, "base_severity": "MEDIUM",
                        "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"}},
            {'name': 'CVE-2021-29601', 'cvssv2': None,
             'cvssv3': {"base_score": 7.1, "impact_score": 5.2, "base_severity": "HIGH",
                        "vector_string": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"}},
            {'name': 'CVE-2021-29601', 'cvssv2': {"base_score": 4.3, "impact_score": 2.9,
                                                  "vector_string": "AV:N/AC:M/Au:N/C:N/I:P/A:N"},
             'cvssv3': None}
        ]
        self.vulns = list(map(lambda cve_kwargs: get_vulnerability(cve_kwargs=cve_kwargs).to_dict(), severity_kwargs))
        self.unpinned_remediation = {
            "version": None,
            "recommended_version": "2.22.0",
            "requirement": {"name": "requests", "specifier": ">=2.21.0,<2.22.0"}
        }
        self.pinned_remediation = {
            "version": '2.21.0',
            "recommended_version": "2.22.0",
            "requirement": {"name": "requests", "specifier": "==2.21.0"}
        }
        self.api_key = "api_key"

    def test_highest_base_score_with_an_unknown_cvssv3(self):
        score = utils.highest_base_score(self.vulns)
        # TODO: This needs validation with users, it at least a CVSSv3 is None, then it returns 10
        self.assertEqual(score, 10)

    def test_highest_base_score(self):
        cvssv3_vulns = filter(lambda v: (v.get('severity', {}) or {}).get('cvssv3', {}), self.vulns)
        score = utils.highest_base_score(cvssv3_vulns)
        self.assertEqual(score, 7.1)

    def test_generate_branch_name_unpinned_remediation(self):
        branch_name = utils.generate_branch_name(self.pkg, self.unpinned_remediation)
        self.assertEqual(branch_name, "requests/>=2.21.0,<2.22.0/2.22.0")

    def test_generate_branch_name_pinned_remediation(self):
        branch_name = utils.generate_branch_name(self.pkg, self.pinned_remediation)
        self.assertEqual(branch_name, "requests/==2.21.0/2.22.0")

    def test_generate_issue_title_unpinned_remediation(self):
        issue_title = utils.generate_issue_title(self.pkg, self.unpinned_remediation)
        self.assertEqual(issue_title, "Security Vulnerability in requests>=2.21.0,<2.22.0")

    def test_generate_issue_title_pinned_remediation(self):
        issue_title = utils.generate_issue_title(self.pkg, self.pinned_remediation)
        self.assertEqual(issue_title, "Security Vulnerability in requests==2.21.0")

    def test_generate_title_pinned_remediation(self):
        title = utils.generate_title(self.pkg, self.pinned_remediation, [self.vulns[0]])
        self.assertEqual(title, "Update requests from 2.21.0 to 2.22.0 to fix 1 vulnerability")

        title = utils.generate_title(self.pkg, self.pinned_remediation, self.vulns)
        self.assertEqual(title, "Update requests from 2.21.0 to 2.22.0 to fix 4 vulnerabilities")

    def test_generate_title_unpinned_remediation(self):
        title = utils.generate_title(self.pkg, self.unpinned_remediation, [self.vulns[0]])
        self.assertEqual(title, "Update requests from >=2.21.0,<2.22.0 to 2.22.0 to fix 1 vulnerability")

        title = utils.generate_title(self.pkg, self.unpinned_remediation, self.vulns)
        self.assertEqual(title, "Update requests from >=2.21.0,<2.22.0 to 2.22.0 to fix 4 vulnerabilities")

    def test_cvss3_score_to_label_low_score(self):
        score = 1.5
        expected_label = 'low'
        self.assertEqual(utils.cvss3_score_to_label(score), expected_label)

    def test_cvss3_score_to_label_medium_score(self):
        score = 5.2
        expected_label = 'medium'
        self.assertEqual(utils.cvss3_score_to_label(score), expected_label)

    def test_cvss3_score_to_label_high_score(self):
        score = 7.8
        expected_label = 'high'
        self.assertEqual(utils.cvss3_score_to_label(score), expected_label)

    def test_cvss3_score_to_label_critical_score(self):
        score = 10.0
        expected_label = 'critical'
        self.assertEqual(utils.cvss3_score_to_label(score), expected_label)

    def test_cvss3_score_to_label_invalid_score(self):
        score = -1.0
        expected_label = None
        self.assertEqual(utils.cvss3_score_to_label(score), expected_label)

        score = 11.0
        expected_label = None
        self.assertEqual(utils.cvss3_score_to_label(score), expected_label)
