import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime
from packaging.specifiers import SpecifierSet

from safety.scan.ecosystems.python.main import (
    should_fail, VulnerabilitySeverityLabels,
    ignore_vuln_if_needed, get_vulnerability, PythonFile
)
from safety_schemas.models import (
    ConfigModel, Vulnerability, PythonDependency, PythonSpecification,
    FileType, IgnoredItems, IgnoredItemDetail, IgnoreCodes
)
from safety.models import Severity

class TestMain(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.vulnerability = MagicMock()
        self.dependency = MagicMock(spec=PythonDependency)
        self.file_type = MagicMock(spec=FileType)
        self.vuln_id = "vuln_id"
        self.cve = MagicMock()
        self.ignore_vulns = {}
        self.specification = MagicMock(spec=PythonSpecification)
        self.config.dependency_vulnerability = MagicMock()

    def test_fail_on_disabled(self):
        self.config.dependency_vulnerability.fail_on.enabled = False
        result = should_fail(self.config, self.vulnerability)
        self.assertFalse(result)

    def test_severity_none(self):
        self.config.dependency_vulnerability.fail_on.enabled = True
        self.vulnerability.severity = None
        result = should_fail(self.config, self.vulnerability)
        self.assertFalse(result)

    def test_severity_none_with_fail_on_unknow_none(self):
        self.config.depedendency_vulnerability.fail_on.enabled = True
        self.vulnerability.severity = None

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.UNKNOWN]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.NONE]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.UNKNOWN,
                                                                        VulnerabilitySeverityLabels.NONE]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.LOW,
                                                                        VulnerabilitySeverityLabels.MEDIUM]
        self.assertFalse(should_fail(self.config, self.vulnerability))

        self.vulnerability.severity = MagicMock()
        self.vulnerability.severity.cvssv3 = {"base_severity": "NONE"}

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.NONE]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.UNKNOWN]
        self.assertFalse(should_fail(self.config, self.vulnerability))

        self.vulnerability.severity.cvssv3 = {"base_severity": "UNKNOWN"}
        self.assertTrue(should_fail(self.config, self.vulnerability))

    def test_known_severity_failure(self):
        self.config.depedendency_vulnerability.fail_on.enabled = True
        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.HIGH]
        self.vulnerability.severity.cvssv3 = {"base_severity": "HIGH"}
        result = should_fail(self.config, self.vulnerability)
        self.assertTrue(result)

    def test_unexpected_severity_with_warning(self):
        self.config.depedendency_vulnerability.fail_on.enabled = True
        self.config.depedendency_vulnerability.fail_on.cvss_severity = [VulnerabilitySeverityLabels.HIGH]
        self.vulnerability.severity.cvssv3 = {"base_severity": "UNKNOWN_SEVERITY"}
        with self.assertLogs(level='WARNING') as log:
            result = should_fail(self.config, self.vulnerability)
            self.assertIn("Unexpected base severity value", log.output[0])
        self.assertFalse(result)

    def test_ignore_vuln_if_needed_ignore_environment(self):
        self.file_type = FileType.VIRTUAL_ENVIRONMENT
        ignore_vuln_if_needed(
            dependency=self.dependency, file_type=self.file_type,
            vuln_id=self.vuln_id, cve=self.cve,
            ignore_vulns=self.ignore_vulns, ignore_unpinned=False,
            ignore_environment=True, specification=self.specification
        )
        self.assertIn(self.vuln_id, self.ignore_vulns)
        self.assertEqual(self.ignore_vulns[self.vuln_id].code, IgnoreCodes.environment_dependency)


    def test_python_file_init(self):
        file_type = FileType.VIRTUAL_ENVIRONMENT
        file = MagicMock()
        python_file = PythonFile(file_type, file)
        self.assertEqual(python_file.ecosystem, file_type.ecosystem)
        self.assertEqual(python_file.file_type, file_type)


    @patch('safety.scan.ecosystems.python.main.get_from_cache', return_value={})
    def test_python_file_remediate_no_db_full(self, mock_get_from_cache):
        file_type = FileType.VIRTUAL_ENVIRONMENT
        file = MagicMock()
        python_file = PythonFile(file_type, file)
        python_file.dependency_results = MagicMock()
        python_file.remediate()
        mock_get_from_cache.assert_called_once_with(db_name="insecure_full.json", skip_time_verification=True)

    @patch('safety.scan.ecosystems.python.main.get_from_cache')
    def test_python_file_remediate_with_db_full(self, mock_get_from_cache):
        mock_get_from_cache.return_value = {
            'vulnerable_packages': {
                'dependency_name': [
                    {
                        'type': 'pyup',
                        'ids': [{'type': 'pyup', 'id': 'vuln_id'}],
                        'affected_versions': ['1.0.0']
                    }
                ]
            }
        }
        file_type = FileType.VIRTUAL_ENVIRONMENT
        file = MagicMock()
        python_file = PythonFile(file_type, file)
        dependency = MagicMock(spec=PythonDependency)
        dependency.name = "dependency_name"
        dependency.specifications = [MagicMock(spec=PythonSpecification)]
        dependency.secure_versions = ["1.0.1"]
        python_file.dependency_results = MagicMock()
        python_file.dependency_results.get_affected_dependencies.return_value = [dependency]

        # Mock vulnerabilities attribute
        for spec in dependency.specifications:
            spec.vulnerabilities = []

        python_file.remediate()

        mock_get_from_cache.assert_called_with(db_name="insecure_full.json", skip_time_verification=True)
        self.assertEqual(dependency.secure_versions, ["1.0.1"])
