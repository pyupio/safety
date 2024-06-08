import unittest
from unittest.mock import MagicMock
from safety.scan.ecosystems.python.main import should_fail, VulnerabilitySeverityLabels

class TestMain(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.vulnerability = MagicMock()

    def test_fail_on_disabled(self):
        self.config.depedendency_vulnerability.fail_on.enabled = False
        result = should_fail(self.config, self.vulnerability)
        self.assertFalse(result)

    def test_severity_none(self):
        self.config.depedendency_vulnerability.fail_on.enabled = True
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
