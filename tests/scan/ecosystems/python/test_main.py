import unittest
from unittest.mock import MagicMock, patch
from safety.scan.ecosystems.python.main import (
    PythonFile,
    should_fail,
    VulnerabilitySeverityLabels,
)


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

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.UNKNOWN
        ]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.NONE
        ]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.UNKNOWN,
            VulnerabilitySeverityLabels.NONE,
        ]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.LOW,
            VulnerabilitySeverityLabels.MEDIUM,
        ]
        self.assertFalse(should_fail(self.config, self.vulnerability))

        self.vulnerability.severity = MagicMock()
        self.vulnerability.severity.cvssv3 = {"base_severity": "NONE"}

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.NONE
        ]
        self.assertTrue(should_fail(self.config, self.vulnerability))

        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.UNKNOWN
        ]
        self.assertFalse(should_fail(self.config, self.vulnerability))

        self.vulnerability.severity.cvssv3 = {"base_severity": "UNKNOWN"}
        self.assertTrue(should_fail(self.config, self.vulnerability))

    def test_known_severity_failure(self):
        self.config.depedendency_vulnerability.fail_on.enabled = True
        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.HIGH
        ]
        self.vulnerability.severity.cvssv3 = {"base_severity": "HIGH"}
        result = should_fail(self.config, self.vulnerability)
        self.assertTrue(result)

    def test_unexpected_severity_with_warning(self):
        self.config.depedendency_vulnerability.fail_on.enabled = True
        self.config.depedendency_vulnerability.fail_on.cvss_severity = [
            VulnerabilitySeverityLabels.HIGH
        ]
        self.vulnerability.severity.cvssv3 = {"base_severity": "UNKNOWN_SEVERITY"}
        with self.assertLogs(level="WARNING") as log:
            result = should_fail(self.config, self.vulnerability)
            self.assertIn("Unexpected base severity value", log.output[0])
        self.assertFalse(result)


class TestLoadFullDb(unittest.TestCase):
    def setUp(self):
        self.python_file = PythonFile(file_type=MagicMock(), file=MagicMock())

    @patch("safety.scan.ecosystems.python.main.get_from_cache")
    def test_returns_db_when_cache_is_available(self, mock_get_from_cache):
        db_full = {"vulnerable_packages": {}}
        mock_get_from_cache.return_value = db_full

        result = self.python_file._load_full_db()
        self.assertIs(result, db_full)

        mock_get_from_cache.assert_called_once_with(
            db_name="insecure_full.json", skip_time_verification=True
        )

    @patch("safety.scan.ecosystems.python.main.get_from_cache")
    def test_returns_none_and_logs_when_cache_is_missing(self, mock_get_from_cache):
        mock_get_from_cache.return_value = None

        with self.assertLogs(level="DEBUG") as log:
            result = self.python_file._load_full_db()

        self.assertIsNone(result)
        self.assertIn("insecure_full.json", log.output[0])
