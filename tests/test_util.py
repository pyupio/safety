# type: ignore
import os
import sys
import unittest
from io import StringIO
from unittest.mock import MagicMock, patch, Mock

import click as click

from safety import util
from safety.models import SafetyRequirement
from safety.util import (
    read_requirements,
    get_processed_options,
    SafetyPolicyFile,
    transform_ignore,
)


class ReadRequirementsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dirname = os.path.dirname(__file__)

    def test_unpinned_vcs_requirement(self):
        """
        https://github.com/pyupio/safety/issues/72
        """
        # this shouldn't raise an error
        content = StringIO(
            "-e git+https://github.com/jdunck/python-unicodecsv#egg=unicodecsv"
        )
        result = list(read_requirements(content))
        self.assertEqual(len(result), 0)

    def test_recursive_requirement(self):
        """
        https://github.com/pyupio/safety/issues/132
        """
        # this should find 1 packages with two requirements found
        dirname = os.path.dirname(__file__)
        test_filename = os.path.join(dirname, "reqs_1.txt")
        with open(test_filename) as fh:
            result = list(read_requirements(fh, resolve=True))
        self.assertEqual(len(result), 1)
        found_pkg = result[0]
        self.assertEqual(found_pkg.name, "insecure-package")
        self.assertEqual(found_pkg.version, None)
        expected = [
            SafetyRequirement("insecure-package==0.1.0"),
            SafetyRequirement("insecure-package==0.1.1"),
        ]
        self.assertListEqual(expected, found_pkg.requirements)

    def test_recursive_requirement_pinned_after_unpinned(self):
        # this should find 4 packages, unpinned aren't ignored.
        dirname = os.path.dirname(__file__)
        test_filename = os.path.join(dirname, "reqs_pinned_and_unpinned.txt")
        with open(test_filename) as fh:
            result = list(read_requirements(fh, resolve=True))
        self.assertEqual(len(result), 4)

    @patch("safety.util.get_flags_from_context")
    @patch.object(
        sys,
        "argv",
        [
            "safety/__main__.py",
            "check",
            "--key=my-key",
            "-i",
            "3232",
            "-i",
            "3231",
            "--ignore",
            "1212",
            "--json",
        ],
    )
    def test_log_used_options_with_argv(self, get_flags_from_context):
        get_flags_from_context.return_value = {
            "--key": "key",
            "--db": "db",
            "--json": "json",
            "--no-json": "json",
            "--full-report": "full_report",
            "--short-report": "full_report",
            "--bare": "bare",
            "--not-bare": "bare",
            "--cache": "cache",
            "--no-cache": "cache",
            "--stdin": "stdin",
            "--no-stdin": "stdin",
            "--file": "files",
            "-r": "files",
            "--ignore": "ignore",
            "-i": "ignore",
            "--output": "output",
            "-o": "output",
            "--proxy-host": "proxyhost",
            "-ph": "proxyhost",
            "--proxy-port": "proxyport",
            "-pp": "proxyport",
            "--proxy-protocol": "proxyprotocol",
            "-pr": "proxyprotocol",
        }
        used_options = util.get_used_options()

        self.assertEqual(
            used_options,
            {
                "ignore": {"-i": 2, "--ignore": 1},
                "json": {"--json": 1},
                "key": {"--key": 1},
            },
        )

    @patch.object(
        click,
        "get_current_context",
        Mock(
            get_parameter_source=Mock(return_value=click.core.ParameterSource.DEFAULT)
        ),
    )
    def test_cli_ignore_overrule_policy_file(self):
        path_pf = os.path.join(self.dirname, ".policy_with_ignores.yml")
        policy_file = SafetyPolicyFile().convert(value=path_pf, param=None, ctx=None)

        cli_ignores = {"1234": {"reason": "", "expires": None}}
        ignore, ignore_severity_rules, exit_code, ignore_unpinned_packages, project = (
            get_processed_options(
                policy_file=policy_file,
                ignore=cli_ignores,
                ignore_severity_rules=None,
                exit_code=True,
            )
        )

        self.assertEqual(ignore, cli_ignores)

    @patch.object(
        click,
        "get_current_context",
        Mock(
            get_parameter_source=Mock(
                return_value=click.core.ParameterSource.COMMANDLINE
            )
        ),
    )
    def test_cli_continue_on_error_overrule_policy_file(self):
        path_pf = os.path.join(self.dirname, ".policy_full.yml")
        policy_file = SafetyPolicyFile().convert(value=path_pf, param=None, ctx=None)

        ignore, ignore_severity_rules, exit_code, ignore_unpinned_packages, project = (
            get_processed_options(
                policy_file=policy_file,
                ignore={},
                ignore_severity_rules=None,
                exit_code=True,
            )
        )

        self.assertEqual(exit_code, True)

    @patch.object(
        click,
        "get_current_context",
        Mock(
            get_parameter_source=Mock(
                return_value=click.core.ParameterSource.COMMANDLINE
            )
        ),
    )
    def test_cli_exit_code_partial_overrule_policy_file(self):
        path_pf = os.path.join(self.dirname, ".policy_full.yml")
        policy_file = SafetyPolicyFile().convert(value=path_pf, param=None, ctx=None)

        # Cli only passes the exit_code argument by commandline
        ignore, ignore_severity_rules, exit_code, ignore_unpinned_packages, project = (
            get_processed_options(
                policy_file=policy_file,
                ignore={},
                ignore_severity_rules=None,
                exit_code=True,
            )
        )

        security_pf = policy_file.get("security", {})
        severity_rules = {
            "ignore-cvss-severity-below": security_pf.get(
                "ignore-cvss-severity-below", 0.0
            ),
            "ignore-cvss-unknown-severity": security_pf.get(
                "ignore-cvss-unknown-severity", False
            ),
        }

        self.assertEqual(ignore, security_pf.get("ignore-vulnerabilities", None))
        self.assertEqual(ignore_severity_rules, severity_rules)
        self.assertEqual(exit_code, True)

    @patch.object(
        click,
        "get_current_context",
        Mock(
            get_parameter_source=Mock(return_value=click.core.ParameterSource.DEFAULT)
        ),
    )
    def test_cli_ignore_partial_overrule_policy_file(self):
        path_pf = os.path.join(self.dirname, ".policy_full.yml")
        policy_file = SafetyPolicyFile().convert(value=path_pf, param=None, ctx=None)

        # Cli only passes the ignores argument by commandline
        cli_ignores = {"1234": {"reason": "", "expires": None}}
        ignore, ignore_severity_rules, exit_code, ignore_unpinned_packages, project = (
            get_processed_options(
                policy_file=policy_file,
                ignore=cli_ignores,
                ignore_severity_rules=None,
                exit_code=True,
            )
        )

        security_pf = policy_file.get("security", {})
        severity_rules = {
            "ignore-cvss-severity-below": security_pf.get(
                "ignore-cvss-severity-below", 0.0
            ),
            "ignore-cvss-unknown-severity": security_pf.get(
                "ignore-cvss-unknown-severity", False
            ),
        }

        self.assertEqual(ignore, cli_ignores)
        self.assertEqual(ignore_severity_rules, severity_rules)
        self.assertIsNotNone(
            security_pf.get("continue-on-vulnerability-error", None),
            msg="This test requires a yml with a continue-on-vulnerability-error value",
        )
        EXPECTED = not security_pf.get("continue-on-vulnerability-error")
        self.assertEqual(exit_code, EXPECTED)

    def test_transform_ignore(self):
        ignored_transformed = {
            "123": {"expires": None, "reason": ""},
            "456": {"expires": None, "reason": ""},
        }
        self.assertEqual(
            transform_ignore(None, None, value=("123", "456")), ignored_transformed
        )
        self.assertEqual(
            transform_ignore(None, None, value=("123,456",)), ignored_transformed
        )

    def test_transform_ignore_mixed_arguments(self):
        # mix old and new way of providing --ignore
        ignored_transformed = {
            "123": {"expires": None, "reason": ""},
            "456": {"expires": None, "reason": ""},
            "789": {"expires": None, "reason": ""},
        }
        self.assertEqual(
            transform_ignore(None, None, value=("123,456", "789")), ignored_transformed
        )


class TestInitializeEventBus(unittest.TestCase):
    def setUp(self):
        self.mock_ctx = MagicMock()
        self.mock_obj = MagicMock()
        self.mock_auth = MagicMock()
        self.mock_client = MagicMock()

        self.mock_ctx.obj = self.mock_obj
        self.mock_obj.auth = self.mock_auth
        self.mock_auth.client = self.mock_client
        self.mock_obj.events_enabled = True
        self.mock_obj.event_bus = MagicMock()

    @patch("safety.util.start_event_bus")
    @patch("safety.events.utils.create_internal_event")
    def test_successful_initialization_with_token(
        self, mock_create_event, mock_start_event_bus
    ):
        self.mock_client.token = {"access_token": "test_token"}
        self.mock_client.api_key = None
        mock_event = MagicMock()
        mock_create_event.return_value = mock_event

        from safety.util import initialize_event_bus

        result = initialize_event_bus(self.mock_ctx)

        self.assertTrue(result)
        mock_start_event_bus.assert_called_once_with(self.mock_obj, self.mock_client)
        self.mock_obj.event_bus.emit.assert_called_once_with(mock_event)

    @patch("safety.util.start_event_bus")
    @patch("safety.events.utils.create_internal_event")
    def test_successful_initialization_with_api_key(
        self, mock_create_event, mock_start_event_bus
    ):
        self.mock_client.token = None
        self.mock_client.api_key = "test_api_key"
        mock_event = MagicMock()
        mock_create_event.return_value = mock_event

        from safety.util import initialize_event_bus

        result = initialize_event_bus(self.mock_ctx)

        self.assertTrue(result)
        mock_start_event_bus.assert_called_once_with(self.mock_obj, self.mock_client)
        self.mock_obj.event_bus.emit.assert_called_once_with(mock_event)

    @patch("safety.util.start_event_bus")
    def test_initialization_when_no_authn(self, mock_start_event_bus):
        self.mock_client.token = None
        self.mock_client.api_key = None

        from safety.util import initialize_event_bus

        result = initialize_event_bus(self.mock_ctx)

        self.assertFalse(result)
        mock_start_event_bus.assert_not_called()

    @patch("safety.util.LOG")
    def test_initialization_with_exception(self, mock_log):
        self.mock_client.token = {"access_token": "test_token"}
        self.mock_obj.event_bus = None

        with patch(
            "safety.util.start_event_bus", side_effect=Exception("Test exception")
        ):
            from safety.util import initialize_event_bus

            result = initialize_event_bus(self.mock_ctx)

        self.assertFalse(result)
        mock_log.exception.assert_called_once()


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions that were previously untested."""

    def test_is_a_remote_mirror_with_https(self):
        """Test is_a_remote_mirror with HTTPS URL."""
        from safety.util import is_a_remote_mirror
        
        self.assertTrue(is_a_remote_mirror("https://pypi.org/simple/"))
        
    def test_is_a_remote_mirror_with_http(self):
        """Test is_a_remote_mirror with HTTP URL."""
        from safety.util import is_a_remote_mirror
        
        self.assertTrue(is_a_remote_mirror("http://pypi.org/simple/"))
        
    def test_is_a_remote_mirror_with_local_path(self):
        """Test is_a_remote_mirror with local file path."""
        from safety.util import is_a_remote_mirror
        
        self.assertFalse(is_a_remote_mirror("/local/path/to/mirror"))
        self.assertFalse(is_a_remote_mirror("file:///local/path"))
        self.assertFalse(is_a_remote_mirror(""))
        
    def test_is_supported_by_parser_with_valid_extensions(self):
        """Test is_supported_by_parser with valid file extensions."""
        from safety.util import is_supported_by_parser
        
        valid_files = [
            "requirements.txt",
            "requirements.in", 
            "config.yml",
            "setup.cfg",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            ".safety-policy.yml"
        ]
        
        for file_path in valid_files:
            self.assertTrue(is_supported_by_parser(file_path), f"Failed for {file_path}")
            
    def test_is_supported_by_parser_with_invalid_extensions(self):
        """Test is_supported_by_parser with invalid file extensions."""
        from safety.util import is_supported_by_parser
        
        invalid_files = [
            "requirements.json",
            "config.xml",
            "setup.py",
            "README.md",
            "file.unknown",
            ""
        ]
        
        for file_path in invalid_files:
            self.assertFalse(is_supported_by_parser(file_path), f"Should fail for {file_path}")
            
    def test_get_proxy_dict_with_all_parameters(self):
        """Test get_proxy_dict with all required parameters."""
        from safety.util import get_proxy_dict
        
        result = get_proxy_dict("http", "proxy.example.com", 8080)
        expected = {"https": "http://proxy.example.com:8080"}
        self.assertEqual(result, expected)
        
    def test_get_proxy_dict_with_https_protocol(self):
        """Test get_proxy_dict with HTTPS protocol."""
        from safety.util import get_proxy_dict
        
        result = get_proxy_dict("https", "secure-proxy.example.com", 3128)
        expected = {"https": "https://secure-proxy.example.com:3128"}
        self.assertEqual(result, expected)
        
    def test_get_proxy_dict_with_missing_parameters(self):
        """Test get_proxy_dict returns None when parameters are missing."""
        from safety.util import get_proxy_dict
        
        # Test with missing protocol
        self.assertIsNone(get_proxy_dict("", "proxy.example.com", 8080))
        self.assertIsNone(get_proxy_dict(None, "proxy.example.com", 8080))
        
        # Test with missing host
        self.assertIsNone(get_proxy_dict("http", "", 8080))
        self.assertIsNone(get_proxy_dict("http", None, 8080))
        
        # Test with missing port
        self.assertIsNone(get_proxy_dict("http", "proxy.example.com", 0))
        self.assertIsNone(get_proxy_dict("http", "proxy.example.com", None))
        
    def test_get_license_name_by_id_with_valid_id(self):
        """Test get_license_name_by_id with valid license ID."""
        from safety.util import get_license_name_by_id
        
        db = {
            "licenses": {
                "MIT": 1,
                "Apache-2.0": 2, 
                "GPL-3.0": 3
            }
        }
        
        self.assertEqual(get_license_name_by_id(1, db), "MIT")
        self.assertEqual(get_license_name_by_id(2, db), "Apache-2.0")
        self.assertEqual(get_license_name_by_id(3, db), "GPL-3.0")
        
    def test_get_license_name_by_id_with_invalid_id(self):
        """Test get_license_name_by_id with invalid license ID."""
        from safety.util import get_license_name_by_id
        
        db = {
            "licenses": {
                "MIT": 1,
                "Apache-2.0": 2
            }
        }
        
        self.assertIsNone(get_license_name_by_id(99, db))
        self.assertIsNone(get_license_name_by_id(-1, db))
        
    def test_get_license_name_by_id_with_empty_db(self):
        """Test get_license_name_by_id with empty database."""
        from safety.util import get_license_name_by_id
        
        # Empty database
        self.assertIsNone(get_license_name_by_id(1, {}))
        
        # Database without licenses key
        db = {"other_data": "value"}
        self.assertIsNone(get_license_name_by_id(1, db))
        
        # Database with empty licenses
        db = {"licenses": {}}
        self.assertIsNone(get_license_name_by_id(1, db))
        
    def test_pluralize_with_singular_count(self):
        """Test pluralize function with count of 1."""
        from safety.util import pluralize
        
        self.assertEqual(pluralize("package", 1), "package")
        self.assertEqual(pluralize("vulnerability", 1), "vulnerability")
        self.assertEqual(pluralize("was", 1), "was")
        
    def test_pluralize_with_plural_count(self):
        """Test pluralize function with count greater than 1."""
        from safety.util import pluralize
        
        # Regular plurals
        self.assertEqual(pluralize("package", 2), "packages")
        self.assertEqual(pluralize("vulnerability", 5), "vulnerabilities")
        self.assertEqual(pluralize("dependency", 3), "dependencies")
        
        # Special cases with 's', 'x', 'ch', 'sh' endings
        self.assertEqual(pluralize("class", 2), "classes")
        self.assertEqual(pluralize("box", 2), "boxes")
        self.assertEqual(pluralize("branch", 2), "branches")
        self.assertEqual(pluralize("bush", 2), "bushes")
        
        # Words ending in 'y'
        self.assertEqual(pluralize("library", 2), "libraries")
        self.assertEqual(pluralize("key", 2), "keys")  # vowel before 'y'
        
        # Default mappings
        self.assertEqual(pluralize("was", 2), "were")
        self.assertEqual(pluralize("this", 2), "these")
        self.assertEqual(pluralize("has", 2), "have")
        
    def test_pluralize_with_zero_count(self):
        """Test pluralize function with count of 0."""
        from safety.util import pluralize
        
        self.assertEqual(pluralize("package", 0), "packages")
        self.assertEqual(pluralize("was", 0), "were")
        
    def test_clean_project_id_with_valid_input(self):
        """Test clean_project_id with valid input strings."""
        from safety.util import clean_project_id
        
        self.assertEqual(clean_project_id("MyProject"), "myproject")
        self.assertEqual(clean_project_id("my-project"), "my-project")
        self.assertEqual(clean_project_id("my_project"), "my-project")
        
    def test_clean_project_id_with_special_characters(self):
        """Test clean_project_id with special characters."""
        from safety.util import clean_project_id
        
        self.assertEqual(clean_project_id("my@project#123"), "my-project-123")
        self.assertEqual(clean_project_id("Project Name With Spaces"), "project-name-with-spaces")
        self.assertEqual(clean_project_id("project!!!"), "project")
        
    def test_clean_project_id_with_edge_cases(self):
        """Test clean_project_id with edge cases."""
        from safety.util import clean_project_id
        
        # Leading/trailing non-alphanumeric characters
        self.assertEqual(clean_project_id("---project---"), "project")
        self.assertEqual(clean_project_id("@@@"), "")
        self.assertEqual(clean_project_id(""), "")
        
    def test_validate_expiration_date_with_valid_dates(self):
        """Test validate_expiration_date with valid date formats."""
        from safety.util import validate_expiration_date
        from datetime import datetime
        
        # YYYY-MM-DD format
        result = validate_expiration_date("2024-12-31")
        self.assertIsInstance(result, datetime)
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 12)
        self.assertEqual(result.day, 31)
        
        # YYYY-MM-DD HH:MM:SS format
        result = validate_expiration_date("2024-12-31 23:59:59")
        self.assertIsInstance(result, datetime)
        self.assertEqual(result.hour, 23)
        self.assertEqual(result.minute, 59)
        self.assertEqual(result.second, 59)
        
    def test_validate_expiration_date_with_invalid_dates(self):
        """Test validate_expiration_date with invalid date formats."""
        from safety.util import validate_expiration_date
        
        invalid_dates = [
            "invalid-date",
            "2024-13-01",  # Invalid month
            "2024-12-32",  # Invalid day
            "2024/12/31",  # Wrong format
            "Dec 31, 2024",  # Wrong format
            "",
            None
        ]
        
        for invalid_date in invalid_dates:
            result = validate_expiration_date(invalid_date)
            self.assertIsNone(result, f"Should return None for {invalid_date}")
            
    def test_build_remediation_info_url_with_version(self):
        """Test build_remediation_info_url with version parameters."""
        from safety.util import build_remediation_info_url
        
        base_url = "https://example.com/remediation"
        result = build_remediation_info_url(base_url, "1.0.0", ">=1.0.0", "2.0.0")
        
        self.assertIn("from=1.0.0", result)
        self.assertIn("to=2.0.0", result)
        self.assertTrue(result.startswith(base_url))
        
    def test_build_remediation_info_url_without_version(self):
        """Test build_remediation_info_url without version (unpinned)."""
        from safety.util import build_remediation_info_url
        
        base_url = "https://example.com/remediation"
        spec = ">=1.0.0"
        result = build_remediation_info_url(base_url, None, spec, "2.0.0")
        
        self.assertIn(f"spec={spec.replace('>=', '%3E%3D')}", result)
        self.assertTrue(result.startswith(base_url))
        
    def test_get_terminal_size(self):
        """Test get_terminal_size function."""
        from safety.util import get_terminal_size
        import os
        
        result = get_terminal_size()
        self.assertIsInstance(result, os.terminal_size)
        
        # Terminal size should have reasonable defaults
        self.assertGreaterEqual(result.columns, 80)
        self.assertGreaterEqual(result.lines, 24)
        
    @patch("shutil.get_terminal_size")
    def test_get_terminal_size_with_zero_values(self, mock_get_terminal_size):
        """Test get_terminal_size when system returns 0 values."""
        from safety.util import get_terminal_size
        import os
        
        # Mock system returning 0 values (common in some environments)
        mock_terminal_size = os.terminal_size((0, 0))
        mock_get_terminal_size.return_value = mock_terminal_size
        
        result = get_terminal_size()
        
        # Should fall back to defaults
        self.assertEqual(result.columns, 80)
        self.assertEqual(result.lines, 24)
        
    def test_get_hashes_with_valid_dependency(self):
        """Test get_hashes function with valid dependency hashes."""
        from safety.util import get_hashes
        from unittest.mock import MagicMock
        
        # Mock dependency with hash strings
        mock_dependency = MagicMock()
        mock_dependency.hashes = [
            "--hash=sha256:abcd1234",
            "--hash sha256:efgh5678",
            "--hash=md5:ijkl9012"
        ]
        
        result = get_hashes(mock_dependency)
        
        expected = [
            {"method": "sha256", "hash": "abcd1234"},
            {"method": "sha256", "hash": "efgh5678"},
            {"method": "md5", "hash": "ijkl9012"}
        ]
        
        self.assertEqual(result, expected)
        
    def test_get_hashes_with_empty_dependency(self):
        """Test get_hashes function with dependency that has no hashes."""
        from safety.util import get_hashes
        from unittest.mock import MagicMock
        
        # Mock dependency with no hashes
        mock_dependency = MagicMock()
        mock_dependency.hashes = []
        
        result = get_hashes(mock_dependency)
        self.assertEqual(result, [])
        
    def test_is_supported_by_parser_security_file_extensions(self):
        """Test is_supported_by_parser with security-relevant file extensions."""
        from safety.util import is_supported_by_parser
        
        # Additional security-relevant files that should be supported
        security_files = [
            "requirements-dev.txt",
            "requirements-test.txt", 
            "dev-requirements.txt",
            "test-requirements.txt",
            "constraints.txt",
            "pip.conf"  # False - not supported but testing edge case
        ]
        
        # These should be supported (have valid extensions)
        for file_path in security_files[:5]:  # First 5 are .txt/.ini files
            self.assertTrue(is_supported_by_parser(file_path), f"Should support {file_path}")
            
        # This should not be supported (.conf is not in the supported list)
        self.assertFalse(is_supported_by_parser("pip.conf"))
        
    def test_clean_project_id_security_considerations(self):
        """Test clean_project_id with potential security injection patterns."""
        from safety.util import clean_project_id
        
        # Test potential injection patterns are properly sanitized
        malicious_inputs = [
            "../../../etc/passwd",
            "project<script>alert('xss')</script>", 
            "project; rm -rf /",
            "project && echo 'injected'",
            "project|cat /etc/passwd",
            "project`whoami`",
            "project$(id)"
        ]
        
        for malicious_input in malicious_inputs:
            result = clean_project_id(malicious_input)
            
            # Should not contain dangerous characters
            self.assertNotIn("..", result)
            self.assertNotIn("/", result) 
            self.assertNotIn("<", result)
            self.assertNotIn(">", result)
            self.assertNotIn(";", result)
            self.assertNotIn("&", result)
            self.assertNotIn("|", result)
            self.assertNotIn("`", result)
            self.assertNotIn("$", result)
            self.assertNotIn("(", result)
            self.assertNotIn(")", result)
            
            # Should only contain alphanumeric characters and hyphens
            self.assertTrue(all(c.isalnum() or c == '-' for c in result if result))
            
    def test_validate_expiration_date_security_edge_cases(self):
        """Test validate_expiration_date with security-relevant edge cases."""
        from safety.util import validate_expiration_date
        
        # Test dates that could cause issues in security contexts
        edge_case_dates = [
            "1970-01-01",  # Unix epoch
            "2038-01-19",  # 32-bit timestamp limit
            "9999-12-31",  # Far future date
            "1900-01-01",  # Very old date
            "2024-02-29",  # Leap year
            "2023-02-29",  # Invalid leap year
        ]
        
        # First 5 should be valid dates
        for valid_date in edge_case_dates[:5]:
            result = validate_expiration_date(valid_date)
            self.assertIsNotNone(result, f"Should accept valid date {valid_date}")
            
        # Last one should be invalid (2023 is not a leap year)
        invalid_leap = validate_expiration_date("2023-02-29")
        self.assertIsNone(invalid_leap, "Should reject invalid leap year date")
