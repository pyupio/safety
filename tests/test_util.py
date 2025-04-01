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
