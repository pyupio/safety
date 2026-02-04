import unittest
import tempfile
from importlib.metadata import version
from click.testing import CliRunner
from packaging.version import Version
from safety.auth.models import Auth
from safety.cli import cli
from safety.console import main_console as console
from safety.scan.command import sort_and_filter_vulnerabilities
from unittest.mock import patch, MagicMock


class TestSortAndFilterVulnerabilities(unittest.TestCase):
    """Tests for sort_and_filter_vulnerabilities function"""

    def test_filters_ignored_vulnerabilities(self):
        """Test that ignored vulnerabilities are filtered out"""
        vuln1 = MagicMock()
        vuln1.ignored = False
        vuln1.score = 7.5

        vuln2 = MagicMock()
        vuln2.ignored = True
        vuln2.score = 9.0

        vuln3 = MagicMock()
        vuln3.ignored = False
        vuln3.score = 5.0

        vulnerabilities = [vuln1, vuln2, vuln3]

        result = sort_and_filter_vulnerabilities(
            vulnerabilities,
            key_func=lambda v: v.score
        )

        # Should only have 2 non-ignored vulnerabilities
        self.assertEqual(len(result), 2)
        # vuln2 (ignored) should not be in results
        self.assertNotIn(vuln2, result)
        # Results should be sorted by score descending
        self.assertEqual(result[0], vuln1)  # score 7.5
        self.assertEqual(result[1], vuln3)  # score 5.0

    def test_empty_list_when_all_ignored(self):
        """Test that empty list is returned when all vulnerabilities are ignored"""
        vuln1 = MagicMock()
        vuln1.ignored = True

        vuln2 = MagicMock()
        vuln2.ignored = True

        vulnerabilities = [vuln1, vuln2]

        result = sort_and_filter_vulnerabilities(
            vulnerabilities,
            key_func=lambda v: 0
        )

        self.assertEqual(len(result), 0)

    def test_non_empty_list_triggers_exit_code(self):
        """
        Test that non-ignored vulnerabilities should trigger exit code.
        This tests the condition: if exit_code == 0 and vulns_to_report:
        """
        vuln1 = MagicMock()
        vuln1.ignored = False
        vuln1.score = 7.5

        vulnerabilities = [vuln1]

        result = sort_and_filter_vulnerabilities(
            vulnerabilities,
            key_func=lambda v: v.score
        )

        # Non-empty result should evaluate to True for exit code check
        self.assertTrue(bool(result))
        self.assertEqual(len(result), 1)


class TestScanCommand(unittest.TestCase):
    def setUp(self):
        # mix_stderr was removed in Click 8.2.0
        if Version(version("click")) >= Version("8.2.0"):
            self.runner = CliRunner()
        else:
            self.runner = CliRunner(mix_stderr=False)
        self.target = tempfile.mkdtemp()
        # Make sure the console is not quiet
        # TODO: This is a workaround, we should improve the way the console
        # is initialized in the CLI
        console.quiet = False

        cli.commands = cli.all_commands
        self.cli = cli

    @patch.object(Auth, "is_valid", return_value=False)
    @patch(
        "safety.platform.SafetyPlatformClient.get_authentication_type",
        return_value="unauthenticated",
    )
    def test_scan(self, mock_is_valid, mock_get_auth_type):
        result = self.runner.invoke(
            self.cli, ["scan", "--target", self.target, "--output", "json"]
        )
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(
            self.cli,
            [
                "--stage",
                "production",
                "scan",
                "--target",
                self.target,
                "--output",
                "json",
            ],
        )
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(
            self.cli,
            ["--stage", "cicd", "scan", "--target", self.target, "--output", "screen"],
        )
        self.assertEqual(result.exit_code, 1)
