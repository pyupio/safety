import os
import unittest
import tempfile
from importlib.metadata import version
from click.testing import CliRunner
from packaging.version import Version
from safety.auth.models import Auth
from safety.cli import cli
from safety.console import main_console as console
from unittest.mock import patch, MagicMock


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
        "safety.auth.utils.SafetyAuthSession.get_authentication_type",
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

    @patch("safety.scan.decorators.verify_project")
    @patch.object(Auth, "is_valid", return_value=True)
    @patch("safety.auth.utils.SafetyAuthSession.get_authentication_type", return_value="token")
    def test_scan_non_interactive_flag(self, mock_get_auth_type, mock_is_valid, mock_verify_project):
        """Test that --non-interactive flag sets link_behavior to 'never'"""
        # Setup mock to capture verify_project call
        mock_verify_project.return_value = (True, "found")

        result = self.runner.invoke(
            self.cli,
            ["scan", "--target", self.target, "--non-interactive", "--output", "json"]
        )

        # Verify verify_project was called with link_behavior='never'
        if mock_verify_project.called:
            call_kwargs = mock_verify_project.call_args.kwargs
            self.assertEqual(call_kwargs.get('link_behavior'), 'never')

    @patch("safety.scan.decorators.verify_project")
    @patch.object(Auth, "is_valid", return_value=True)
    @patch("safety.auth.utils.SafetyAuthSession.get_authentication_type", return_value="token")
    def test_scan_non_interactive_env_var(self, mock_get_auth_type, mock_is_valid, mock_verify_project):
        """Test that SAFETY_NONINTERACTIVE environment variable sets link_behavior to 'never'"""
        # Setup mock to capture verify_project call
        mock_verify_project.return_value = (True, "found")

        # Test with env var set to 1
        result = self.runner.invoke(
            self.cli,
            ["scan", "--target", self.target, "--output", "json"],
            env={"SAFETY_NONINTERACTIVE": "1"}
        )

        # Verify verify_project was called with link_behavior='never'
        if mock_verify_project.called:
            call_kwargs = mock_verify_project.call_args.kwargs
            self.assertEqual(call_kwargs.get('link_behavior'), 'never')

    @patch("safety.scan.decorators.verify_project")
    @patch.object(Auth, "is_valid", return_value=True)
    @patch("safety.auth.utils.SafetyAuthSession.get_authentication_type", return_value="token")
    def test_scan_interactive_default(self, mock_get_auth_type, mock_is_valid, mock_verify_project):
        """Test that interactive mode (default) uses 'prompt' link_behavior"""
        # Setup mock to capture verify_project call
        mock_verify_project.return_value = (True, "linked")

        result = self.runner.invoke(
            self.cli,
            ["scan", "--target", self.target, "--output", "json"]
        )

        # Verify verify_project was called with link_behavior='prompt' (default)
        if mock_verify_project.called:
            call_kwargs = mock_verify_project.call_args.kwargs
            self.assertEqual(call_kwargs.get('link_behavior'), 'prompt')
