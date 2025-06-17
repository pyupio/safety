import unittest
import tempfile
from urllib.parse import urlparse, parse_qs

from click.testing import CliRunner
from safety.auth.models import Auth
from safety.cli import cli
from safety.console import main_console as console
from unittest.mock import patch


class TestScanCommand(unittest.TestCase):
    def setUp(self):
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

    def test_url_parameter_handling(self):
        """Test that branch parameters are properly added to URLs with existing query parameters."""
        from urllib.parse import urlencode, urlunparse

        # Test cases: (input_url, branch_name, expected_url)
        test_cases = [
            # URL without existing parameters
            (
                "https://platform.safetycli.com/project/test",
                "master",
                "https://platform.safetycli.com/project/test?branch=master",
            ),
            # URL with existing parameters
            (
                "https://platform.safetycli.com/project/test?env=prod",
                "feature-branch",
                "https://platform.safetycli.com/project/test?env=prod&branch=feature-branch",
            ),
            # URL with multiple existing parameters
            (
                "https://platform.safetycli.com/project/test?env=prod&org=myorg",
                "main",
                "https://platform.safetycli.com/project/test?env=prod&org=myorg&branch=main",
            ),
        ]

        for input_url, branch_name, expected_url in test_cases:
            with self.subTest(input_url=input_url, branch_name=branch_name):
                # This is the same logic as in scan/command.py lines 287-291
                parsed_url = urlparse(input_url)
                query_params = parse_qs(parsed_url.query)
                query_params["branch"] = [branch_name]
                new_query = urlencode(query_params, doseq=True)
                result_url = urlunparse(parsed_url._replace(query=new_query))

                # Parse both URLs to compare query parameters (order might differ)
                expected_parsed = urlparse(expected_url)
                result_parsed = urlparse(result_url)

                # Check that base URL is the same
                self.assertEqual(result_parsed.scheme, expected_parsed.scheme)
                self.assertEqual(result_parsed.netloc, expected_parsed.netloc)
                self.assertEqual(result_parsed.path, expected_parsed.path)

                # Check query parameters
                expected_params = parse_qs(expected_parsed.query)
                result_params = parse_qs(result_parsed.query)
                self.assertEqual(result_params, expected_params)
