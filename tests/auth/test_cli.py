from unittest.mock import patch, ANY
from click.testing import CliRunner
import unittest

from safety.cli import cli

class TestSafetyAuthCLI(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.runner = CliRunner(mix_stderr=False)

        cli.commands = cli.all_commands
        self.cli = cli

    @unittest.skip("We are bypassing email verification for now")
    @patch("safety.auth.cli.fail_if_authenticated")
    @patch("safety.auth.cli.get_authorization_data")
    @patch("safety.auth.cli.process_browser_callback")
    def test_auth_calls_login(
        self, process_browser_callback, get_authorization_data, fail_if_authenticated
    ):
        auth_data = "https://safetycli.com", "initialState"
        get_authorization_data.return_value = auth_data
        process_browser_callback.return_value = {
            "email": "user@safetycli.com",
            "name": "Safety User",
        }
        result = self.runner.invoke(self.cli, ["auth"])

        fail_if_authenticated.assert_called_once()
        get_authorization_data.assert_called_once()
        process_browser_callback.assert_called_once_with(
            auth_data[0], initial_state=auth_data[1], ctx=ANY, headless=False
        )

        expected = [
            "",
            "Redirecting your browser to log in; once authenticated, return here to start using Safety",
            "",
            "You're authenticated",
            " Account: Safety User, user@safetycli.com (email verification required)",
            "",
            "To complete your account open the “verify your email” email sent to",
            "user@safetycli.com",
            "",
            "Can’t find the verification email? Login at",
            "`https://platform.safetycli.com/login/` to resend the verification email",
            "",
        ]

        for res_line, exp_line in zip(result.stdout.splitlines(), expected):
            self.assertIn(exp_line, res_line)
