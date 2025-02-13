import unittest
import tempfile

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

    @patch.object(Auth, 'is_valid', return_value=False)
    @patch('safety.auth.utils.SafetyAuthSession.get_authentication_type', return_value="unauthenticated")
    def test_scan(self, mock_is_valid, mock_get_auth_type):
        result = self.runner.invoke(self.cli, ["scan", "--target", self.target, "--output", "json"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(self.cli, ["--stage", "production", "scan", "--target", self.target, "--output", "json"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(self.cli, ["--stage", "cicd", "scan", "--target", self.target, "--output", "screen"])
        self.assertEqual(result.exit_code, 1)
