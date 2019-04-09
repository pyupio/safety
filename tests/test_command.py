from __future__ import absolute_import
from distutils import dist
import unittest

from safety import command
import mock


class CommandFinalizeOptionsTests(unittest.TestCase):
    def setUp(self):
        super(CommandFinalizeOptionsTests, self).setUp()
        self.command = command.SafetyCommand(dist.Distribution())
        self.command.initialize_options()

    def test_files_option_parsing(self):
        self.command.files = "one two three"
        self.command.finalize_options()
        self.assertEqual(self.command.files, ["one", "two", "three"])

    def test_ignore_option_parsing(self):
        self.command.ignore = "ID1 ID2 ID3"
        self.command.finalize_options()
        self.assertEqual(self.command.ignore, ["ID1", "ID2", "ID3"])


class CommandRunTests(unittest.TestCase):
    @staticmethod
    def run_command_with_options(*option_tuples):
        with mock.patch("safety.command.cli.check") as check_function:
            cmd = command.SafetyCommand(dist.Distribution())
            cmd.initialize_options()
            for option_name, value in option_tuples:
                opt = option_name.replace("-", "_")
                setattr(cmd, opt, value)
            cmd.finalize_options()
            cmd.run()
        return check_function

    def test_that_default_command_is_empty(self):
        check_function = self.run_command_with_options()
        check_function.assert_called_once_with(args=[])

    def test_boolean_options(self):
        for opt in command.SafetyCommand.boolean_options:
            check_function = self.run_command_with_options((opt, True))
            check_function.assert_called_once_with(args=["--"+opt])

    def test_simple_options(self):
        for opt in ("db", "key", "output"):
            check_function = self.run_command_with_options((opt, "value"))
            check_function.assert_called_once_with(args=["--"+opt, "value"])

    def test_list_options(self):
        for opt in ("files", "ignore"):
            check_function = self.run_command_with_options((opt, "one two"))
            check_function.assert_called_once_with(args=[
                "--"+opt, "one", "--"+opt, "two"])

    def test_proxy_options(self):
        check_function = self.run_command_with_options(("proxy-host", "host"))
        check_function.assert_called_once_with(args=["--proxy-host", "host"])

        check_function = self.run_command_with_options(
            ("proxy-host", "host"), ("proxy-port", "1234"))
        check_function.assert_called_once_with(args=[
            "--proxy-host", "host", "--proxy-port", "1234"])

        check_function = self.run_command_with_options(
            ("proxy-host", "host"), ("proxy-protocol", "https"))
        check_function.assert_called_once_with(args=[
            "--proxy-host", "host", "--proxy-protocol", "https"])

        check_function = self.run_command_with_options(
            ("proxy-host", "host"), ("proxy-port", "1234"),
            ("proxy-protocol", "https"))
        check_function.assert_called_once_with(args=[
            "--proxy-host", "host", "--proxy-protocol", "https",
            "--proxy-port", "1234"])

        check_function = self.run_command_with_options(("proxy-port", "1234"))
        check_function.assert_called_once_with(args=[])

        check_function = self.run_command_with_options(
            ("proxy-protocol", "http"))
        check_function.assert_called_once_with(args=[])
