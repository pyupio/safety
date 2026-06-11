import unittest
from unittest.mock import patch, MagicMock
import sys

import click

from safety.error_handlers import output_exception, handle_cmd_exception
from safety.errors import SafetyError, SafetyException
from safety.constants import EXIT_CODE_FAILURE, EXIT_CODE_OK


class TestOutputException(unittest.TestCase):

    @patch("safety.error_handlers.click.secho")
    @patch("safety.error_handlers.sys.exit")
    def test_output_exception_basic(self, mock_exit, mock_secho):
        exception = Exception("Something went wrong")
        output_exception(exception)
        mock_secho.assert_called_once_with("Something went wrong", fg="red", file=sys.stderr)
        mock_exit.assert_called_once_with(EXIT_CODE_FAILURE)

    @patch("safety.error_handlers.click.secho")
    @patch("safety.error_handlers.sys.exit")
    def test_output_exception_custom_exit_code(self, mock_exit, mock_secho):
        from safety.errors import MalformedDatabase
        exception = MalformedDatabase()
        output_exception(exception)
        mock_exit.assert_called_once_with(exception.get_exit_code())

    @patch("safety.error_handlers.click.secho")
    @patch("safety.error_handlers.sys.exit")
    def test_output_exception_exit_code_false(self, mock_exit, mock_secho):
        exception = Exception("Something went wrong")
        output_exception(exception, exit_code_output=False)
        mock_exit.assert_called_once_with(EXIT_CODE_OK)


class TestHandleCmdException(unittest.TestCase):

    def setUp(self):
        self.ctx = MagicMock()
        self.ctx.obj.event_bus = MagicMock()
        self.ctx.parent = None
        self.ctx.command = None

    @patch("safety.error_handlers.output_exception")
    def test_handle_safety_error(self, mock_output_exception):
        @handle_cmd_exception
        def failing_func(ctx):
            raise SafetyError("Test safety error")
        failing_func(self.ctx)
        mock_output_exception.assert_called_once()
        args, kwargs = mock_output_exception.call_args
        self.assertIsInstance(args[0], SafetyError)
        self.assertTrue(kwargs["exit_code_output"])

    @patch("safety.error_handlers.output_exception")
    def test_handle_generic_exception(self, mock_output_exception):
        @handle_cmd_exception
        def failing_func(ctx):
            raise ValueError("Some value error")
        failing_func(self.ctx)
        mock_output_exception.assert_called_once()
        args, kwargs = mock_output_exception.call_args
        self.assertIsInstance(args[0], SafetyException)
        self.assertTrue(kwargs["exit_code_output"])

    def test_handle_click_exception_is_re_raised(self):
        @handle_cmd_exception
        def failing_func(ctx):
            raise click.ClickException("Click error")
        with self.assertRaises(click.ClickException):
            failing_func(self.ctx)

    @patch("safety.error_handlers.emit_command_error")
    @patch("safety.error_handlers.output_exception")
    def test_successful_execution(self, mock_output_exception, mock_emit):
        @handle_cmd_exception
        def successful_func(ctx):
            return "success"
        result = successful_func(self.ctx)
        self.assertEqual(result, "success")
        mock_output_exception.assert_not_called()
        mock_emit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
