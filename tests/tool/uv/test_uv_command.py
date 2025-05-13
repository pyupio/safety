# type: ignore
import unittest
from unittest.mock import patch, MagicMock

import typer
from safety.tool.uv.command import UvCommand


class TestUvCommand(unittest.TestCase):
    """
    Test cases for UvCommand functionality.
    """

    def setUp(self):
        """
        Set up test environment before each test method.
        """
        self.command = UvCommand(["uv", "pip", "install", "package"])

    def test_env_preserves_existing_variables(self):
        """
        Test that env() method does not replace existing environment variables.
        """
        ctx = MagicMock(spec=typer.Context)

        existing_env = {
            "EXISTING_VAR": "existing_value",
            "ANOTHER_VAR": "another_value",
        }

        with patch(
            "safety.tool.pip.command.PipCommand.env", return_value=existing_env
        ) as mock_super_env:
            with patch(
                "safety.tool.uv.command.index_credentials",
                return_value="mock_credentials",
            ):
                result_env = self.command.env(ctx)

                self.assertEqual(result_env["EXISTING_VAR"], "existing_value")
                self.assertEqual(result_env["ANOTHER_VAR"], "another_value")
                mock_super_env.assert_called_once_with(ctx)

    def test_env_adds_uv_credentials_variables(self):
        """
        Test that env() method always adds UV_INDEX_SAFETY_USERNAME and
        UV_INDEX_SAFETY_PASSWORD environment variables.
        """
        ctx = MagicMock(spec=typer.Context)

        mock_credentials = "mock_credentials_value"

        with patch(
            "safety.tool.uv.command.index_credentials", return_value=mock_credentials
        ):
            with patch("safety.tool.pip.command.PipCommand.env", return_value={}):
                result_env = self.command.env(ctx)

                self.assertIn("UV_INDEX_SAFETY_USERNAME", result_env)
                self.assertIn("UV_INDEX_SAFETY_PASSWORD", result_env)
                self.assertEqual(result_env["UV_INDEX_SAFETY_USERNAME"], "user")
                self.assertEqual(
                    result_env["UV_INDEX_SAFETY_PASSWORD"], mock_credentials
                )

    def test_env_combines_parent_env_with_uv_credentials(self):
        """
        Test that env() method properly combines parent environment with UV credentials.
        """
        ctx = MagicMock(spec=typer.Context)

        existing_env = {"EXISTING_VAR": "existing_value", "PATH": "/usr/bin:/bin"}

        mock_credentials = "mock_credentials_value"

        with patch(
            "safety.tool.uv.command.index_credentials", return_value=mock_credentials
        ):
            with patch(
                "safety.tool.pip.command.PipCommand.env", return_value=existing_env
            ):
                result_env = self.command.env(ctx)

                self.assertEqual(result_env["EXISTING_VAR"], "existing_value")
                self.assertEqual(result_env["PATH"], "/usr/bin:/bin")
                self.assertEqual(result_env["UV_INDEX_SAFETY_USERNAME"], "user")
                self.assertEqual(
                    result_env["UV_INDEX_SAFETY_PASSWORD"], mock_credentials
                )
