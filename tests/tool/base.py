# type: ignore
from unittest.mock import patch, MagicMock
from typing import List, Dict, Any

import typer

from safety.tool.base import BaseCommand


class CommandToolCaseMixin:
    """
    Generic test case for command implementations.
    """

    command_class = None
    command_args: List[str] = None
    parent_env: Dict[str, str] = None
    expected_env_vars: Dict[str, str] = None
    mock_configurations: List[Dict[str, Any]] = None

    def setUp(self):
        """
        Set up test environment before each test method.
        """
        if not self.command_class or not self.command_args:
            raise ValueError("command_class and command_args must be set by subclasses")

        self.command = self.command_class(self.command_args)
        self.parent_env = self.parent_env or {}
        self.expected_env_vars = self.expected_env_vars or {}
        self.mock_configurations = self.mock_configurations or []

    def test_env_preserves_existing_variables(self):
        """
        Test that env() method does not replace existing environment variables.
        """
        ctx = MagicMock(spec=typer.Context)

        # Setup parent environment
        existing_env = self.parent_env.copy()

        # Setup all required mocks
        mock_objects = {}
        for mock_config in self.mock_configurations:
            target = mock_config.get("target")
            return_value = mock_config.get("return_value")

            patcher = patch(target, return_value=return_value)
            mock = patcher.start()
            mock_objects[target] = mock
            self.addCleanup(patcher.stop)

        # Get the env from the command
        with patch.object(
            BaseCommand, "env", return_value=existing_env
        ) as mock_super_env:
            result_env = self.command.env(ctx)

            # Check that parent env variables are preserved
            for key, value in existing_env.items():
                self.assertEqual(result_env[key], value)

            # Check that expected env variables are added
            for key, value in self.expected_env_vars.items():
                self.assertIn(key, result_env)
                self.assertEqual(result_env[key], value)

            # Verify parent env was called
            mock_super_env.assert_called_once_with(ctx)
