# type: ignore

import pytest
from unittest.mock import MagicMock, patch

import typer

from safety.tool.pip.command import PipInstallCommand
from safety.tool.uv.command import UvInstallCommand
from safety.tool.poetry.command import PoetryAddCommand


class TestInstallationCommandsAudit:
    """
    Test suite for verifying installation audit functionality in command classes.
    """

    def setup_method(self):
        """
        Set up test fixtures.
        """
        self.ctx = MagicMock(spec=typer.Context)
        self.ctx.obj = MagicMock()
        self.result = MagicMock(duration_ms=100, process=MagicMock(returncode=0))

    @pytest.mark.parametrize(
        "command_class,command_args",
        [
            (PipInstallCommand, ["install", "requests"]),
            (UvInstallCommand, ["pip", "install", "requests"]),
            (PoetryAddCommand, ["add", "requests"]),
        ],
    )
    @patch("safety.tool.base.BaseCommand._handle_command_result")
    def test_installation_command_calls_audit(
        self, mock_handle_result, command_class, command_args
    ):
        """
        Test that all installation commands call handle_installation_audit in after().
        """
        command = command_class(command_args)

        with patch.object(
            command_class, "handle_installation_audit"
        ) as mock_handle_audit:
            command.after(self.ctx, self.result)

            mock_handle_audit.assert_called_once_with(self.ctx, self.result)
