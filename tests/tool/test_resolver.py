"""
Tests for tool resolver.
"""

import pytest
from unittest.mock import patch, MagicMock

from safety.tool.resolver import get_unwrapped_command


@pytest.mark.unit
class TestGetUnwrappedCommand:
    """
    Test suite for get_unwrapped_command function.
    """

    @patch("safety.tool.resolver.shutil.which")
    @patch("safety.tool.resolver.subprocess.run")
    def test_get_unwrapped_command_unix_simple(self, mock_run, mock_which):
        """
        Test get_unwrapped_command on Unix systems with simple command.
        """
        # Arrange
        mock_which.return_value = "/usr/bin/pip"

        # Act
        with patch("sys.platform", "linux"):
            result = get_unwrapped_command("pip")

        # Assert
        assert result == "/usr/bin/pip"
        mock_which.assert_called_once_with("pip")
        mock_run.assert_not_called()

    @patch("safety.tool.resolver.shutil.which")
    @patch("safety.tool.resolver.subprocess.run")
    def test_get_unwrapped_command_unix_not_found(self, mock_run, mock_which):
        """
        Test get_unwrapped_command on Unix when command not found.
        """
        # Arrange
        mock_which.return_value = None

        # Act
        with patch("sys.platform", "linux"):
            result = get_unwrapped_command("nonexistent-tool")

        # Assert
        assert result == "nonexistent-tool"
        mock_which.assert_called_once_with("nonexistent-tool")
        mock_run.assert_not_called()

    @patch("safety.tool.resolver.shutil.which")
    @patch("safety.tool.resolver.subprocess.run")
    def test_get_unwrapped_command_windows_with_bat_file(self, mock_run, mock_which):
        """
        Test get_unwrapped_command on Windows with .bat wrapper.
        """
        # Arrange - Simulate Windows with .bat file
        mock_process = MagicMock()
        mock_process.stdout = (
            "C:\\Python39\\Scripts\\pip.bat\nC:\\Python39\\Scripts\\pip.exe"
        )
        mock_process.returncode = 0
        mock_run.return_value = mock_process

        # Act
        with patch("sys.platform", "win32"):
            result = get_unwrapped_command("pip")

        # Assert - Should find the actual executable, not the .bat
        assert result == "C:\\Python39\\Scripts\\pip.exe"
        mock_which.assert_not_called()
        mock_run.assert_called_once_with(
            ["where.exe", "pip.exe"], capture_output=True, text=True
        )

    @patch("safety.tool.resolver.shutil.which")
    @patch("safety.tool.resolver.subprocess.run")
    def test_get_unwrapped_command_windows_with_failed_where_call(
        self, mock_run, mock_which
    ):
        """
        Test get_unwrapped_command on Windows without .bat wrapper available.
        """
        # Arrange
        mock_which.return_value = "C:\\Python39\\Scripts\\poetry.exe"
        mock_process = MagicMock()
        mock_process.stdout = ""
        mock_process.returncode = 1  # where command fails
        mock_run.return_value = mock_process

        # Act
        with patch("sys.platform", "win32"):
            result = get_unwrapped_command("poetry")

        # Assert - Should return the original path from which
        assert result == "C:\\Python39\\Scripts\\poetry.exe"
