from __future__ import annotations

import pytest
import stat
from unittest.mock import patch, mock_open, Mock

from safety.system_scan.scanner.detectors.execution_contexts.utils.linux.main import (
    get_linux_machine_id,
)


@pytest.mark.unit
class TestGetLinuxMachineId:
    """Test get_linux_machine_id function."""

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_from_etc(self, mock_file, mock_stat):
        """Test getting machine ID from /etc/machine-id."""
        # Mock file stats
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33  # Normal size for machine ID
        mock_stat_result.st_mode = stat.S_IFREG  # Regular file
        mock_stat.return_value = mock_stat_result

        # Mock file content
        machine_id = "12345678901234567890123456789012"
        mock_file.return_value.read.return_value = machine_id + "\n"

        result = get_linux_machine_id()

        assert result == machine_id
        mock_stat.assert_called_once_with("/etc/machine-id")
        mock_file.assert_called_once_with("/etc/machine-id", "r", encoding="utf-8")

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_from_var_lib_dbus(self, mock_file, mock_stat):
        """Test getting machine ID from /var/lib/dbus/machine-id as fallback."""

        # First path fails, second succeeds
        def stat_side_effect(path):
            if path == "/etc/machine-id":
                raise OSError("File not found")
            else:  # /var/lib/dbus/machine-id
                mock_result = Mock()
                mock_result.st_size = 33
                mock_result.st_mode = stat.S_IFREG
                return mock_result

        mock_stat.side_effect = stat_side_effect

        machine_id = "abcdef1234567890abcdef1234567890"
        mock_file.return_value.read.return_value = machine_id

        result = get_linux_machine_id()

        assert result == machine_id
        assert mock_stat.call_count == 2
        mock_file.assert_called_once_with(
            "/var/lib/dbus/machine-id", "r", encoding="utf-8"
        )

    @patch("os.stat")
    def test_get_linux_machine_id_file_too_large(self, mock_stat):
        """Test rejecting files that are too large."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 100  # Larger than max_size (64)
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        result = get_linux_machine_id()

        assert result is None
        # Should try both paths and reject both due to size
        assert mock_stat.call_count == 2

    @patch("os.stat")
    def test_get_linux_machine_id_not_regular_file(self, mock_stat):
        """Test rejecting non-regular files (e.g., directories, symlinks)."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33
        mock_stat_result.st_mode = stat.S_IFDIR  # Directory, not regular file
        mock_stat.return_value = mock_stat_result

        result = get_linux_machine_id()

        assert result is None
        assert mock_stat.call_count == 2

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_empty_file(self, mock_file, mock_stat):
        """Test handling empty machine ID file."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 0
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        mock_file.return_value.read.return_value = ""

        result = get_linux_machine_id()

        assert result is None

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_whitespace_only(self, mock_file, mock_stat):
        """Test handling file with only whitespace."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 10
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        mock_file.return_value.read.return_value = "   \n  \t  "

        result = get_linux_machine_id()

        assert result is None

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_with_whitespace(self, mock_file, mock_stat):
        """Test machine ID with leading/trailing whitespace."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        machine_id = "12345678901234567890123456789012"
        mock_file.return_value.read.return_value = f"  {machine_id}  \n"

        result = get_linux_machine_id()

        assert result == machine_id

    @patch("os.stat")
    def test_get_linux_machine_id_stat_os_error(self, mock_stat):
        """Test handling OSError during stat."""
        mock_stat.side_effect = OSError("Permission denied")

        result = get_linux_machine_id()

        assert result is None
        assert mock_stat.call_count == 2

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_read_os_error(self, mock_file, mock_stat):
        """Test handling OSError during file reading."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        mock_file.side_effect = OSError("Permission denied")

        result = get_linux_machine_id()

        assert result is None

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_read_unicode_error(self, mock_file, mock_stat):
        """Test handling UnicodeDecodeError during file reading."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        mock_file.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "Invalid UTF-8")

        result = get_linux_machine_id()

        assert result is None

    @patch("os.stat")
    @patch("builtins.open")
    def test_get_linux_machine_id_value_error(self, mock_open_func, mock_stat):
        """Test handling ValueError during file operations."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        # Mock open to raise ValueError (e.g., invalid encoding specification)
        mock_open_func.side_effect = ValueError("invalid encoding")

        result = get_linux_machine_id()

        assert result is None

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_first_path_invalid_second_valid(
        self, mock_file, mock_stat
    ):
        """Test when first path has invalid file, second path is valid."""
        call_count = 0

        def stat_side_effect(path):
            nonlocal call_count
            call_count += 1
            mock_result = Mock()
            if call_count == 1:  # First path - too large
                mock_result.st_size = 100
                mock_result.st_mode = stat.S_IFREG
            else:  # Second path - valid
                mock_result.st_size = 33
                mock_result.st_mode = stat.S_IFREG
            return mock_result

        mock_stat.side_effect = stat_side_effect

        machine_id = "validmachineid123456789012345678"
        mock_file.return_value.read.return_value = machine_id

        result = get_linux_machine_id()

        assert result == machine_id
        assert mock_stat.call_count == 2
        mock_file.assert_called_once_with(
            "/var/lib/dbus/machine-id", "r", encoding="utf-8"
        )

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_respects_max_size_limit(self, mock_file, mock_stat):
        """Test that file reading respects max_size limit."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        # Very long content, but read() should be called with max_size (64)
        long_content = "x" * 200
        mock_file.return_value.read.return_value = long_content

        result = get_linux_machine_id()

        # Should return the long content (strip() will be called on it)
        assert result == long_content
        # Verify read was called with max_size parameter
        mock_file.return_value.read.assert_called_once_with(64)

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_typical_machine_id_format(self, mock_file, mock_stat):
        """Test with typical machine ID format (32 hex chars)."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33  # 32 chars + newline
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        # Typical machine ID: 32 lowercase hex characters
        machine_id = "a1b2c3d4e5f67890a1b2c3d4e5f67890"
        mock_file.return_value.read.return_value = machine_id + "\n"

        result = get_linux_machine_id()

        assert result == machine_id
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    @patch("os.stat")
    @patch("builtins.open", new_callable=mock_open)
    def test_get_linux_machine_id_mixed_case(self, mock_file, mock_stat):
        """Test machine ID with mixed case (should preserve case)."""
        mock_stat_result = Mock()
        mock_stat_result.st_size = 33
        mock_stat_result.st_mode = stat.S_IFREG
        mock_stat.return_value = mock_stat_result

        machine_id = "A1B2c3d4E5F67890a1b2C3D4e5f67890"
        mock_file.return_value.read.return_value = machine_id

        result = get_linux_machine_id()

        assert result == machine_id
