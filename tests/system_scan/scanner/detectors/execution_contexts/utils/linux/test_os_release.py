from __future__ import annotations

import pytest
from unittest.mock import patch, mock_open

from safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release import (
    get_linux_version_info,
    _parse_os_release,
    _is_debian_family,
    _is_rhel_family,
    _get_point_release,
    _read_file,
    _parse_kv_file,
)
from safety.system_scan.scanner.detectors.execution_contexts.utils.main import (
    LinuxVersionInfo,
)


@pytest.mark.unit
class TestGetLinuxVersionInfo:
    """Test get_linux_version_info function."""

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._parse_os_release"
    )
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._get_point_release"
    )
    def test_get_linux_version_info_ubuntu(
        self, mock_get_point_release, mock_parse_os_release
    ):
        """Test getting version info for Ubuntu."""
        mock_parse_os_release.return_value = {
            "ID": "ubuntu",
            "VERSION_ID": "22.04",
            "NAME": "Ubuntu",
            "VERSION_CODENAME": "jammy",
            "PRETTY_NAME": "Ubuntu 22.04.3 LTS",
            "ID_LIKE": "debian",
        }
        mock_get_point_release.return_value = "22.04.3"

        result = get_linux_version_info()

        assert isinstance(result, LinuxVersionInfo)
        assert result.id == "ubuntu"
        assert result.version_id == "22.04"
        assert result.version == "22.04.3"
        assert result.name == "Ubuntu"
        assert result.codename == "jammy"
        assert result.pretty_name == "Ubuntu 22.04.3 LTS"
        assert result.id_like == "debian"

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._parse_os_release"
    )
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._get_point_release"
    )
    def test_get_linux_version_info_minimal(
        self, mock_get_point_release, mock_parse_os_release
    ):
        """Test getting version info with minimal data."""
        mock_parse_os_release.return_value = {}
        mock_get_point_release.return_value = ""

        result = get_linux_version_info()

        assert result.id == "linux"
        assert result.version_id == ""
        assert result.version == ""
        assert result.name == "Linux"
        assert result.codename == ""
        assert result.pretty_name == "Linux"
        assert result.id_like == ""

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._parse_os_release"
    )
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._get_point_release"
    )
    def test_get_linux_version_info_with_root_prefix(
        self, mock_get_point_release, mock_parse_os_release
    ):
        """Test getting version info with root prefix."""
        mock_parse_os_release.return_value = {"ID": "debian", "VERSION_ID": "11"}
        mock_get_point_release.return_value = "11.8"

        get_linux_version_info(root="/mnt/target")

        mock_parse_os_release.assert_called_once_with("/mnt/target")
        mock_get_point_release.assert_called_once_with(
            "/mnt/target", "debian", "11", {"ID": "debian", "VERSION_ID": "11"}
        )


@pytest.mark.unit
class TestParseOsRelease:
    """Test _parse_os_release function."""

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._parse_kv_file"
    )
    def test_parse_os_release_first_path_exists(self, mock_parse_kv_file):
        """Test parsing os-release from first path."""
        mock_parse_kv_file.side_effect = [
            {"ID": "ubuntu", "VERSION_ID": "22.04"},  # /etc/os-release
            {},  # /usr/lib/os-release (shouldn't be called)
        ]

        result = _parse_os_release()

        assert result == {"ID": "ubuntu", "VERSION_ID": "22.04"}
        assert mock_parse_kv_file.call_count == 1
        mock_parse_kv_file.assert_called_with("/etc/os-release")

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._parse_kv_file"
    )
    def test_parse_os_release_second_path_exists(self, mock_parse_kv_file):
        """Test parsing os-release from second path."""
        mock_parse_kv_file.side_effect = [
            {},  # /etc/os-release (empty)
            {"ID": "fedora", "VERSION_ID": "39"},  # /usr/lib/os-release
        ]

        result = _parse_os_release()

        assert result == {"ID": "fedora", "VERSION_ID": "39"}
        assert mock_parse_kv_file.call_count == 2

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._parse_kv_file"
    )
    def test_parse_os_release_no_files(self, mock_parse_kv_file):
        """Test parsing os-release when no files exist."""
        mock_parse_kv_file.return_value = {}

        result = _parse_os_release()

        assert result == {}
        assert mock_parse_kv_file.call_count == 2

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._parse_kv_file"
    )
    def test_parse_os_release_with_root(self, mock_parse_kv_file):
        """Test parsing os-release with root prefix."""
        mock_parse_kv_file.return_value = {"ID": "debian"}

        _parse_os_release(root="/mnt/target")

        mock_parse_kv_file.assert_called_with("/mnt/target/etc/os-release")


@pytest.mark.unit
class TestFamilyDetection:
    """Test distro family detection functions."""

    def test_is_debian_family_debian(self):
        """Test Debian family detection for debian."""
        assert _is_debian_family("debian", "") is True
        assert _is_debian_family("debian", "gnu/linux") is True

    def test_is_debian_family_ubuntu(self):
        """Test Debian family detection for Ubuntu."""
        assert _is_debian_family("ubuntu", "debian") is True
        assert _is_debian_family("ubuntu", "debian gnu/linux") is True

    def test_is_debian_family_not_debian(self):
        """Test Debian family detection for non-Debian."""
        assert _is_debian_family("fedora", "rhel") is False
        assert _is_debian_family("centos", "") is False

    def test_is_rhel_family_direct(self):
        """Test RHEL family detection for direct RHEL family members."""
        assert _is_rhel_family("rhel", "") is True
        assert _is_rhel_family("centos", "") is True
        assert _is_rhel_family("rocky", "") is True
        assert _is_rhel_family("almalinux", "") is True
        assert _is_rhel_family("fedora", "") is True
        assert _is_rhel_family("ol", "") is True

    def test_is_rhel_family_id_like(self):
        """Test RHEL family detection via ID_LIKE."""
        assert _is_rhel_family("custom", "rhel fedora") is True
        assert _is_rhel_family("custom", "rhel") is True
        assert _is_rhel_family("custom", "fedora rhel") is True

    def test_is_rhel_family_not_rhel(self):
        """Test RHEL family detection for non-RHEL."""
        assert _is_rhel_family("ubuntu", "debian") is False
        assert _is_rhel_family("debian", "") is False


@pytest.mark.unit
class TestGetPointRelease:
    """Test _get_point_release function."""

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_get_point_release_ubuntu(self, mock_read_file):
        """Test getting point release for Ubuntu."""
        os_release = {
            "ID": "ubuntu",
            "VERSION": "22.04.3 LTS",
            "VERSION_ID": "22.04",
        }

        result = _get_point_release("", "ubuntu", "22.04", os_release)

        assert result == "22.04.3"
        mock_read_file.assert_not_called()  # Should use VERSION field

    def test_get_point_release_ubuntu_no_version_field(self):
        """Test getting point release for Ubuntu without VERSION field."""
        os_release = {"ID": "ubuntu", "VERSION_ID": "22.04"}

        result = _get_point_release("", "ubuntu", "22.04", os_release)

        assert result == "22.04"  # Falls back to VERSION_ID

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_get_point_release_debian(self, mock_read_file):
        """Test getting point release for Debian."""
        mock_read_file.return_value = "11.8"
        os_release = {"ID": "debian", "VERSION_ID": "11", "ID_LIKE": ""}

        result = _get_point_release("", "debian", "11", os_release)

        assert result == "11.8"
        mock_read_file.assert_called_once_with("/etc/debian_version")

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_get_point_release_debian_with_root(self, mock_read_file):
        """Test getting point release for Debian with root prefix."""
        mock_read_file.return_value = "11.8"
        os_release = {"ID": "debian", "VERSION_ID": "11", "ID_LIKE": ""}

        result = _get_point_release("/mnt/target", "debian", "11", os_release)

        assert result == "11.8"
        mock_read_file.assert_called_once_with("/mnt/target/etc/debian_version")

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_get_point_release_debian_invalid_content(self, mock_read_file):
        """Test getting point release for Debian with invalid content."""
        mock_read_file.return_value = "bullseye/sid"  # Non-numeric
        os_release = {"ID": "debian", "VERSION_ID": "11", "ID_LIKE": ""}

        result = _get_point_release("", "debian", "11", os_release)

        assert result == "11"  # Falls back to VERSION_ID

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_get_point_release_rhel_family(self, mock_read_file):
        """Test getting point release for RHEL family."""
        mock_read_file.return_value = "Rocky Linux release 8.9 (Green Obsidian)"
        os_release = {"ID": "rocky", "VERSION_ID": "8", "ID_LIKE": "rhel fedora"}

        result = _get_point_release("", "rocky", "8", os_release)

        assert result == "8.9"
        mock_read_file.assert_called_once_with("/etc/redhat-release")

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_get_point_release_rhel_no_match(self, mock_read_file):
        """Test getting point release for RHEL family with no regex match."""
        mock_read_file.return_value = "Some other content"
        os_release = {"ID": "centos", "VERSION_ID": "7", "ID_LIKE": "rhel fedora"}

        result = _get_point_release("", "centos", "7", os_release)

        assert result == "7"  # Falls back to VERSION_ID

    def test_get_point_release_unknown_distro(self):
        """Test getting point release for unknown distro."""
        os_release = {"ID": "unknown", "VERSION_ID": "1.0"}

        result = _get_point_release("", "unknown", "1.0", os_release)

        assert result == "1.0"  # Falls back to VERSION_ID


@pytest.mark.unit
class TestReadFile:
    """Test _read_file function."""

    def test_read_file_success(self):
        """Test reading file successfully."""
        content = "ID=ubuntu\nVERSION_ID=22.04\n"

        with patch("builtins.open", mock_open(read_data=content)):
            result = _read_file("/etc/os-release")

        assert result == "ID=ubuntu\nVERSION_ID=22.04"

    def test_read_file_with_whitespace(self):
        """Test reading file with whitespace."""
        content = "  ID=ubuntu  \n  VERSION_ID=22.04  \n  "

        with patch("builtins.open", mock_open(read_data=content)):
            result = _read_file("/etc/os-release")

        assert result == "ID=ubuntu  \n  VERSION_ID=22.04"

    def test_read_file_os_error(self):
        """Test reading file with OS error."""
        with patch("builtins.open", side_effect=OSError("File not found")):
            result = _read_file("/nonexistent")

        assert result == ""

    def test_read_file_permission_error(self):
        """Test reading file with permission error."""
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = _read_file("/etc/shadow")

        assert result == ""


@pytest.mark.unit
class TestParseKvFile:
    """Test _parse_kv_file function."""

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_parse_kv_file_success(self, mock_read_file):
        """Test parsing key-value file successfully."""
        mock_read_file.return_value = """ID=ubuntu
VERSION_ID="22.04"
NAME='Ubuntu'
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_CODENAME=jammy"""

        result = _parse_kv_file("/etc/os-release")

        expected = {
            "ID": "ubuntu",
            "VERSION_ID": "22.04",
            "NAME": "Ubuntu",
            "PRETTY_NAME": "Ubuntu 22.04.3 LTS",
            "VERSION_CODENAME": "jammy",
        }
        assert result == expected

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_parse_kv_file_with_comments(self, mock_read_file):
        """Test parsing key-value file with comments."""
        mock_read_file.return_value = """# This is a comment
ID=ubuntu
# Another comment
VERSION_ID=22.04

# Empty line above
NAME=Ubuntu"""

        result = _parse_kv_file("/etc/os-release")

        expected = {
            "ID": "ubuntu",
            "VERSION_ID": "22.04",
            "NAME": "Ubuntu",
        }
        assert result == expected

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_parse_kv_file_no_equals(self, mock_read_file):
        """Test parsing key-value file with lines without equals."""
        mock_read_file.return_value = """ID=ubuntu
INVALID_LINE_NO_EQUALS
VERSION_ID=22.04"""

        result = _parse_kv_file("/etc/os-release")

        expected = {
            "ID": "ubuntu",
            "VERSION_ID": "22.04",
        }
        assert result == expected

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_parse_kv_file_empty_content(self, mock_read_file):
        """Test parsing empty file."""
        mock_read_file.return_value = ""

        result = _parse_kv_file("/etc/os-release")

        assert result == {}

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_parse_kv_file_equals_in_value(self, mock_read_file):
        """Test parsing key-value file with equals in value."""
        mock_read_file.return_value = '''ID=ubuntu
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/?test=value"'''

        result = _parse_kv_file("/etc/os-release")

        expected = {
            "ID": "ubuntu",
            "HOME_URL": "https://www.ubuntu.com/",
            "SUPPORT_URL": "https://help.ubuntu.com/?test=value",
        }
        assert result == expected

    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release._read_file"
    )
    def test_parse_kv_file_mixed_quotes(self, mock_read_file):
        """Test parsing key-value file with mixed quote styles."""
        mock_read_file.return_value = """ID=ubuntu
VERSION_ID="22.04"
NAME='Ubuntu'
CODENAME=jammy"""

        result = _parse_kv_file("/etc/os-release")

        expected = {
            "ID": "ubuntu",
            "VERSION_ID": "22.04",
            "NAME": "Ubuntu",
            "CODENAME": "jammy",
        }
        assert result == expected
