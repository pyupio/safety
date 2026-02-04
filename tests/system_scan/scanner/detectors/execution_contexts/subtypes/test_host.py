from __future__ import annotations

import pytest
from sys import platform as sys_platform
from unittest.mock import patch, Mock

from safety.system_scan.scanner.detectors.execution_contexts.subtypes.host import (
    get_machine_id,
    get_kernel_info,
    get_os_info,
    KernelName,
)
from safety.system_scan.scanner.events.payloads.execution_context import OsFamily


@pytest.mark.unit
class TestGetMachineId:
    """Test get_machine_id function."""

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_machine_id"
    )
    def test_get_machine_id_linux(self, mock_get_linux_machine_id, mock_system):
        """Test getting machine ID on Linux."""
        mock_system.return_value = "Linux"
        mock_get_linux_machine_id.return_value = "linux-machine-id-123456"

        result = get_machine_id()

        assert result == "linux-machine-id-123456"
        mock_get_linux_machine_id.assert_called_once()

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_macos_machine_id"
    )
    def test_get_machine_id_macos(self, mock_get_macos_machine_id, mock_system):
        """Test getting machine ID on macOS."""
        mock_system.return_value = "Darwin"
        mock_get_macos_machine_id.return_value = "12345678-1234-1234-1234-123456789ABC"

        result = get_machine_id()

        assert result == "12345678-1234-1234-1234-123456789ABC"
        mock_get_macos_machine_id.assert_called_once()

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_windows_machine_id"
    )
    def test_get_machine_id_windows(self, mock_get_windows_machine_id, mock_system):
        """Test getting machine ID on Windows."""
        mock_system.return_value = "Windows"
        mock_get_windows_machine_id.return_value = "windows-machine-guid"

        result = get_machine_id()

        assert result == "windows-machine-guid"
        mock_get_windows_machine_id.assert_called_once()

    @patch("platform.system")
    def test_get_machine_id_unknown_system(self, mock_system):
        """Test getting machine ID on unknown system."""
        mock_system.return_value = "FreeBSD"

        result = get_machine_id()

        assert result is None

    @patch("platform.system")
    def test_get_machine_id_case_insensitive(self, mock_system):
        """Test that system detection is case insensitive."""
        # Test mixed case
        mock_system.return_value = "LINUX"

        with patch(
            "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_machine_id"
        ) as mock_linux:
            mock_linux.return_value = "test-id"
            result = get_machine_id()
            assert result == "test-id"
            mock_linux.assert_called_once()

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_machine_id"
    )
    def test_get_machine_id_handler_returns_none(
        self, mock_get_linux_machine_id, mock_system
    ):
        """Test when handler returns None."""
        mock_system.return_value = "Linux"
        mock_get_linux_machine_id.return_value = None

        result = get_machine_id()

        assert result is None


@pytest.mark.unit
class TestGetKernelInfo:
    """Test get_kernel_info function."""

    @patch("platform.system")
    @patch("platform.release")
    def test_get_kernel_info_linux(self, mock_release, mock_system):
        """Test getting kernel info on Linux."""
        mock_system.return_value = "Linux"
        mock_release.return_value = "5.15.0-generic"

        result = get_kernel_info()

        assert result == (KernelName.LINUX, "5.15.0-generic")
        mock_release.assert_called_once()

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_xnu_kernel_version"
    )
    def test_get_kernel_info_macos(self, mock_get_xnu_kernel_version, mock_system):
        """Test getting kernel info on macOS."""
        mock_system.return_value = "Darwin"
        mock_get_xnu_kernel_version.return_value = "10002.41.9~6"

        result = get_kernel_info()

        assert result == (KernelName.XNU, "10002.41.9~6")
        mock_get_xnu_kernel_version.assert_called_once()

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_windows_version_info"
    )
    def test_get_kernel_info_windows(self, mock_get_windows_version_info, mock_system):
        """Test getting kernel info on Windows."""
        mock_system.return_value = "Windows"
        mock_windows_info = Mock()
        mock_windows_info.kernel_version = "10.0.22621"
        mock_get_windows_version_info.return_value = mock_windows_info

        result = get_kernel_info()

        assert result == (KernelName.WINDOWS_NT, "10.0.22621")
        mock_get_windows_version_info.assert_called_once()

    @patch("platform.system")
    @patch("platform.release")
    def test_get_kernel_info_unknown_system(self, mock_release, mock_system):
        """Test getting kernel info on unknown system."""
        mock_system.return_value = "FreeBSD"
        mock_release.return_value = "13.2-RELEASE"

        result = get_kernel_info()

        assert result == (KernelName.UNKNOWN, "13.2-RELEASE")
        mock_release.assert_called_once()

    @patch("platform.system")
    def test_get_kernel_info_case_insensitive(self, mock_system):
        """Test that system detection is case insensitive."""
        mock_system.return_value = "DARWIN"

        with patch(
            "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_xnu_kernel_version"
        ) as mock_xnu:
            mock_xnu.return_value = "test-version"
            result = get_kernel_info()
            assert result == (KernelName.XNU, "test-version")


@pytest.mark.unit
class TestGetOsInfo:
    """Test get_os_info function."""

    @patch("platform.system")
    @patch("getpass.getuser")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_version_info"
    )
    def test_get_os_info_linux(
        self, mock_get_linux_version_info, mock_getuser, mock_system
    ):
        """Test getting OS info on Linux."""
        mock_system.return_value = "Linux"
        mock_getuser.return_value = "testuser"

        mock_linux_info = Mock()
        mock_linux_info.name = "Ubuntu"
        mock_linux_info.pretty_name = "Ubuntu 22.04.3 LTS"
        mock_linux_info.version = "22.04.3"
        mock_get_linux_version_info.return_value = mock_linux_info

        result = get_os_info()

        expected = ("Ubuntu", OsFamily.LINUX, "22.04.3", None, "testuser")
        assert result == expected
        assert (
            mock_get_linux_version_info.call_count == 2
        )  # Called for name/pretty_name and version

    @patch("platform.system")
    @patch("getpass.getuser")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_version_info"
    )
    def test_get_os_info_linux_no_name_fallback_to_pretty_name(
        self, mock_get_linux_version_info, mock_getuser, mock_system
    ):
        """Test Linux OS info when name is None, should fallback to pretty_name."""
        mock_system.return_value = "Linux"
        mock_getuser.return_value = "testuser"

        mock_linux_info = Mock()
        mock_linux_info.name = None
        mock_linux_info.pretty_name = "Debian GNU/Linux 11 (bullseye)"
        mock_linux_info.version = "11.8"
        mock_get_linux_version_info.return_value = mock_linux_info

        result = get_os_info()

        expected = (
            "Debian GNU/Linux 11 (bullseye)",
            OsFamily.LINUX,
            "11.8",
            None,
            "testuser",
        )
        assert result == expected

    @patch("platform.system")
    @patch("getpass.getuser")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_macos_version_info"
    )
    def test_get_os_info_macos(
        self, mock_get_macos_version_info, mock_getuser, mock_system
    ):
        """Test getting OS info on macOS."""
        mock_system.return_value = "Darwin"
        mock_getuser.return_value = "macuser"

        mock_macos_info = Mock()
        mock_macos_info.name = "macOS"
        mock_macos_info.version = "14.1.2"
        mock_macos_info.build = "23B92"
        mock_get_macos_version_info.return_value = mock_macos_info

        result = get_os_info()

        expected = ("macOS", OsFamily.MACOS, "14.1.2", "23B92", "macuser")
        assert result == expected
        assert (
            mock_get_macos_version_info.call_count == 3
        )  # Called for name, version, build

    @patch("platform.system")
    @patch("getpass.getuser")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_windows_version_info"
    )
    def test_get_os_info_windows(
        self, mock_get_windows_version_info, mock_getuser, mock_system
    ):
        """Test getting OS info on Windows."""
        mock_system.return_value = "Windows"
        mock_getuser.return_value = "winuser"

        mock_windows_info = Mock()
        mock_windows_info.product_name = "Windows 11 Pro"
        mock_windows_info.display_version = "23H2"
        mock_windows_info.build = "22621"
        mock_windows_info.ubr = "2715"
        mock_get_windows_version_info.return_value = mock_windows_info

        result = get_os_info()

        expected = ("Windows 11 Pro", OsFamily.WINDOWS, "23H2", "22621.2715", "winuser")
        assert result == expected
        assert (
            mock_get_windows_version_info.call_count == 4
        )  # Called for product_name, display_version, build, ubr

    @patch("platform.system")
    @patch("platform.release")
    @patch("getpass.getuser")
    def test_get_os_info_unknown_system(self, mock_getuser, mock_release, mock_system):
        """Test getting OS info on unknown system."""
        mock_system.return_value = "FreeBSD"
        mock_release.return_value = "13.2-RELEASE"
        mock_getuser.return_value = "bsduser"

        result = get_os_info()

        expected = ("FreeBSD", OsFamily.UNKNOWN, "13.2-RELEASE", "", "bsduser")
        assert result == expected
        mock_system.assert_called()
        mock_release.assert_called_once()

    @patch("platform.system")
    @patch("getpass.getuser")
    def test_get_os_info_case_insensitive(self, mock_getuser, mock_system):
        """Test that system detection is case insensitive."""
        mock_system.return_value = "WINDOWS"
        mock_getuser.return_value = "testuser"

        with patch(
            "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_windows_version_info"
        ) as mock_windows:
            mock_windows_info = Mock()
            mock_windows_info.product_name = "Windows 11"
            mock_windows_info.display_version = "23H2"
            mock_windows_info.build = "22621"
            mock_windows_info.ubr = "1000"
            mock_windows.return_value = mock_windows_info

            result = get_os_info()
            assert result[0] == "Windows 11"
            assert result[1] == OsFamily.WINDOWS

    @patch("platform.system")
    @patch("getpass.getuser")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_version_info"
    )
    def test_get_os_info_linux_empty_name_and_pretty_name(
        self, mock_get_linux_version_info, mock_getuser, mock_system
    ):
        """Test Linux OS info when both name and pretty_name are empty."""
        mock_system.return_value = "Linux"
        mock_getuser.return_value = "testuser"

        mock_linux_info = Mock()
        mock_linux_info.name = ""
        mock_linux_info.pretty_name = ""
        mock_linux_info.version = "5.15"
        mock_get_linux_version_info.return_value = mock_linux_info

        result = get_os_info()

        # Should use empty string when both are empty
        expected = ("", OsFamily.LINUX, "5.15", None, "testuser")
        assert result == expected


@pytest.mark.unit
class TestKernelNameEnum:
    """Test KernelName enum."""

    def test_kernel_name_values(self):
        """Test KernelName enum values."""
        assert KernelName.WINDOWS_NT.value == "Windows NT"
        assert KernelName.LINUX.value == "Linux"
        assert KernelName.XNU.value == "XNU"
        assert KernelName.UNKNOWN.value == "Unknown"

    def test_kernel_name_membership(self):
        """Test KernelName enum membership."""
        assert KernelName.WINDOWS_NT in KernelName
        assert KernelName.LINUX in KernelName
        assert KernelName.XNU in KernelName
        assert KernelName.UNKNOWN in KernelName

    def test_kernel_name_comparison(self):
        """Test KernelName enum comparison."""
        assert KernelName.LINUX == KernelName.LINUX
        assert KernelName.LINUX != KernelName.WINDOWS_NT
        assert KernelName.XNU != KernelName.UNKNOWN


@pytest.mark.unit
class TestErrorHandling:
    """Test error handling in host detection functions."""

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_machine_id"
    )
    def test_get_machine_id_handler_exception(
        self, mock_get_linux_machine_id, mock_system
    ):
        """Test get_machine_id when handler raises exception."""
        mock_system.return_value = "Linux"
        mock_get_linux_machine_id.side_effect = Exception("Test error")

        # The current implementation doesn't catch exceptions from handlers
        # so this should raise the exception
        with pytest.raises(Exception, match="Test error"):
            get_machine_id()

    @patch("platform.system")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_xnu_kernel_version"
    )
    def test_get_kernel_info_handler_exception(
        self, mock_get_xnu_kernel_version, mock_system
    ):
        """Test get_kernel_info when handler raises exception."""
        mock_system.return_value = "Darwin"
        mock_get_xnu_kernel_version.side_effect = Exception("Test error")

        # The current implementation doesn't catch exceptions from handlers
        # so this should raise the exception
        with pytest.raises(Exception, match="Test error"):
            get_kernel_info()

    @patch("platform.system")
    @patch("getpass.getuser")
    @patch(
        "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.get_linux_version_info"
    )
    def test_get_os_info_handler_exception(
        self, mock_get_linux_version_info, mock_getuser, mock_system
    ):
        """Test get_os_info when handler raises exception."""
        mock_system.return_value = "Linux"
        mock_getuser.return_value = "testuser"
        mock_get_linux_version_info.side_effect = Exception("Test error")

        # The current implementation doesn't catch exceptions from handlers
        # so this should raise the exception
        with pytest.raises(Exception, match="Test error"):
            get_os_info()

    @patch("platform.system")
    @patch("platform.release")
    @patch("getpass.getuser")
    def test_get_os_info_getuser_exception(
        self, mock_getuser, mock_release, mock_system
    ):
        """Test get_os_info when getuser raises exception."""
        mock_system.return_value = "FreeBSD"
        mock_release.return_value = "13.2"
        mock_getuser.side_effect = Exception("Cannot get user")

        # Should propagate the getuser exception since it's not caught
        with pytest.raises(Exception, match="Cannot get user"):
            get_os_info()


@pytest.mark.integration
@pytest.mark.unix_only
@pytest.mark.skipif(
    sys_platform not in ["linux", "linux2", "darwin"], reason="Unix-specific test"
)
class TestHostDetectionIntegration:
    """Integration tests for host detection functions."""

    def test_get_machine_id_integration(self):
        """Test get_machine_id with real system calls."""
        result = get_machine_id()

        # Result should be either a valid machine ID string or None
        if result is not None:
            assert isinstance(result, str)
            assert len(result) > 0
            assert result.strip() == result  # No leading/trailing whitespace

    def test_get_kernel_info_integration(self):
        """Test get_kernel_info with real system calls."""
        kernel_name, kernel_version = get_kernel_info()

        assert isinstance(kernel_name, KernelName)
        assert isinstance(kernel_version, str)
        assert len(kernel_version) > 0

    def test_get_os_info_integration(self):
        """Test get_os_info with real system calls."""
        os_name, os_family, os_version, os_build, os_username = get_os_info()

        assert isinstance(os_name, str)
        assert isinstance(os_family, OsFamily)
        assert isinstance(os_version, str)
        assert isinstance(os_username, str)

        # OS name and version should not be empty
        assert len(os_name) > 0
        assert len(os_version) > 0
        assert len(os_username) > 0

        # Build can be empty string or None
        assert os_build is None or isinstance(os_build, str)
