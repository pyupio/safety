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
from safety.errors import MachineIdUnavailableError
from safety.system_scan.scanner.events.payloads.execution_context import OsFamily


# Patch target for resolve_machine_id where it's looked up (in host.py's namespace),
# not where it's defined (safety.auth.machine_id).
_RESOLVE_MACHINE_ID = "safety.system_scan.scanner.detectors.execution_contexts.subtypes.host.resolve_machine_id"


@pytest.mark.unit
class TestGetMachineId:
    """Test get_machine_id delegation to resolve_machine_id()."""

    @patch(_RESOLVE_MACHINE_ID)
    def test_machine_id_unavailable_returns_none(self, mock_resolve):
        """MachineIdUnavailableError is caught and returns None."""
        mock_resolve.side_effect = MachineIdUnavailableError()

        result = get_machine_id()

        assert result is None
        mock_resolve.assert_called_once()


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


@pytest.mark.unit
class TestErrorHandling:
    """Test error handling in host detection functions."""

    @patch(_RESOLVE_MACHINE_ID)
    def test_get_machine_id_handler_exception(self, mock_resolve):
        """Test get_machine_id when resolve_machine_id raises a non-handled exception."""
        mock_resolve.side_effect = Exception("Test error")

        # Only MachineIdUnavailableError is caught; other exceptions propagate
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
