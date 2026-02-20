from __future__ import annotations

import pytest
import subprocess
from unittest.mock import patch, Mock

from safety.system_scan.scanner.detectors.execution_contexts.utils.macos.main import (
    get_xnu_kernel_version,
    get_macos_version_info,
    SwVersKey,
    SW_VERS_KEYS,
)
from safety.system_scan.scanner.detectors.execution_contexts.utils.main import (
    MacOSVersionInfo,
)


@pytest.mark.unit
class TestGetXnuKernelVersion:
    """Test get_xnu_kernel_version function."""

    @patch("platform.version")
    def test_get_xnu_kernel_version_success(self, mock_version):
        """Test extracting XNU kernel version successfully."""
        mock_version.return_value = "Darwin Kernel Version 23.1.0: Mon Oct  9 21:27:24 PDT 2023; root:xnu-10002.41.9~6/RELEASE_ARM64_T6000"

        result = get_xnu_kernel_version()

        assert result == "10002.41.9~6"

    @patch("platform.version")
    def test_get_xnu_kernel_version_no_xnu_marker(self, mock_version):
        """Test extracting XNU kernel version when xnu marker not found."""
        mock_version.return_value = "Some other kernel version string"

        result = get_xnu_kernel_version()

        assert result == ""

    @patch("platform.version")
    def test_get_xnu_kernel_version_case_insensitive(self, mock_version):
        """Test extracting XNU kernel version with case variation."""
        mock_version.return_value = (
            "Darwin Kernel Version 23.1.0: root:XNU-10002.41.9~6/RELEASE_ARM64_T6000"
        )

        result = get_xnu_kernel_version()

        assert result == "10002.41.9~6"

    @patch("platform.version")
    def test_get_xnu_kernel_version_with_slash(self, mock_version):
        """Test extracting XNU kernel version with slash separator."""
        mock_version.return_value = (
            "Darwin Kernel Version 23.1.0: root:xnu-10002.41.9~6/RELEASE_ARM64_T6000"
        )

        result = get_xnu_kernel_version()

        assert result == "10002.41.9~6"

    @patch("platform.version")
    def test_get_xnu_kernel_version_no_slash(self, mock_version):
        """Test extracting XNU kernel version without slash separator."""
        mock_version.return_value = (
            "Darwin Kernel Version 23.1.0: root:xnu-10002.41.9~6"
        )

        result = get_xnu_kernel_version()

        assert result == "10002.41.9~6"

    @patch("platform.version")
    def test_get_xnu_kernel_version_empty_after_xnu(self, mock_version):
        """Test extracting XNU kernel version when empty after xnu marker."""
        mock_version.return_value = "Darwin Kernel Version 23.1.0: root:xnu-"

        result = get_xnu_kernel_version()

        assert result == ""


@pytest.mark.unit
class TestGetMacOSVersionInfo:
    """Test get_macos_version_info function."""

    @patch("subprocess.run")
    def test_get_macos_version_info_success(self, mock_run):
        """Test getting macOS version info successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """ProductName:\tmacOS
ProductVersion:\t14.1.2
BuildVersion:\t23B92"""
        mock_run.return_value = mock_result

        result = get_macos_version_info()

        assert isinstance(result, MacOSVersionInfo)
        assert result.name == "macOS"
        assert result.version == "14.1.2"
        assert result.build == "23B92"

        mock_run.assert_called_once_with(
            ["sw_vers"],
            capture_output=True,
            text=True,
            timeout=5,
        )

    @patch("subprocess.run")
    @patch("platform.mac_ver")
    def test_get_macos_version_info_sw_vers_fails(self, mock_mac_ver, mock_run):
        """Test getting macOS version info when sw_vers fails."""
        mock_run.side_effect = subprocess.SubprocessError("Command failed")
        mock_mac_ver.return_value = ("13.6.1", ("", "", ""), "arm64")

        result = get_macos_version_info()

        assert result.name == "macOS"  # fallback
        assert result.version == "13.6.1"  # from platform.mac_ver
        assert result.build == ""  # fallback

    @patch("subprocess.run")
    @patch("platform.mac_ver")
    def test_get_macos_version_info_sw_vers_nonzero_exit(self, mock_mac_ver, mock_run):
        """Test getting macOS version info when sw_vers returns non-zero."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        mock_mac_ver.return_value = ("13.6.1", ("", "", ""), "arm64")

        result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == "13.6.1"
        assert result.build == ""

    @patch("subprocess.run")
    def test_get_macos_version_info_partial_data(self, mock_run):
        """Test getting macOS version info with partial data."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """ProductName:\tmacOS
ProductVersion:\t14.1.2"""  # Missing BuildVersion
        mock_run.return_value = mock_result

        with patch("platform.mac_ver") as mock_mac_ver:
            mock_mac_ver.return_value = ("14.1.2", ("", "", ""), "arm64")
            result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == "14.1.2"
        assert result.build == ""  # fallback

    @patch("subprocess.run")
    def test_get_macos_version_info_malformed_output(self, mock_run):
        """Test getting macOS version info with malformed output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """ProductName:\tmacOS
InvalidLine
ProductVersion:\t14.1.2
LineWithoutColon
BuildVersion:\t23B92"""
        mock_run.return_value = mock_result

        result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == "14.1.2"
        assert result.build == "23B92"

    @patch("subprocess.run")
    def test_get_macos_version_info_unknown_keys(self, mock_run):
        """Test getting macOS version info with unknown keys."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """ProductName:\tmacOS
ProductVersion:\t14.1.2
BuildVersion:\t23B92
UnknownKey:\tUnknownValue"""
        mock_run.return_value = mock_result

        result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == "14.1.2"
        assert result.build == "23B92"

    @patch("subprocess.run")
    def test_get_macos_version_info_case_variations(self, mock_run):
        """Test getting macOS version info with case variations."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """productname:\tmacOS
PRODUCTVERSION:\t14.1.2
buildversion:\t23B92"""
        mock_run.return_value = mock_result

        result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == "14.1.2"
        assert result.build == "23B92"

    @patch("subprocess.run")
    def test_get_macos_version_info_whitespace_handling(self, mock_run):
        """Test getting macOS version info with extra whitespace."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """  ProductName  :  macOS
  ProductVersion  :  14.1.2
  BuildVersion  :  23B92  """
        mock_run.return_value = mock_result

        result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == "14.1.2"
        assert result.build == "23B92"

    @patch("subprocess.run")
    @patch("platform.mac_ver")
    def test_get_macos_version_info_os_error(self, mock_mac_ver, mock_run):
        """Test getting macOS version info when OS error occurs."""
        mock_run.side_effect = OSError("Permission denied")
        mock_mac_ver.return_value = ("13.6.1", ("", "", ""), "arm64")

        result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == "13.6.1"
        assert result.build == ""

    @patch("subprocess.run")
    @patch("platform.mac_ver")
    def test_get_macos_version_info_empty_platform_mac_ver(
        self, mock_mac_ver, mock_run
    ):
        """Test getting macOS version info when platform.mac_ver returns empty."""
        mock_run.side_effect = subprocess.SubprocessError()
        mock_mac_ver.return_value = ("", ("", "", ""), "")

        result = get_macos_version_info()

        assert result.name == "macOS"
        assert result.version == ""
        assert result.build == ""


@pytest.mark.unit
class TestSwVersConstants:
    """Test SwVersKey enum and SW_VERS_KEYS constant."""

    def test_sw_vers_key_values(self):
        """Test SwVersKey enum values."""
        assert SwVersKey.PRODUCT_NAME == "productname"
        assert SwVersKey.PRODUCT_VERSION == "productversion"
        assert SwVersKey.BUILD_VERSION == "buildversion"

    def test_sw_vers_keys_constant(self):
        """Test SW_VERS_KEYS contains all enum values."""
        expected_keys = {"productname", "productversion", "buildversion"}
        assert SW_VERS_KEYS == expected_keys

    def test_sw_vers_keys_membership(self):
        """Test membership testing with SW_VERS_KEYS."""
        assert "productname" in SW_VERS_KEYS
        assert "productversion" in SW_VERS_KEYS
        assert "buildversion" in SW_VERS_KEYS
        assert "unknownkey" not in SW_VERS_KEYS
