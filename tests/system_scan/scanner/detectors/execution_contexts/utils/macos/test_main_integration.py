from __future__ import annotations

import pytest
import platform
from sys import platform as sys_platform

from safety.system_scan.scanner.detectors.execution_contexts.utils.macos.main import (
    get_xnu_kernel_version,
    get_macos_version_info,
)
from safety.system_scan.scanner.detectors.execution_contexts.utils.main import (
    MacOSVersionInfo,
)


@pytest.mark.darwin
@pytest.mark.skipif(sys_platform != "darwin", reason="macOS-specific test")
@pytest.mark.integration
@pytest.mark.slow
class TestMacOSIntegration:
    """Integration tests for macOS functionality."""

    def test_get_xnu_kernel_version_real(self):
        """Test getting real XNU kernel version on actual macOS system."""
        if platform.system() != "Darwin":
            pytest.skip("Test requires macOS system")

        result = get_xnu_kernel_version()

        assert isinstance(result, str)
        # On real macOS, should return something like "10002.41.9~6" or empty string
        if result:
            # Basic validation - should contain numbers
            assert any(c.isdigit() for c in result)

    def test_get_macos_version_info_real(self):
        """Test getting real macOS version info on actual macOS system."""
        if platform.system() != "Darwin":
            pytest.skip("Test requires macOS system")

        result = get_macos_version_info()

        assert isinstance(result, MacOSVersionInfo)
        assert result.name != ""  # Should have some OS name
        assert result.version != ""  # Should have some version

        # Basic validation of fields
        assert isinstance(result.build, str)

        # Version should look like semantic version (e.g., "14.1.2")
        if result.version:
            parts = result.version.split(".")
            assert len(parts) >= 2  # At least major.minor
            assert all(part.isdigit() for part in parts)

        # Build should be alphanumeric if present
        if result.build:
            assert result.build.replace(".", "").replace("-", "").isalnum()


@pytest.mark.darwin
@pytest.mark.skipif(sys_platform != "darwin", reason="macOS-specific test")
@pytest.mark.integration
@pytest.mark.slow
class TestMacOSCommandAvailability:
    """Test availability of macOS system commands."""

    def test_sw_vers_command_available(self):
        """Test that sw_vers command is available on macOS."""
        if platform.system() != "Darwin":
            pytest.skip("Test requires macOS system")

        import subprocess

        try:
            result = subprocess.run(
                ["which", "sw_vers"], capture_output=True, text=True, timeout=5
            )
            # Should find sw_vers command on macOS
            assert result.returncode == 0
            assert "sw_vers" in result.stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            pytest.fail("sw_vers command should be available on macOS")
