from __future__ import annotations

import pytest
import platform
from sys import platform as sys_platform

from safety.system_scan.scanner.detectors.execution_contexts.utils.linux.os_release import (
    get_linux_version_info,
)
from safety.system_scan.scanner.detectors.execution_contexts.utils.main import (
    LinuxVersionInfo,
)


@pytest.mark.linux
@pytest.mark.skipif(
    sys_platform not in ["linux", "linux2"], reason="Linux-specific test"
)
@pytest.mark.integration
@pytest.mark.slow
class TestLinuxIntegration:
    """Integration tests for Linux os-release functionality."""

    def test_get_linux_version_info_real(self):
        """Test getting real Linux version info on actual Linux system."""
        # Skip if not running on Linux
        if platform.system() != "Linux":
            pytest.skip("Test requires Linux system")

        result = get_linux_version_info()

        assert isinstance(result, LinuxVersionInfo)
        assert result.id != ""  # Should have some distribution ID
        assert result.name != ""  # Should have some distribution name

        # Basic validation of fields
        assert isinstance(result.version, str)
        assert isinstance(result.version_id, str)
        assert isinstance(result.codename, str)
        assert isinstance(result.pretty_name, str)
        assert isinstance(result.id_like, str)

    def test_get_linux_version_info_with_custom_root(self):
        """Test getting Linux version info with custom root (should fail gracefully)."""
        if platform.system() != "Linux":
            pytest.skip("Test requires Linux system")

        # Using a non-existent root should return minimal info
        result = get_linux_version_info(root="/nonexistent")

        assert isinstance(result, LinuxVersionInfo)
        # Should fall back to defaults when files don't exist
        assert result.id == "linux"
        assert result.name == "Linux"
        assert result.pretty_name == "Linux"
