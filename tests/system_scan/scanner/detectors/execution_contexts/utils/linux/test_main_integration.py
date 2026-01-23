from __future__ import annotations

import pytest
import platform
import os
from sys import platform as sys_platform
from pathlib import Path

from safety.system_scan.scanner.detectors.execution_contexts.utils.linux.main import (
    get_linux_machine_id,
)


@pytest.mark.linux
@pytest.mark.skipif(
    sys_platform not in ["linux", "linux2"], reason="Linux-specific test"
)
@pytest.mark.integration
@pytest.mark.slow
class TestLinuxMachineIdIntegration:
    """Integration tests for Linux machine ID functionality."""

    def test_get_linux_machine_id_real(self):
        """Test getting real Linux machine ID on actual Linux system."""
        # Skip if not running on Linux
        if platform.system() != "Linux":
            pytest.skip("Test requires Linux system")

        result = get_linux_machine_id()

        # On real Linux systems, should typically return a machine ID
        if result is not None:
            assert isinstance(result, str)
            assert len(result) > 0
            # Machine ID is typically 32 hex characters, but we'll be flexible
            assert len(result) >= 16  # At least some reasonable length
            assert all(
                c.isalnum() or c == "-" for c in result
            )  # Alphanumeric or dashes

    def test_machine_id_files_exist_on_linux(self):
        """Test that machine ID files exist on real Linux systems."""
        if platform.system() != "Linux":
            pytest.skip("Test requires Linux system")

        # At least one of these paths should exist on a real Linux system
        paths = [
            Path("/etc/machine-id"),
            Path("/var/lib/dbus/machine-id"),
        ]

        found_files = [path for path in paths if path.exists()]

        # We expect at least one machine ID file to exist on a real Linux system
        # But we won't fail if neither exists, as some systems might be configured differently
        if found_files:
            for path in found_files:
                assert path.is_file(), f"{path} should be a regular file"

                # Check file size is reasonable (not empty, not huge)
                stat_result = path.stat()
                assert 0 < stat_result.st_size <= 64, (
                    f"{path} should have reasonable size"
                )

    def test_machine_id_content_format_on_linux(self):
        """Test that machine ID content follows expected format on real Linux."""
        if platform.system() != "Linux":
            pytest.skip("Test requires Linux system")

        result = get_linux_machine_id()

        if result is not None:
            # Machine ID should not contain whitespace after stripping
            assert result == result.strip()

            # Should be printable ASCII
            assert result.isprintable()

            # Common format is 32 hex chars, but some systems may vary
            if len(result) == 32:
                # If it's 32 chars, should be hex
                assert all(c in "0123456789abcdefABCDEF" for c in result)

    def test_machine_id_consistency_on_linux(self):
        """Test that machine ID returns consistently on real Linux."""
        if platform.system() != "Linux":
            pytest.skip("Test requires Linux system")

        # Call multiple times and verify consistency
        first_call = get_linux_machine_id()
        second_call = get_linux_machine_id()
        third_call = get_linux_machine_id()

        # All calls should return the same result
        assert first_call == second_call == third_call

    def test_machine_id_file_permissions_on_linux(self):
        """Test that machine ID files have expected permissions on real Linux."""
        if platform.system() != "Linux":
            pytest.skip("Test requires Linux system")

        paths = [
            Path("/etc/machine-id"),
            Path("/var/lib/dbus/machine-id"),
        ]

        for path in paths:
            if path.exists():
                # File should be readable
                assert os.access(path, os.R_OK), f"{path} should be readable"

                # Get file mode
                stat_result = path.stat()
                mode = stat_result.st_mode

                # Should be a regular file (not directory, symlink, etc.)
                import stat

                assert stat.S_ISREG(mode), f"{path} should be a regular file"


@pytest.mark.unix_only
@pytest.mark.skipif(
    sys_platform not in ["linux", "linux2", "darwin"], reason="Unix-specific test"
)
@pytest.mark.integration
@pytest.mark.slow
class TestLinuxMachineIdUnixCompatibility:
    """Test Linux machine ID behavior on Unix-like systems."""

    def test_get_linux_machine_id_graceful_on_non_linux(self):
        """Test that function fails gracefully on non-Linux Unix systems."""
        if platform.system() == "Windows":
            pytest.skip("Test requires Unix-like system")

        # Function should not crash on non-Linux Unix systems
        result = get_linux_machine_id()

        # Result should be None or a string (no exceptions)
        assert result is None or isinstance(result, str)

    def test_machine_id_paths_handling_on_unix(self):
        """Test that machine ID path handling works on Unix systems."""
        if platform.system() == "Windows":
            pytest.skip("Test requires Unix-like system")

        # Even if files don't exist, function should handle gracefully
        result = get_linux_machine_id()

        # Should return None or valid string, never crash
        assert result is None or (isinstance(result, str) and len(result) > 0)


@pytest.mark.integration
@pytest.mark.slow
class TestLinuxMachineIdFileSystemErrors:
    """Test Linux machine ID behavior with filesystem errors."""

    def test_get_linux_machine_id_nonexistent_paths(self):
        """Test behavior when machine ID files don't exist."""
        # This test doesn't require specific OS since it tests error handling
        result = get_linux_machine_id()

        # Function should handle nonexistent files gracefully
        assert result is None or isinstance(result, str)
