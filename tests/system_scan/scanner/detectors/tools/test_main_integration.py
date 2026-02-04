from __future__ import annotations

import pytest
from sys import platform as sys_platform
from pathlib import Path
from unittest.mock import Mock

from safety.system_scan.scanner.detectors.tools.main import ToolDetector
from safety.system_scan.scanner.models import Candidate
from safety.system_scan.scanner.filesystem.runtime import FsRuntime
from safety.system_scan.scanner.registry import ScanRefRegistry
from safety.system_scan.scanner.context import DetectContext
from safety.system_scan.scanner.events.payloads.links import ExecutionContextRelation


@pytest.mark.integration
@pytest.mark.slow
class TestToolDetectorIntegration:
    """Integration tests for ToolDetector with real filesystem."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        """Create ToolDetector instance."""
        return ToolDetector()

    @pytest.fixture
    def real_fs(self) -> FsRuntime:
        """Real filesystem runtime for integration tests."""
        return FsRuntime()

    @pytest.fixture
    def mock_registry(self) -> Mock:
        """Mock scan registry."""
        registry = Mock(spec=ScanRefRegistry)
        registry.is_seen.return_value = False  # Never seen before
        return registry

    @pytest.fixture
    def mock_context(self, real_fs, mock_registry) -> Mock:
        """Mock detect context with real filesystem."""
        ctx = Mock(spec=DetectContext)
        ctx.fs = real_fs
        ctx.registry = mock_registry
        ctx.exec_ctx_rel = Mock(spec=ExecutionContextRelation)
        return ctx

    def test_detect_system_python_pip(self, detector: ToolDetector, mock_context):
        """Test detecting system pip installation."""
        # Common system pip locations
        potential_paths = [
            Path("/usr/bin/pip"),
            Path("/usr/bin/pip3"),
            Path("/usr/local/bin/pip"),
            Path("/usr/local/bin/pip3"),
            Path("/opt/homebrew/bin/pip"),  # macOS Homebrew
            Path("/opt/homebrew/bin/pip3"),
        ]

        found_tools = []
        for path in potential_paths:
            if path.exists() and path.is_file():
                candidate = Candidate(path=path, source="INTEGRATION_TEST", hint="tool")
                results = list(detector.detect(candidate, mock_context))
                if results:
                    found_tools.extend(results)
                    break

        # If we found any pip tools, validate them
        for tool in found_tools:
            assert tool.subtype == "package_manager:pip"
            assert tool.primary_path in [str(p) for p in potential_paths]
            assert tool.scope in ["system", "user"]

    @pytest.mark.unix_only
    @pytest.mark.skipif(
        sys_platform not in ["linux", "linux2", "darwin"], reason="Unix-specific test"
    )
    def test_scan_usr_bin_directory(self, detector: ToolDetector, real_fs: FsRuntime):
        """
        Test scanning /usr/bin directory on Unix systems.
        """

        usr_bin = Path("/usr/bin")
        if not usr_bin.exists():
            pytest.skip("/usr/bin directory not found")

        mock_registry = Mock(spec=ScanRefRegistry)
        mock_registry.is_seen.return_value = False
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        # Scan the directory
        results = list(
            detector.scan_directory(
                directory_path=usr_bin,
                fs=real_fs,
                exec_context_ref=mock_exec_ctx_rel,
                scan_registry=mock_registry,
                source="INTEGRATION_TEST",
            )
        )

        # Should find at least some tools in /usr/bin
        # Don't assert specific count as this varies by system
        if results:
            for result in results:
                assert result.scope == "system"
                assert result.found_via == ["INTEGRATION_TEST"]
                assert result.subtype in ToolDetector.TOOL_PATTERNS.values()

    @pytest.mark.darwin
    @pytest.mark.skipif(sys_platform != "darwin", reason="macOS-specific test")
    def test_scan_homebrew_bin_directory(
        self, detector: ToolDetector, real_fs: FsRuntime
    ):
        """
        Test scanning Homebrew bin directory on macOS.
        """

        # Try both Intel and Apple Silicon Homebrew paths
        homebrew_paths = [
            Path("/usr/local/bin"),  # Intel Mac
            Path("/opt/homebrew/bin"),  # Apple Silicon Mac
        ]

        for homebrew_bin in homebrew_paths:
            if not homebrew_bin.exists():
                continue

            mock_registry = Mock(spec=ScanRefRegistry)
            mock_registry.is_seen.return_value = False
            mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

            results = list(
                detector.scan_directory(
                    directory_path=homebrew_bin,
                    fs=real_fs,
                    exec_context_ref=mock_exec_ctx_rel,
                    scan_registry=mock_registry,
                    source="HOMEBREW_SCAN",
                )
            )

            # If we found tools, validate them
            for result in results:
                assert result.scope in ["system", "user"]
                assert result.found_via == ["HOMEBREW_SCAN"]
                break  # Only need to test one path that exists

    def test_validate_real_files(self, detector: ToolDetector, real_fs: FsRuntime):
        """Test _validate method with real filesystem files."""
        # Test with a file that should exist on most systems
        test_paths = [
            Path("/bin/sh"),  # Unix shell
            Path("/usr/bin/python3"),  # Python 3
            Path("/usr/bin/git"),  # Git
        ]

        for path in test_paths:
            if path.exists():
                result = detector._validate(path, real_fs)

                if path.name in ["git"]:
                    assert result == "vcs:git"
                elif "python" in path.name:
                    # Python executable, but not in our tool patterns
                    assert result is None
                else:
                    # sh is not in our patterns
                    assert result is None
                break

    @pytest.mark.unix_only
    @pytest.mark.skipif(
        sys_platform not in ["linux", "linux2", "darwin"], reason="Unix-specific tests"
    )
    def test_is_system_tool_real_paths(self, detector: ToolDetector):
        """
        Test _is_system_tool with real system paths.
        """
        system_paths = [
            Path("/usr/bin/python3"),
            Path("/usr/local/bin/git"),
            Path("/bin/sh"),
        ]

        user_paths = [
            Path("/home/user/.local/bin/pip"),
            Path("/Users/user/venv/bin/python"),
            Path("./local_script"),
        ]

        for path in system_paths:
            assert detector._is_system_tool(path) is True

        for path in user_paths:
            assert detector._is_system_tool(path) is False

    def test_get_stable_id_real_files(self, detector: ToolDetector, real_fs: FsRuntime):
        """Test _get_stable_id with real filesystem files."""
        test_paths = [
            Path("/bin/sh"),
            Path("/usr/bin/python3"),
            Path("/etc/hosts"),  # Not executable, but should have stats
        ]

        for path in test_paths:
            if path.exists():
                stable_id = detector._get_stable_id(path, real_fs)

                # Should contain tool name and either inode info or path
                assert path.stem.lower() in stable_id
                assert stable_id.startswith("tool:")

                # Should be either inode format or path fallback format
                if ":" in stable_id[5:]:  # Remove "tool:" prefix
                    parts = stable_id.split(":")
                    if len(parts) >= 4:
                        # Inode format: tool:name:device:inode
                        assert parts[2].isdigit()  # device
                        assert parts[3].isdigit()  # inode
                break


@pytest.mark.integration
@pytest.mark.slow
class TestToolDetectorFileSystemErrors:
    """Test ToolDetector behavior with filesystem errors."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        return ToolDetector()

    @pytest.fixture
    def real_fs(self) -> FsRuntime:
        return FsRuntime()

    def test_scan_nonexistent_directory(
        self, detector: ToolDetector, real_fs: FsRuntime
    ):
        """Test scanning non-existent directory."""
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        results = list(
            detector.scan_directory(
                directory_path=Path("/definitely/does/not/exist"),
                fs=real_fs,
                exec_context_ref=mock_exec_ctx_rel,
                scan_registry=mock_registry,
            )
        )

        assert len(results) == 0

    def test_validate_nonexistent_file(
        self, detector: ToolDetector, real_fs: FsRuntime
    ):
        """Test validating non-existent file."""
        result = detector._validate(Path("/definitely/does/not/exist"), real_fs)
        assert result is None
