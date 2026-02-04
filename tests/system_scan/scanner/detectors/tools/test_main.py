from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from safety.system_scan.scanner.detectors.tools.main import ToolDetector
from safety.system_scan.scanner.models import Candidate, Detection, DetectionKind
from safety.system_scan.scanner.filesystem.runtime import FsRuntime
from safety.system_scan.scanner.registry import ScanRefRegistry
from safety.system_scan.scanner.context import DetectContext
from safety.system_scan.scanner.events.payloads.links import ExecutionContextRelation


@pytest.mark.unit
class TestToolDetector:
    """Test ToolDetector class."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        """Create ToolDetector instance."""
        return ToolDetector()

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """Mock filesystem runtime."""
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def mock_registry(self) -> Mock:
        """Mock scan registry."""
        return Mock(spec=ScanRefRegistry)

    @pytest.fixture
    def mock_exec_ctx_rel(self) -> Mock:
        """Mock execution context relation."""
        return Mock(spec=ExecutionContextRelation)

    @pytest.fixture
    def mock_context(self, mock_fs, mock_registry, mock_exec_ctx_rel) -> Mock:
        """Mock detect context."""
        ctx = Mock(spec=DetectContext)
        ctx.fs = mock_fs
        ctx.registry = mock_registry
        ctx.exec_ctx_rel = mock_exec_ctx_rel
        return ctx


@pytest.mark.unit
class TestValidate:
    """Test _validate method."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        return ToolDetector()

    def test_validate_known_tool_executable(self, detector: ToolDetector):
        """Test validating known executable tool."""
        mock_fs = Mock(spec=FsRuntime)
        mock_fs.is_file.return_value = True
        mock_fs.is_executable.return_value = True

        path = Path("/usr/bin/pip")
        result = detector._validate(path, mock_fs)

        assert result == "package_manager:pip"
        mock_fs.is_file.assert_called_once_with(path)
        mock_fs.is_executable.assert_called_once_with(path)

    def test_validate_unknown_tool(self, detector: ToolDetector):
        """Test validating unknown tool."""
        mock_fs = Mock(spec=FsRuntime)
        mock_fs.is_file.return_value = True
        mock_fs.is_executable.return_value = True

        path = Path("/usr/bin/unknown")
        result = detector._validate(path, mock_fs)

        assert result is None

    def test_validate_not_file(self, detector: ToolDetector):
        """Test validating path that is not a file."""
        mock_fs = Mock(spec=FsRuntime)
        mock_fs.is_file.return_value = False

        path = Path("/usr/bin/pip")
        result = detector._validate(path, mock_fs)

        assert result is None
        mock_fs.is_file.assert_called_once_with(path)

    def test_validate_not_executable(self, detector: ToolDetector):
        """Test validating file that is not executable."""
        mock_fs = Mock(spec=FsRuntime)
        mock_fs.is_file.return_value = True
        mock_fs.is_executable.return_value = False

        path = Path("/usr/bin/pip")
        result = detector._validate(path, mock_fs)

        assert result is None
        mock_fs.is_executable.assert_called_once_with(path)

    def test_validate_case_insensitive(self, detector: ToolDetector):
        """Test validating with case insensitive matching."""
        mock_fs = Mock(spec=FsRuntime)
        mock_fs.is_file.return_value = True
        mock_fs.is_executable.return_value = True

        path = Path("/usr/bin/PIP")
        result = detector._validate(path, mock_fs)

        assert result == "package_manager:pip"


@pytest.mark.unit
class TestGetStableId:
    """Test _get_stable_id method."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        return ToolDetector()

    def test_get_stable_id_success(self, detector: ToolDetector):
        """Test getting stable ID from file stats."""
        mock_fs = Mock(spec=FsRuntime)
        mock_stat = Mock()
        mock_stat.st_dev = 12345
        mock_stat.st_ino = 67890
        mock_fs.stat.return_value = mock_stat

        path = Path("/usr/bin/pip")
        result = detector._get_stable_id(path, mock_fs)

        assert result == "tool:pip:12345:67890"
        mock_fs.stat.assert_called_once_with(path)

    def test_get_stable_id_os_error(self, detector: ToolDetector):
        """Test getting stable ID when stat fails with OSError."""
        mock_fs = Mock(spec=FsRuntime)
        mock_fs.stat.side_effect = OSError("Permission denied")

        path = Path("/usr/bin/pip")
        result = detector._get_stable_id(path, mock_fs)

        assert result == f"tool:pip:{path}"

    def test_get_stable_id_permission_error(self, detector: ToolDetector):
        """Test getting stable ID when stat fails with PermissionError."""
        mock_fs = Mock(spec=FsRuntime)
        mock_fs.stat.side_effect = PermissionError("Access denied")

        path = Path("/usr/bin/pip")
        result = detector._get_stable_id(path, mock_fs)

        assert result == f"tool:pip:{path}"


@pytest.mark.unit
class TestIsSystemTool:
    @pytest.fixture
    def detector(self) -> ToolDetector:
        return ToolDetector()

    @pytest.mark.parametrize(
        "platform_name,path,expected",
        [
            # Linux system tools
            ("Linux", "/bin/sh", True),
            ("Linux", "/usr/bin/pip", True),
            ("Linux", "/usr/local/bin/pip", True),
            # macOS system tools
            (
                "Darwin",
                "/System/Library/Frameworks/Python.framework/Versions/3.9/bin/pip",
                True,
            ),
            # Windows system tools
            ("Windows", "C:/Program Files/Python39/Scripts/pip.exe", True),
            # Non-system tools
            ("Linux", "/home/user/.local/bin/pip", False),
            ("Linux", "/home/user/project/venv/bin/pip", False),
        ],
    )
    @patch("safety.system_scan.scanner.detectors.tools.main.platform.system")
    def test_is_system_tool(
        self,
        mock_platform,
        detector: ToolDetector,
        platform_name: str,
        path: str,
        expected: bool,
    ):
        mock_platform.return_value = platform_name
        assert detector._is_system_tool(Path(path)) is expected


@pytest.mark.unit
class TestDetectTool:
    """Test _detect_tool method."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        return ToolDetector()

    @patch("safety.system_scan.scanner.detectors.tools.main.collect_tool_info")
    @patch.object(ToolDetector, "_is_system_tool", return_value=True)
    def test_detect_tool_success(
        self, mock_is_system_tool, mock_collect_tool_info, detector: ToolDetector
    ):
        """Test successful tool detection."""
        # Setup mocks
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_stat = Mock()
        mock_stat.st_dev = 12345
        mock_stat.st_ino = 67890
        mock_fs.stat.return_value = mock_stat

        mock_registry.is_seen.return_value = False

        mock_tool_info = Mock()
        mock_collect_tool_info.return_value = mock_tool_info

        path = Path("/usr/bin/pip")
        subtype = "package_manager:pip"

        result = detector._detect_tool(
            path=path,
            subtype=subtype,
            fs=mock_fs,
            exec_context_ref=mock_exec_ctx_rel,
            scan_registry=mock_registry,
            source="DIRECT",
        )

        assert result is not None
        assert isinstance(result, Detection)
        assert result.kind == DetectionKind.TOOL
        assert result.subtype == subtype
        assert result.primary_path == str(path)
        assert result.scope == "system"
        assert result.found_via == ["DIRECT"]

        mock_registry.is_seen.assert_called_once()
        mock_registry.register_other.assert_called_once()
        mock_collect_tool_info.assert_called_once_with(path, "pip", subtype, mock_fs)

    def test_detect_tool_already_seen(self, detector: ToolDetector):
        """Test detection when tool already seen in registry."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_registry.is_seen.return_value = True

        path = Path("/usr/bin/pip")
        result = detector._detect_tool(
            path=path,
            subtype="package_manager:pip",
            fs=mock_fs,
            exec_context_ref=mock_exec_ctx_rel,
            scan_registry=mock_registry,
        )

        assert result is None
        mock_registry.register_other.assert_not_called()

    @patch("safety.system_scan.scanner.detectors.tools.main.collect_tool_info")
    def test_detect_tool_collect_fails(
        self, mock_collect_tool_info, detector: ToolDetector
    ):
        """Test detection when tool info collection fails."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_registry.is_seen.return_value = False
        mock_collect_tool_info.return_value = None

        path = Path("/usr/bin/pip")
        result = detector._detect_tool(
            path=path,
            subtype="package_manager:pip",
            fs=mock_fs,
            exec_context_ref=mock_exec_ctx_rel,
            scan_registry=mock_registry,
        )

        assert result is None
        mock_registry.register_other.assert_not_called()

    @patch("safety.system_scan.scanner.detectors.tools.main.collect_tool_info")
    def test_detect_tool_with_aliases(
        self, mock_collect_tool_info, detector: ToolDetector
    ):
        """Test detection with aliases."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_registry.is_seen.return_value = False
        mock_tool_info = Mock()
        mock_collect_tool_info.return_value = mock_tool_info

        path = Path("/usr/bin/pip")
        aliases = ["pip3", "pip3.9"]

        result = detector._detect_tool(
            path=path,
            subtype="package_manager:pip",
            fs=mock_fs,
            exec_context_ref=mock_exec_ctx_rel,
            scan_registry=mock_registry,
            aliases=aliases,
        )

        assert result is not None
        assert mock_tool_info.aliases == aliases


@pytest.mark.unit
class TestDetect:
    """Test detect method."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        return ToolDetector()

    def test_detect_valid_candidate(self, detector: ToolDetector):
        """Test detecting valid candidate."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        ctx = Mock(spec=DetectContext)
        ctx.fs = mock_fs
        ctx.registry = mock_registry
        ctx.exec_ctx_rel = mock_exec_ctx_rel

        # Mock _validate to return a subtype
        detector._validate = Mock(return_value="package_manager:pip")

        # Mock _detect_tool to return a detection
        mock_detection = Mock(spec=Detection)
        detector._detect_tool = Mock(return_value=mock_detection)

        candidate = Candidate(path=Path("/usr/bin/pip"), source="TEST", hint="tool")

        results = list(detector.detect(candidate, ctx))

        assert len(results) == 1
        assert results[0] == mock_detection

    def test_detect_invalid_candidate(self, detector: ToolDetector):
        """Test detecting invalid candidate."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        ctx = Mock(spec=DetectContext)
        ctx.fs = mock_fs
        ctx.registry = mock_registry
        ctx.exec_ctx_rel = mock_exec_ctx_rel

        # Mock _validate to return None (invalid)
        detector._validate = Mock(return_value=None)
        detector._detect_tool = Mock()  # Mock this too

        candidate = Candidate(path=Path("/usr/bin/unknown"), source="TEST", hint="tool")

        results = list(detector.detect(candidate, ctx))

        assert len(results) == 0
        detector._detect_tool.assert_not_called()

    def test_detect_tool_collection_fails(self, detector: ToolDetector):
        """Test detecting when tool detection fails."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        ctx = Mock(spec=DetectContext)
        ctx.fs = mock_fs
        ctx.registry = mock_registry
        ctx.exec_ctx_rel = mock_exec_ctx_rel

        detector._validate = Mock(return_value="package_manager:pip")
        detector._detect_tool = Mock(return_value=None)  # Detection fails

        candidate = Candidate(path=Path("/usr/bin/pip"), source="TEST", hint="tool")

        results = list(detector.detect(candidate, ctx))

        assert len(results) == 0


@pytest.mark.unit
class TestScanDirectory:
    """Test scan_directory method."""

    @pytest.fixture
    def detector(self) -> ToolDetector:
        return ToolDetector()

    def test_scan_directory_not_exists(self, detector: ToolDetector):
        """Test scanning non-existent directory."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_fs.is_dir.return_value = False

        results = list(
            detector.scan_directory(
                directory_path=Path("/nonexistent"),
                fs=mock_fs,
                exec_context_ref=mock_exec_ctx_rel,
                scan_registry=mock_registry,
            )
        )

        assert len(results) == 0

    @patch("os.scandir")
    def test_scan_directory_with_tools(self, mock_scandir, detector: ToolDetector):
        """Test scanning directory with tools."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_fs.is_dir.return_value = True

        # Mock directory entries
        mock_entry1 = Mock()
        mock_entry1.is_file.return_value = True
        mock_entry1.path = "/usr/bin/pip"
        mock_entry1.stat.return_value = Mock(st_size=1024)

        mock_entry2 = Mock()
        mock_entry2.is_file.return_value = True
        mock_entry2.path = "/usr/bin/pip3"
        mock_entry2.stat.return_value = Mock(st_size=1024)  # Same size

        mock_entry3 = Mock()
        mock_entry3.is_file.return_value = False  # Not a file

        mock_scandir.return_value.__enter__.return_value = [
            mock_entry1,
            mock_entry2,
            mock_entry3,
        ]

        # Mock _validate to recognize pip tools
        def mock_validate(path, fs):
            if "pip" in str(path):
                return "package_manager:pip"
            return None

        detector._validate = Mock(side_effect=mock_validate)

        # Mock _detect_tool to return detection
        mock_detection = Mock(spec=Detection)
        detector._detect_tool = Mock(return_value=mock_detection)

        results = list(
            detector.scan_directory(
                directory_path=Path("/usr/bin"),
                fs=mock_fs,
                exec_context_ref=mock_exec_ctx_rel,
                scan_registry=mock_registry,
            )
        )

        assert len(results) == 1  # Should group tools by signature
        detector._detect_tool.assert_called_once()

    @patch("os.scandir")
    def test_scan_directory_os_error(self, mock_scandir, detector: ToolDetector):
        """Test scanning directory with OS error."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_fs.is_dir.return_value = True
        mock_scandir.side_effect = OSError("Permission denied")

        results = list(
            detector.scan_directory(
                directory_path=Path("/usr/bin"),
                fs=mock_fs,
                exec_context_ref=mock_exec_ctx_rel,
                scan_registry=mock_registry,
            )
        )

        assert len(results) == 0

    @patch("os.scandir")
    def test_scan_directory_stat_error_continues(
        self, mock_scandir, detector: ToolDetector
    ):
        """Test scanning directory continues when stat fails on individual files."""
        mock_fs = Mock(spec=FsRuntime)
        mock_registry = Mock(spec=ScanRefRegistry)
        mock_exec_ctx_rel = Mock(spec=ExecutionContextRelation)

        mock_fs.is_dir.return_value = True

        # Mock entry that fails stat
        mock_entry1 = Mock()
        mock_entry1.is_file.return_value = True
        mock_entry1.path = "/usr/bin/pip"
        mock_entry1.stat.side_effect = OSError("Permission denied")

        # Mock entry that succeeds
        mock_entry2 = Mock()
        mock_entry2.is_file.return_value = True
        mock_entry2.path = "/usr/bin/poetry"
        mock_entry2.stat.return_value = Mock(st_size=2048)

        mock_scandir.return_value.__enter__.return_value = [mock_entry1, mock_entry2]

        def mock_validate(path, fs):
            if "pip" in str(path) or "poetry" in str(path):
                return (
                    "package_manager:pip"
                    if "pip" in str(path)
                    else "package_manager:poetry"
                )
            return None

        detector._validate = Mock(side_effect=mock_validate)
        mock_detection = Mock(spec=Detection)
        detector._detect_tool = Mock(return_value=mock_detection)

        results = list(
            detector.scan_directory(
                directory_path=Path("/usr/bin"),
                fs=mock_fs,
                exec_context_ref=mock_exec_ctx_rel,
                scan_registry=mock_registry,
            )
        )

        # Should only process the entry that didn't fail stat
        assert len(results) == 1
        detector._detect_tool.assert_called_once()
