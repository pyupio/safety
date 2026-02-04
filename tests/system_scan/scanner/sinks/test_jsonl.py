from __future__ import annotations

import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from safety.system_scan.scanner.sinks.jsonl import JsonlSink
from safety.system_scan.scanner.models import Detection


@pytest.mark.unit
class TestJsonlSink:
    """
    Test JsonlSink implementation.
    """

    @pytest.fixture
    def temp_dir(self):
        """
        Create temporary directory for testing.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            yield Path(tmp_dir)

    @pytest.fixture
    def mock_detection(self) -> Mock:
        """
        Mock detection with payload.
        """
        detection = Mock(spec=Detection)
        detection.get_payload.return_value = {
            "type": "dependency",
            "name": "test-package",
            "version": "1.0.0",
        }
        return detection

    def test_sink_name(self) -> None:
        """
        Test sink has correct name.
        """
        sink = JsonlSink(Path("/test/path"))

        assert sink.name == "jsonl"

    def test_init_with_path(self) -> None:
        """
        Test sink initialization with path.
        """
        path = Path("/test/output.jsonl")
        sink = JsonlSink(path)

        assert sink.path == path
        assert sink._fp is None

    @patch("safety.system_scan.scanner.sinks.jsonl.datetime")
    def test_open_with_file_path(self, mock_datetime: Mock, temp_dir: Path) -> None:
        """
        Test opening sink with file path.
        """
        # Mock datetime.now() to return fixed timestamp
        mock_now = Mock()
        mock_now.timestamp.return_value = 1640995200  # 2022-01-01 00:00:00
        mock_datetime.now.return_value = mock_now

        file_path = temp_dir / "output.jsonl"
        sink = JsonlSink(file_path)

        scan_id = sink.open("machine-123", "hostname-test")

        assert scan_id == "offline-scan-1640995200"
        assert sink._fp is not None
        assert file_path.exists()

        # Clean up
        sink.close(True)

    @patch("safety.system_scan.scanner.sinks.jsonl.datetime")
    def test_open_with_directory_path(
        self, mock_datetime: Mock, temp_dir: Path
    ) -> None:
        """
        Test opening sink with directory path.
        """
        # Mock datetime.now() to return fixed timestamp
        mock_now = Mock()
        mock_now.timestamp.return_value = 1640995200
        mock_datetime.now.return_value = mock_now

        sink = JsonlSink(temp_dir)

        scan_id = sink.open("machine-456", "hostname-prod")

        assert scan_id == "offline-scan-1640995200"
        assert sink._fp is not None
        expected_file = temp_dir / "offline-scan-1640995200.jsonl"
        assert expected_file.exists()

        # Clean up
        sink.close(True)

    def test_write_detection(self, mock_detection: Mock, temp_dir: Path) -> None:
        """
        Test writing detection to JSONL file.
        """
        file_path = temp_dir / "test.jsonl"
        sink = JsonlSink(file_path)

        sink.open("machine-789", "hostname-dev")
        sink.write(mock_detection)
        sink.close(True)

        # Read and verify content
        with open(file_path, "r", encoding="utf-8") as f:
            line = f.readline().strip()
            data = json.loads(line)

        assert data == {
            "type": "dependency",
            "name": "test-package",
            "version": "1.0.0",
        }
        mock_detection.get_payload.assert_called_once()

    def test_write_multiple_detections(self, temp_dir: Path) -> None:
        """
        Test writing multiple detections creates multiple JSONL lines.
        """
        file_path = temp_dir / "multiple.jsonl"
        sink = JsonlSink(file_path)

        # Create multiple mock detections
        detection1 = Mock(spec=Detection)
        detection1.get_payload.return_value = {"id": 1, "name": "pkg1"}

        detection2 = Mock(spec=Detection)
        detection2.get_payload.return_value = {"id": 2, "name": "pkg2"}

        sink.open("machine-001", "test-host")
        sink.write(detection1)
        sink.write(detection2)
        sink.close(True)

        # Verify both lines written
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) == 2
        assert json.loads(lines[0].strip()) == {"id": 1, "name": "pkg1"}
        assert json.loads(lines[1].strip()) == {"id": 2, "name": "pkg2"}

    def test_write_without_open_raises_assertion(self, mock_detection: Mock) -> None:
        """
        Test writing without opening sink raises AssertionError.
        """
        sink = JsonlSink(Path("/test/path"))

        with pytest.raises(AssertionError):
            sink.write(mock_detection)

    def test_close_with_ok_true(self, temp_dir: Path) -> None:
        """
        Test closing sink with ok=True.
        """
        file_path = temp_dir / "close_test.jsonl"
        sink = JsonlSink(file_path)

        sink.open("machine-close", "hostname-close")
        assert sink._fp is not None

        sink.close(True)
        assert sink._fp is None

    def test_close_with_ok_false(self, temp_dir: Path) -> None:
        """
        Test closing sink with ok=False.
        """
        file_path = temp_dir / "close_false.jsonl"
        sink = JsonlSink(file_path)

        sink.open("machine-error", "hostname-error")
        assert sink._fp is not None

        sink.close(False)
        assert sink._fp is None

    def test_close_when_not_opened(self) -> None:
        """
        Test closing sink when not opened does nothing.
        """
        sink = JsonlSink(Path("/test/path"))

        # Should not raise
        sink.close(True)
        assert sink._fp is None

    def test_close_already_closed(self, temp_dir: Path) -> None:
        """
        Test closing already closed sink does nothing.
        """
        file_path = temp_dir / "double_close.jsonl"
        sink = JsonlSink(file_path)

        sink.open("machine-double", "hostname-double")
        sink.close(True)

        # Second close should not raise
        sink.close(True)
        assert sink._fp is None

    def test_json_serialization_compact(self, temp_dir: Path) -> None:
        """
        Test JSON is serialized in compact format.
        """
        file_path = temp_dir / "compact.jsonl"
        sink = JsonlSink(file_path)

        detection = Mock(spec=Detection)
        detection.get_payload.return_value = {"key1": "value1", "key2": "value2"}

        sink.open("machine-compact", "hostname-compact")
        sink.write(detection)
        sink.close(True)

        # Verify compact JSON (no spaces after separators)
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        assert content == '{"key1":"value1","key2":"value2"}'
        assert " : " not in content  # No spaces around colons
        assert " , " not in content  # No spaces around commas

    @patch("safety.system_scan.scanner.sinks.jsonl.open")
    def test_file_encoding_utf8(self, mock_file_open: Mock) -> None:
        """
        Test file is opened with UTF-8 encoding.
        """
        mock_fp = Mock()
        mock_file_open.return_value = mock_fp

        sink = JsonlSink(Path("/test/encoding.jsonl"))
        sink.open("machine-utf8", "hostname-utf8")

        mock_file_open.assert_called_once_with(
            Path("/test/encoding.jsonl"), "a", encoding="utf-8"
        )
