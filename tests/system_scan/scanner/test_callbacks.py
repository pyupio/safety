from __future__ import annotations

import pytest
from unittest.mock import Mock

from safety.system_scan.scanner.callbacks import ScanSummary, Callbacks, NullCallbacks
from safety.system_scan.scanner.models import Detection


@pytest.mark.unit
class TestScanSummary:
    """
    Test ScanSummary dataclass.
    """

    def test_scan_summary_creation(self) -> None:
        """
        Test ScanSummary can be created with total_detections.
        """
        summary = ScanSummary(total_detections=42)

        assert summary.total_detections == 42

    def test_scan_summary_zero_detections(self) -> None:
        """
        Test ScanSummary works with zero detections.
        """
        summary = ScanSummary(total_detections=0)

        assert summary.total_detections == 0


@pytest.mark.unit
class TestNullCallbacks:
    """
    Test NullCallbacks implementation.
    """

    @pytest.fixture
    def callbacks(self) -> NullCallbacks:
        """
        Fixture for NullCallbacks instance.
        """
        return NullCallbacks()

    def test_phase_does_nothing(self, callbacks: NullCallbacks) -> None:
        """
        Test phase method executes without error.
        """
        callbacks.phase("test_phase")
        # No assertion needed - just verify it doesn't raise

    def test_scan_id_does_nothing(self, callbacks: NullCallbacks) -> None:
        """
        Test scan_id method executes without error.
        """
        callbacks.scan_id("scan-123")
        # No assertion needed - just verify it doesn't raise

    def test_detection_does_nothing(self, callbacks: NullCallbacks) -> None:
        """
        Test detection method executes without error.
        """
        mock_detection = Mock(spec=Detection)
        callbacks.detection(mock_detection)
        # No assertion needed - just verify it doesn't raise

    def test_warning_does_nothing(self, callbacks: NullCallbacks) -> None:
        """
        Test warning method executes without error.
        """
        callbacks.warning("test warning", "/test/path")
        # No assertion needed - just verify it doesn't raise

    def test_warning_without_path(self, callbacks: NullCallbacks) -> None:
        """
        Test warning method with default path parameter.
        """
        callbacks.warning("test warning")
        # No assertion needed - just verify it doesn't raise

    def test_error_does_nothing(self, callbacks: NullCallbacks) -> None:
        """
        Test error method executes without error.
        """
        exception = ValueError("test error")
        callbacks.error("test message", exception)
        # No assertion needed - just verify it doesn't raise

    def test_progress_does_nothing(self, callbacks: NullCallbacks) -> None:
        """
        Test progress method executes without error.
        """
        callbacks.progress(5, 10)
        # No assertion needed - just verify it doesn't raise

    def test_complete_does_nothing(self, callbacks: NullCallbacks) -> None:
        """
        Test complete method executes without error.
        """
        summary = ScanSummary(total_detections=3)
        callbacks.complete(summary)
        # No assertion needed - just verify it doesn't raise


@pytest.mark.unit
class TestCallbacksProtocol:
    """
    Test that classes implementing Callbacks protocol work correctly.
    """

    def test_null_callbacks_implements_protocol(self) -> None:
        """
        Test NullCallbacks implements Callbacks protocol.
        """
        callbacks: Callbacks = NullCallbacks()

        # Test that all protocol methods are callable
        assert callable(callbacks.phase)
        assert callable(callbacks.scan_id)
        assert callable(callbacks.detection)
        assert callable(callbacks.warning)
        assert callable(callbacks.error)
        assert callable(callbacks.progress)
        assert callable(callbacks.complete)
