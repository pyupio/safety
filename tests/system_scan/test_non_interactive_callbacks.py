from __future__ import annotations

import pytest
from datetime import datetime
from unittest.mock import Mock

from safety.system_scan.callbacks import NonInteractiveCallbacks
from safety.system_scan.scanner.callbacks import ScanSummary
from safety.system_scan.ui.state import ScanState


@pytest.mark.unit
class TestNonInteractiveCallbacks:
    """Test NonInteractiveCallbacks functionality."""

    def test_initialization(self):
        """Test callback initialization with state."""
        state = ScanState()
        callbacks = NonInteractiveCallbacks(state=state)

        assert callbacks.state is state

    def test_scan_id_capture(self):
        """Test scan ID is captured in state."""
        state = ScanState()
        callbacks = NonInteractiveCallbacks(state=state)
        test_scan_id = "test-scan-123"

        callbacks.scan_id(test_scan_id)

        assert state.scan_id == test_scan_id

    def test_detection_increments_counters(self):
        """Test detection increments appropriate counters."""
        state = ScanState()
        callbacks = NonInteractiveCallbacks(state=state)

        # Mock detection with context kind
        mock_detection = Mock()
        mock_detection.kind.value = "execution_context"

        initial_contexts = state.contexts
        callbacks.detection(mock_detection)

        # Verify counter was incremented
        assert state.contexts == initial_contexts + 1

    def test_complete_marks_scan_complete(self):
        """Test completion marks state as completed."""
        state = ScanState(start_time=datetime.now())
        callbacks = NonInteractiveCallbacks(state=state)

        summary = ScanSummary(total_detections=42)
        callbacks.complete(summary)

        assert state.is_completed is True
        assert state.completion_time is not None
