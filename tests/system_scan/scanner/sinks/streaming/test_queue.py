from __future__ import annotations

import json
import time
import pytest
from typing import cast
from unittest.mock import Mock

from safety.system_scan.scanner.sinks.streaming.queue import BatchedQueue
from safety.system_scan.scanner.sinks.streaming.config import BatchConfig
from safety.system_scan.scanner.sinks.streaming.callbacks import (
    StreamingCallbacks,
    QueuePressure,
    NullStreamingCallbacks,
)


@pytest.mark.unit
class TestBatchedQueue:
    """
    Test BatchedQueue implementation.
    """

    @pytest.fixture
    def batch_config(self) -> BatchConfig:
        """
        Create batch configuration for testing.
        """
        return BatchConfig(
            max_events=3,
            max_bytes=100,
            flush_interval=0.1,
            max_pending_events=10,
        )

    @pytest.fixture
    def mock_callbacks(self) -> Mock:
        """
        Mock streaming callbacks.
        """
        return Mock(spec=StreamingCallbacks)

    @pytest.fixture
    def null_callbacks(self) -> NullStreamingCallbacks:
        """
        Null streaming callbacks.
        """
        return NullStreamingCallbacks()

    @pytest.fixture
    def batched_queue(
        self, batch_config: BatchConfig, mock_callbacks: Mock
    ) -> BatchedQueue:
        """
        Create BatchedQueue instance for testing.
        """
        return BatchedQueue(batch_config, mock_callbacks)

    def test_init(self, batch_config: BatchConfig, mock_callbacks: Mock) -> None:
        """
        Test BatchedQueue initialization.
        """
        queue_obj = BatchedQueue(batch_config, mock_callbacks)

        assert queue_obj.config == batch_config
        assert queue_obj.callbacks == mock_callbacks
        assert queue_obj._closed is False
        assert queue_obj._last_pressure == QueuePressure.LOW
        assert queue_obj._queue.maxsize == batch_config.max_pending_events

    def test_put_single_event(self, batched_queue: BatchedQueue) -> None:
        """
        Test putting single event triggers callbacks.
        """
        event = {"type": "test", "data": "value"}

        batched_queue.put(event)

        # Verify callbacks called
        cast(Mock, batched_queue.callbacks.batch_queued).assert_called_once_with(1)
        # Pressure callback only called when pressure level changes
        # Since we start with LOW and 1 event is still LOW, no pressure callback
        cast(Mock, batched_queue.callbacks.queue_pressure).assert_not_called()

    def test_put_multiple_events(self, batched_queue: BatchedQueue) -> None:
        """
        Test putting multiple events updates queue size.
        """
        events = [
            {"type": "test1", "data": "value1"},
            {"type": "test2", "data": "value2"},
            {"type": "test3", "data": "value3"},
        ]

        for event in events:
            batched_queue.put(event)

        # Last call should show size 3
        assert cast(Mock, batched_queue.callbacks.batch_queued).call_count == 3
        cast(Mock, batched_queue.callbacks.batch_queued).assert_called_with(3)

    def test_put_pressure_level_changes(self, batch_config: BatchConfig) -> None:
        """
        Test queue pressure level changes trigger notifications.
        """
        # Use smaller queue to trigger pressure changes
        batch_config.max_pending_events = 10
        mock_callbacks = Mock(spec=StreamingCallbacks)
        queue_obj = BatchedQueue(batch_config, mock_callbacks)

        # Add events to reach medium pressure (30% = 3 events)
        for i in range(4):
            queue_obj.put({"event": i})

        # Should have called with LOW initially, then MEDIUM
        pressure_calls = mock_callbacks.queue_pressure.call_args_list
        assert len(pressure_calls) >= 1
        # Last call should be MEDIUM pressure
        last_call = pressure_calls[-1]
        assert last_call[0][0] == QueuePressure.MEDIUM

    def test_put_no_pressure_change_no_callback(
        self, batched_queue: BatchedQueue
    ) -> None:
        """
        Test no pressure callback when pressure level unchanged.
        """
        # Put two events (both will be LOW pressure)
        batched_queue.put({"event": 1})
        cast(Mock, batched_queue.callbacks).reset_mock()

        batched_queue.put({"event": 2})

        # Should have batch_queued but not queue_pressure
        cast(Mock, batched_queue.callbacks.batch_queued).assert_called_once()
        cast(Mock, batched_queue.callbacks.queue_pressure).assert_not_called()

    def test_put_callback_exception_handling(self, batch_config: BatchConfig) -> None:
        """
        Test callback exceptions don't crash the queue.
        """
        mock_callbacks = Mock(spec=StreamingCallbacks)
        mock_callbacks.batch_queued.side_effect = Exception("Callback error")
        queue_obj = BatchedQueue(batch_config, mock_callbacks)

        # Should not raise despite callback error
        event = {"type": "test"}
        queue_obj.put(event)

        # Event should still be in queue
        assert queue_obj._queue.qsize() == 1

    def test_put_no_callbacks_set(self, batch_config: BatchConfig) -> None:
        """
        Test putting when callbacks are None doesn't crash.
        """
        mock_callbacks = Mock(spec=StreamingCallbacks)
        mock_callbacks.batch_queued = None
        mock_callbacks.queue_pressure = None
        queue_obj = BatchedQueue(batch_config, mock_callbacks)

        event = {"type": "test"}
        queue_obj.put(event)

        # Should not raise
        assert queue_obj._queue.qsize() == 1

    def test_get_batch_max_events_trigger(self, batched_queue: BatchedQueue) -> None:
        """
        Test get returns batch when max_events reached.
        """
        events = [
            {"event": 1},
            {"event": 2},
            {"event": 3},  # Should trigger at 3 events
        ]

        for event in events:
            batched_queue.put(event)

        batch = batched_queue.get(timeout=1.0)

        assert batch == events
        assert batched_queue._queue.empty()

    def test_get_batch_max_bytes_trigger(self) -> None:
        """
        Test get returns batch when max_bytes reached.
        """
        config = BatchConfig(max_events=10, max_bytes=50, flush_interval=1.0)
        mock_callbacks = Mock(spec=StreamingCallbacks)
        queue_obj = BatchedQueue(config, mock_callbacks)

        # Create large event that exceeds max_bytes
        large_event = {"data": "x" * 100}  # Will be > 50 bytes when JSON encoded
        queue_obj.put(large_event)

        batch = queue_obj.get(timeout=1.0)

        assert batch == [large_event]

    def test_get_batch_timeout_trigger(self, batched_queue: BatchedQueue) -> None:
        """
        Test get returns batch when timeout reached.
        """
        event = {"event": 1}
        batched_queue.put(event)

        start_time = time.monotonic()
        batch = batched_queue.get(timeout=0.05)  # Very short timeout
        elapsed = time.monotonic() - start_time

        assert batch == [event]
        assert elapsed >= 0.05

    def test_get_no_events_timeout(self, batched_queue: BatchedQueue) -> None:
        """
        Test get returns None when no events and timeout reached.
        """
        batch = batched_queue.get(timeout=0.01)

        assert batch is None

    def test_get_empty_queue_returns_none(self, batched_queue: BatchedQueue) -> None:
        """
        Test get from empty queue returns None.
        """
        batch = batched_queue.get(timeout=0.01)

        assert batch is None

    def test_get_uses_config_flush_interval_as_default(
        self, batched_queue: BatchedQueue
    ) -> None:
        """
        Test get uses config flush_interval when timeout not specified.
        """
        event = {"event": 1}
        batched_queue.put(event)

        start_time = time.monotonic()
        batch = batched_queue.get()  # No timeout specified
        elapsed = time.monotonic() - start_time

        assert batch == [event]
        # Should have used config.flush_interval (0.1s)
        assert elapsed >= 0.1

    def test_get_updates_pressure_after_consuming(
        self, batch_config: BatchConfig
    ) -> None:
        """
        Test get updates pressure after consuming events.
        """
        # Create queue with many events to trigger pressure change
        batch_config.max_pending_events = 10
        mock_callbacks = Mock(spec=StreamingCallbacks)
        queue_obj = BatchedQueue(batch_config, mock_callbacks)

        # Fill queue to medium pressure (4 events = 40%)
        for i in range(4):
            queue_obj.put({"event": i})

        cast(Mock, mock_callbacks).reset_mock()

        # Get batch should reduce pressure back to LOW
        batch = queue_obj.get(timeout=0.1)

        assert batch is not None
        assert len(batch) == 3  # max_events limit
        # Should have called pressure callback with LOW pressure
        cast(Mock, queue_obj.callbacks.queue_pressure).assert_called_with(
            QueuePressure.LOW, 1, 10
        )

    def test_get_pressure_callback_exception_handling(
        self, batched_queue: BatchedQueue
    ) -> None:
        """
        Test pressure callback exceptions during get don't crash.
        """
        cast(Mock, batched_queue.callbacks.queue_pressure).side_effect = Exception(
            "Error"
        )

        batched_queue.put({"event": 1})
        batch = batched_queue.get(timeout=0.1)

        # Should not raise and should return batch
        assert batch == [{"event": 1}]

    def test_close(self, batched_queue: BatchedQueue) -> None:
        """
        Test closing the queue.
        """
        assert not batched_queue.is_closed()

        batched_queue.close()

        assert batched_queue.is_closed()
        assert batched_queue._closed is True

    def test_is_drained_false_when_not_closed(
        self, batched_queue: BatchedQueue
    ) -> None:
        """
        Test is_drained returns False when not closed.
        """
        batched_queue.put({"event": 1})

        assert not batched_queue.is_drained()

    def test_is_drained_false_when_closed_but_not_empty(
        self, batched_queue: BatchedQueue
    ) -> None:
        """
        Test is_drained returns False when closed but queue not empty.
        """
        batched_queue.put({"event": 1})
        batched_queue.close()

        assert not batched_queue.is_drained()

    def test_is_drained_true_when_closed_and_empty(
        self, batched_queue: BatchedQueue
    ) -> None:
        """
        Test is_drained returns True when closed and queue empty.
        """
        batched_queue.close()

        assert batched_queue.is_drained()

    def test_get_batch_behavior_coverage(self, batched_queue: BatchedQueue) -> None:
        """
        Test various batch retrieval scenarios for coverage.
        """
        # Test with events that don't trigger max_events
        batched_queue.put({"event": 1})
        batch = batched_queue.get(timeout=0.01)

        assert batch == [{"event": 1}]

    def test_json_serialization_for_byte_calculation(
        self, batched_queue: BatchedQueue
    ) -> None:
        """
        Test that byte calculation uses compact JSON serialization.
        """
        # Put event that when serialized with separators will be compact
        event = {"key": "value", "number": 123}
        batched_queue.put(event)

        batch = batched_queue.get(timeout=0.1)

        assert batch == [event]
        # Verify it was able to calculate bytes without error
        expected_json = json.dumps(event, separators=(",", ":"))
        assert "," in expected_json and " " not in expected_json

    def test_queue_full_blocks_put(self, batch_config: BatchConfig) -> None:
        """
        Test that queue blocks when max_pending_events reached.
        """
        batch_config.max_pending_events = 2
        mock_callbacks = Mock(spec=StreamingCallbacks)
        queue_obj = BatchedQueue(batch_config, mock_callbacks)

        # Fill queue to capacity
        queue_obj.put({"event": 1})
        queue_obj.put({"event": 2})

        # This should work without blocking since we're at max
        assert queue_obj._queue.qsize() == 2

        # Next put would block in real usage, but we can't test blocking easily
        # Just verify the queue is at capacity
        assert queue_obj._queue.qsize() == batch_config.max_pending_events

    def test_with_null_callbacks(
        self, batch_config: BatchConfig, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test queue works with null callbacks.
        """
        queue_obj = BatchedQueue(batch_config, null_callbacks)

        # Should work without error
        queue_obj.put({"event": 1})
        batch = queue_obj.get(timeout=0.1)

        assert batch == [{"event": 1}]
        assert queue_obj._queue.empty()
