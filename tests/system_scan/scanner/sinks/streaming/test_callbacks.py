from __future__ import annotations

import pytest

from safety.system_scan.scanner.sinks.streaming.callbacks import (
    StreamingStatus,
    QueuePressure,
    StreamingSummary,
    StreamingCallbacks,
    NullStreamingCallbacks,
    calculate_queue_pressure,
)


@pytest.mark.unit
class TestStreamingStatus:
    """
    Test StreamingStatus enum.
    """

    def test_streaming_status_values(self) -> None:
        """
        Test StreamingStatus enum values.
        """
        assert StreamingStatus.CONNECTING.value == "connecting"
        assert StreamingStatus.STREAMING.value == "streaming"
        assert StreamingStatus.RECONNECTING.value == "reconnecting"
        assert StreamingStatus.DISCONNECTED.value == "disconnected"
        assert StreamingStatus.COMPLETE.value == "complete"

    def test_streaming_status_members(self) -> None:
        """
        Test StreamingStatus has expected members.
        """
        expected_members = {
            "CONNECTING",
            "STREAMING",
            "RECONNECTING",
            "DISCONNECTED",
            "COMPLETE",
        }
        actual_members = set(StreamingStatus.__members__.keys())
        assert actual_members == expected_members

    def test_streaming_status_equality(self) -> None:
        """
        Test StreamingStatus enum equality.
        """
        assert StreamingStatus.CONNECTING == StreamingStatus.CONNECTING
        assert StreamingStatus.STREAMING != StreamingStatus.CONNECTING


@pytest.mark.unit
class TestQueuePressure:
    """
    Test QueuePressure enum.
    """

    def test_queue_pressure_values(self) -> None:
        """
        Test QueuePressure enum values.
        """
        assert QueuePressure.LOW.value == "low"
        assert QueuePressure.MEDIUM.value == "medium"
        assert QueuePressure.HIGH.value == "high"
        assert QueuePressure.CRITICAL.value == "critical"

    def test_queue_pressure_members(self) -> None:
        """
        Test QueuePressure has expected members.
        """
        expected_members = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        actual_members = set(QueuePressure.__members__.keys())
        assert actual_members == expected_members

    def test_queue_pressure_ordering(self) -> None:
        """
        Test QueuePressure enum can be compared.
        """
        assert QueuePressure.LOW == QueuePressure.LOW
        assert QueuePressure.MEDIUM != QueuePressure.LOW


@pytest.mark.unit
class TestStreamingSummary:
    """
    Test StreamingSummary dataclass.
    """

    def test_streaming_summary_creation(self) -> None:
        """
        Test StreamingSummary creation with required fields.
        """
        summary = StreamingSummary(
            total_batches_sent=10,
            total_events_sent=150,
            connection_duration_seconds=45.5,
        )

        assert summary.total_batches_sent == 10
        assert summary.total_events_sent == 150
        assert summary.connection_duration_seconds == 45.5
        assert summary.reconnection_count == 0  # default
        assert summary.errors == 0  # default
        assert summary.queue_pressure_events == 0  # default

    def test_streaming_summary_with_optional_fields(self) -> None:
        """
        Test StreamingSummary creation with optional fields.
        """
        summary = StreamingSummary(
            total_batches_sent=25,
            total_events_sent=500,
            connection_duration_seconds=120.0,
            reconnection_count=3,
            errors=2,
            queue_pressure_events=15,
        )

        assert summary.total_batches_sent == 25
        assert summary.total_events_sent == 500
        assert summary.connection_duration_seconds == 120.0
        assert summary.reconnection_count == 3
        assert summary.errors == 2
        assert summary.queue_pressure_events == 15

    def test_streaming_summary_equality(self) -> None:
        """
        Test StreamingSummary equality comparison.
        """
        summary1 = StreamingSummary(
            total_batches_sent=5,
            total_events_sent=100,
            connection_duration_seconds=30.0,
        )

        summary2 = StreamingSummary(
            total_batches_sent=5,
            total_events_sent=100,
            connection_duration_seconds=30.0,
        )

        summary3 = StreamingSummary(
            total_batches_sent=10,
            total_events_sent=100,
            connection_duration_seconds=30.0,
        )

        assert summary1 == summary2
        assert summary1 != summary3

    def test_streaming_summary_repr(self) -> None:
        """
        Test StreamingSummary string representation.
        """
        summary = StreamingSummary(
            total_batches_sent=1,
            total_events_sent=25,
            connection_duration_seconds=10.5,
        )

        repr_str = repr(summary)
        assert "StreamingSummary" in repr_str
        assert "total_batches_sent=1" in repr_str
        assert "total_events_sent=25" in repr_str
        assert "connection_duration_seconds=10.5" in repr_str


@pytest.mark.unit
class TestNullStreamingCallbacks:
    """
    Test NullStreamingCallbacks implementation.
    """

    @pytest.fixture
    def null_callbacks(self) -> NullStreamingCallbacks:
        """
        Create NullStreamingCallbacks instance.
        """
        return NullStreamingCallbacks()

    def test_batch_sent_does_nothing(
        self, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test batch_sent callback does nothing.
        """
        # Should not raise
        null_callbacks.batch_sent(10)
        null_callbacks.batch_sent(0)
        null_callbacks.batch_sent(-1)

    def test_batch_queued_does_nothing(
        self, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test batch_queued callback does nothing.
        """
        # Should not raise
        null_callbacks.batch_queued(50)
        null_callbacks.batch_queued(0)

    def test_connection_change_does_nothing(
        self, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test connection_change callback does nothing.
        """
        # Should not raise
        null_callbacks.connection_change(StreamingStatus.CONNECTING)
        null_callbacks.connection_change(StreamingStatus.STREAMING)
        null_callbacks.connection_change(StreamingStatus.COMPLETE)

    def test_error_does_nothing(self, null_callbacks: NullStreamingCallbacks) -> None:
        """
        Test error callback does nothing.
        """
        exc = ValueError("Test error")

        # Should not raise
        null_callbacks.error("Error message", exc)
        null_callbacks.error("", exc)

    def test_queue_pressure_does_nothing(
        self, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test queue_pressure callback does nothing.
        """
        # Should not raise
        null_callbacks.queue_pressure(QueuePressure.LOW, 10, 100)
        null_callbacks.queue_pressure(QueuePressure.CRITICAL, 95, 100)

    def test_complete_does_nothing(
        self, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test complete callback does nothing.
        """
        summary = StreamingSummary(
            total_batches_sent=5,
            total_events_sent=100,
            connection_duration_seconds=30.0,
        )

        # Should not raise
        null_callbacks.complete(summary)

    def test_null_callbacks_implements_protocol(
        self, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test NullStreamingCallbacks can be used as StreamingCallbacks.
        """

        def accepts_callbacks(callbacks: StreamingCallbacks) -> None:
            callbacks.batch_sent(1)

        # Should not raise type error
        accepts_callbacks(null_callbacks)

    def test_null_callbacks_all_methods_callable(
        self, null_callbacks: NullStreamingCallbacks
    ) -> None:
        """
        Test all callback methods are callable without errors.
        """
        # Call all methods to ensure they exist and are callable
        null_callbacks.batch_sent(42)
        null_callbacks.batch_queued(15)
        null_callbacks.connection_change(StreamingStatus.RECONNECTING)
        null_callbacks.error("test", RuntimeError())
        null_callbacks.queue_pressure(QueuePressure.MEDIUM, 50, 100)

        summary = StreamingSummary(1, 10, 5.0)
        null_callbacks.complete(summary)


@pytest.mark.unit
class TestCalculateQueuePressure:
    """
    Test calculate_queue_pressure function.
    """

    def test_calculate_pressure_zero_max_size(self) -> None:
        """
        Test pressure calculation with zero max size.
        """
        result = calculate_queue_pressure(10, 0)
        assert result == QueuePressure.LOW

    def test_calculate_pressure_low(self) -> None:
        """
        Test pressure calculation for LOW pressure (0-29%).
        """
        # 0%
        result = calculate_queue_pressure(0, 100)
        assert result == QueuePressure.LOW

        # 15%
        result = calculate_queue_pressure(15, 100)
        assert result == QueuePressure.LOW

        # 29%
        result = calculate_queue_pressure(29, 100)
        assert result == QueuePressure.LOW

    def test_calculate_pressure_medium(self) -> None:
        """
        Test pressure calculation for MEDIUM pressure (30-69%).
        """
        # Exactly 30%
        result = calculate_queue_pressure(30, 100)
        assert result == QueuePressure.MEDIUM

        # 50%
        result = calculate_queue_pressure(50, 100)
        assert result == QueuePressure.MEDIUM

        # 69%
        result = calculate_queue_pressure(69, 100)
        assert result == QueuePressure.MEDIUM

    def test_calculate_pressure_high(self) -> None:
        """
        Test pressure calculation for HIGH pressure (70-89%).
        """
        # Exactly 70%
        result = calculate_queue_pressure(70, 100)
        assert result == QueuePressure.HIGH

        # 80%
        result = calculate_queue_pressure(80, 100)
        assert result == QueuePressure.HIGH

        # 89%
        result = calculate_queue_pressure(89, 100)
        assert result == QueuePressure.HIGH

    def test_calculate_pressure_critical(self) -> None:
        """
        Test pressure calculation for CRITICAL pressure (90%+).
        """
        # Exactly 90%
        result = calculate_queue_pressure(90, 100)
        assert result == QueuePressure.CRITICAL

        # 95%
        result = calculate_queue_pressure(95, 100)
        assert result == QueuePressure.CRITICAL

        # 100%
        result = calculate_queue_pressure(100, 100)
        assert result == QueuePressure.CRITICAL

        # Over 100% (edge case)
        result = calculate_queue_pressure(150, 100)
        assert result == QueuePressure.CRITICAL

    def test_calculate_pressure_boundary_conditions(self) -> None:
        """
        Test pressure calculation at boundary conditions.
        """
        # Test 29.9% -> LOW
        result = calculate_queue_pressure(299, 1000)
        assert result == QueuePressure.LOW

        # Test 30.0% -> MEDIUM
        result = calculate_queue_pressure(300, 1000)
        assert result == QueuePressure.MEDIUM

        # Test 69.9% -> MEDIUM
        result = calculate_queue_pressure(699, 1000)
        assert result == QueuePressure.MEDIUM

        # Test 70.0% -> HIGH
        result = calculate_queue_pressure(700, 1000)
        assert result == QueuePressure.HIGH

        # Test 89.9% -> HIGH
        result = calculate_queue_pressure(899, 1000)
        assert result == QueuePressure.HIGH

        # Test 90.0% -> CRITICAL
        result = calculate_queue_pressure(900, 1000)
        assert result == QueuePressure.CRITICAL

    def test_calculate_pressure_small_numbers(self) -> None:
        """
        Test pressure calculation with small queue sizes.
        """
        # 1 out of 3 = 33.33% -> MEDIUM
        result = calculate_queue_pressure(1, 3)
        assert result == QueuePressure.MEDIUM

        # 2 out of 3 = 66.67% -> MEDIUM
        result = calculate_queue_pressure(2, 3)
        assert result == QueuePressure.MEDIUM

        # 3 out of 3 = 100% -> CRITICAL
        result = calculate_queue_pressure(3, 3)
        assert result == QueuePressure.CRITICAL

    def test_calculate_pressure_fractional_results(self) -> None:
        """
        Test pressure calculation with fractional percentages.
        """
        # 7 out of 23 = 30.43% -> MEDIUM
        result = calculate_queue_pressure(7, 23)
        assert result == QueuePressure.MEDIUM

        # 16 out of 23 = 69.57% -> MEDIUM
        result = calculate_queue_pressure(16, 23)
        assert result == QueuePressure.MEDIUM

        # 17 out of 23 = 73.91% -> HIGH
        result = calculate_queue_pressure(17, 23)
        assert result == QueuePressure.HIGH

    def test_calculate_pressure_edge_cases(self) -> None:
        """
        Test pressure calculation edge cases.
        """
        # Empty queue
        result = calculate_queue_pressure(0, 1000)
        assert result == QueuePressure.LOW

        # Single item queues
        result = calculate_queue_pressure(0, 1)
        assert result == QueuePressure.LOW

        result = calculate_queue_pressure(1, 1)
        assert result == QueuePressure.CRITICAL

        # Large numbers
        result = calculate_queue_pressure(25000, 100000)  # 25%
        assert result == QueuePressure.LOW

        result = calculate_queue_pressure(95000, 100000)  # 95%
        assert result == QueuePressure.CRITICAL
