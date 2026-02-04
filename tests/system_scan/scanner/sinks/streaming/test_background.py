from __future__ import annotations

import pytest
from concurrent.futures import ThreadPoolExecutor
from typing import cast
from unittest.mock import Mock, patch

from safety.system_scan.scanner.sinks.streaming.background import (
    StreamingSender,
    StreamingContext,
)
from safety.system_scan.scanner.sinks.streaming.config import SenderConfig, BatchConfig
from safety.system_scan.scanner.sinks.streaming.callbacks import (
    StreamingCallbacks,
    StreamingStatus,
)
from safety.system_scan.scanner.sinks.streaming.http import EventSender
from safety.system_scan.scanner.sinks.streaming.queue import BatchedQueue


@pytest.mark.unit
class TestStreamingSender:
    """
    Test StreamingSender implementation.
    """

    @pytest.fixture
    def mock_event_sender(self) -> Mock:
        """
        Mock event sender.
        """
        return Mock(spec=EventSender)

    @pytest.fixture
    def mock_queue(self) -> Mock:
        """
        Mock batched queue.
        """
        return Mock(spec=BatchedQueue)

    @pytest.fixture
    def streaming_sender(
        self, mock_event_sender: Mock, mock_queue: Mock
    ) -> StreamingSender:
        """
        Create StreamingSender instance for testing.
        """
        return StreamingSender(mock_event_sender, mock_queue)

    def test_init(self, mock_event_sender: Mock, mock_queue: Mock) -> None:
        """
        Test StreamingSender initialization.
        """
        sender = StreamingSender(mock_event_sender, mock_queue)

        assert sender.sender == mock_event_sender
        assert sender.queue == mock_queue
        assert sender.scan_ref is None

    def test_create_scan(self, streaming_sender: StreamingSender) -> None:
        """
        Test creating a scan.
        """
        cast(Mock, streaming_sender.sender).create_scan.return_value = "test-scan-123"

        metadata = {"system_id": "test-machine", "hostname": "test-host"}
        scan_id = streaming_sender.create_scan(metadata)

        assert scan_id == "test-scan-123"
        assert streaming_sender.scan_ref == "test-scan-123"
        cast(Mock, streaming_sender.sender).create_scan.assert_called_once_with(
            metadata
        )

    def test_create_scan_without_metadata(
        self, streaming_sender: StreamingSender
    ) -> None:
        """
        Test creating a scan without metadata.
        """
        cast(Mock, streaming_sender.sender).create_scan.return_value = "scan-456"

        scan_id = streaming_sender.create_scan()

        assert scan_id == "scan-456"
        assert streaming_sender.scan_ref == "scan-456"
        cast(Mock, streaming_sender.sender).create_scan.assert_called_once_with(None)

    def test_send_event(self, streaming_sender: StreamingSender) -> None:
        """
        Test sending an event.
        """
        event = {"type": "discovery", "data": "test-data"}

        streaming_sender.send(event)

        cast(Mock, streaming_sender.queue).put.assert_called_once_with(event)

    def test_finish_with_scan_ref(self, streaming_sender: StreamingSender) -> None:
        """
        Test finishing with active scan.
        """
        streaming_sender.scan_ref = "test-scan"
        cast(Mock, streaming_sender.queue).is_drained.side_effect = [False, True]

        with patch("time.sleep") as mock_sleep:
            streaming_sender.finish()

        cast(Mock, streaming_sender.queue).close.assert_called_once()
        mock_sleep.assert_called_once_with(0.1)

    def test_finish_without_scan_ref(self, streaming_sender: StreamingSender) -> None:
        """
        Test finishing without active scan raises error.
        """
        with pytest.raises(RuntimeError, match="No active scan to finish"):
            streaming_sender.finish()

    def test_finish_waits_for_drain(self, streaming_sender: StreamingSender) -> None:
        """
        Test finish waits for queue to drain.
        """
        streaming_sender.scan_ref = "test-scan"
        # First 3 calls return False, then True
        cast(Mock, streaming_sender.queue).is_drained.side_effect = [
            False,
            False,
            False,
            True,
        ]

        with patch("time.sleep") as mock_sleep:
            streaming_sender.finish()

        assert mock_sleep.call_count == 3

    def test_finish_with_summary(self, streaming_sender: StreamingSender) -> None:
        """
        Test finishing with summary parameter.
        """
        streaming_sender.scan_ref = "test-scan"
        cast(Mock, streaming_sender.queue).is_drained.return_value = True

        summary = {"events_sent": 100}
        streaming_sender.finish(summary)

        cast(Mock, streaming_sender.queue).close.assert_called_once()


@pytest.mark.unit
class TestStreamingContext:
    """
    Test StreamingContext implementation.
    """

    @pytest.fixture
    def sender_config(self) -> SenderConfig:
        """
        Sender configuration for testing.
        """
        return SenderConfig(
            base_url="https://api.test.com",
            timeout=30.0,
            workers=2,
            batch=BatchConfig(max_events=10, flush_interval=1.0),
        )

    @pytest.fixture
    def mock_http_client(self) -> Mock:
        """
        Mock HTTP client.
        """
        return Mock()

    @pytest.fixture
    def mock_callbacks(self) -> Mock:
        """
        Mock streaming callbacks.
        """
        return Mock(spec=StreamingCallbacks)

    @pytest.fixture
    def streaming_context(
        self, sender_config: SenderConfig, mock_http_client: Mock, mock_callbacks: Mock
    ) -> StreamingContext:
        """
        Create StreamingContext instance for testing.
        """
        return StreamingContext(sender_config, mock_http_client, mock_callbacks)

    def test_init(
        self,
        sender_config: SenderConfig,
        mock_http_client: Mock,
        mock_callbacks: Mock,
    ) -> None:
        """
        Test StreamingContext initialization.
        """
        context = StreamingContext(sender_config, mock_http_client, mock_callbacks)

        assert context.config == sender_config
        assert context._http_client == mock_http_client
        assert context.callbacks == mock_callbacks
        assert context._sender is None
        assert context._queue is None
        assert context._pool is None
        assert context._error is None
        assert context._streaming_sender is None

    @patch("safety.system_scan.scanner.sinks.streaming.background.EventSender")
    @patch("safety.system_scan.scanner.sinks.streaming.background.BatchedQueue")
    @patch("safety.system_scan.scanner.sinks.streaming.background.ThreadPoolExecutor")
    def test_enter(
        self,
        mock_thread_pool: Mock,
        mock_batched_queue_class: Mock,
        mock_event_sender_class: Mock,
        streaming_context: StreamingContext,
    ) -> None:
        """
        Test context manager enter.
        """
        # Setup mocks
        mock_sender = Mock(spec=EventSender)
        mock_sender.__enter__ = Mock(return_value=mock_sender)
        mock_event_sender_class.return_value = mock_sender

        mock_queue = Mock(spec=BatchedQueue)
        mock_batched_queue_class.return_value = mock_queue

        mock_pool = Mock(spec=ThreadPoolExecutor)
        mock_thread_pool.return_value = mock_pool

        # Call __enter__
        streaming_sender = streaming_context.__enter__()

        # Verify initialization
        mock_event_sender_class.assert_called_once_with(
            "https://api.test.com",
            http_client=streaming_context._http_client,
            timeout=30.0,
        )
        mock_sender.__enter__.assert_called_once()

        mock_batched_queue_class.assert_called_once_with(
            streaming_context.config.batch, streaming_context.callbacks
        )

        mock_thread_pool.assert_called_once_with(max_workers=2)

        # Verify workers started
        assert mock_pool.submit.call_count == 2

        # Verify callbacks
        assert cast(Mock, streaming_context.callbacks.connection_change).call_count == 2
        calls = cast(Mock, streaming_context.callbacks.connection_change).call_args_list
        assert calls[0][0][0] == StreamingStatus.CONNECTING
        assert calls[1][0][0] == StreamingStatus.STREAMING

        # Verify return value
        assert isinstance(streaming_sender, StreamingSender)

    def test_exit_normal(self, streaming_context: StreamingContext) -> None:
        """
        Test context manager exit without error.
        """
        # Setup mock resources
        mock_queue = Mock(spec=BatchedQueue)
        mock_pool = Mock(spec=ThreadPoolExecutor)
        mock_sender = Mock(spec=EventSender)
        mock_sender.__exit__ = Mock()

        streaming_context._queue = mock_queue
        streaming_context._pool = mock_pool
        streaming_context._sender = mock_sender

        # Call __exit__
        streaming_context.__exit__(None, None, None)

        # Verify cleanup
        mock_queue.close.assert_called_once()
        mock_pool.shutdown.assert_called_once_with(wait=True)
        mock_sender.__exit__.assert_called_once_with(None, None, None)

        cast(Mock, streaming_context.callbacks.connection_change).assert_called_with(
            StreamingStatus.COMPLETE
        )

    def test_exit_with_error(self, streaming_context: StreamingContext) -> None:
        """
        Test context manager exit with worker error.
        """
        # Setup mock resources
        mock_queue = Mock(spec=BatchedQueue)
        mock_pool = Mock(spec=ThreadPoolExecutor)
        mock_sender = Mock(spec=EventSender)
        mock_sender.__exit__ = Mock()

        streaming_context._queue = mock_queue
        streaming_context._pool = mock_pool
        streaming_context._sender = mock_sender
        streaming_context._error = RuntimeError("Worker error")

        # Call __exit__ should propagate error
        with pytest.raises(RuntimeError, match="Worker error"):
            streaming_context.__exit__(None, None, None)

    def test_exit_partial_resources(self, streaming_context: StreamingContext) -> None:
        """
        Test context manager exit with only some resources initialized.
        """
        # Only set queue, not pool or sender
        mock_queue = Mock(spec=BatchedQueue)
        streaming_context._queue = mock_queue

        # Should not raise
        streaming_context.__exit__(None, None, None)

        mock_queue.close.assert_called_once()

    @patch("safety.system_scan.scanner.sinks.streaming.background.BatchedQueue")
    @patch("safety.system_scan.scanner.sinks.streaming.background.EventSender")
    def test_worker_success(
        self,
        mock_event_sender_class: Mock,
        mock_queue_class: Mock,
        streaming_context: StreamingContext,
    ) -> None:
        """
        Test worker processes batches successfully.
        """
        # Setup mocks
        mock_queue = Mock(spec=BatchedQueue)
        mock_queue.is_drained.side_effect = [False, False, True]
        mock_queue.get.side_effect = [
            [{"event": 1}, {"event": 2}],  # First batch
            None,  # Second call returns None (empty)
        ]

        mock_sender = Mock(spec=EventSender)
        mock_streaming_sender = Mock(spec=StreamingSender)
        mock_streaming_sender.scan_ref = "test-scan-123"

        streaming_context._queue = mock_queue
        streaming_context._sender = mock_sender
        streaming_context._streaming_sender = mock_streaming_sender

        # Call worker
        streaming_context._worker()

        # Verify batch sent
        mock_sender.send_batch.assert_called_once_with(
            "test-scan-123", [{"event": 1}, {"event": 2}]
        )

        # Verify callback
        cast(Mock, streaming_context.callbacks.batch_sent).assert_called_once_with(2)

    @patch("safety.system_scan.scanner.sinks.streaming.background.BatchedQueue")
    def test_worker_no_scan_ref(
        self, mock_queue_class: Mock, streaming_context: StreamingContext
    ) -> None:
        """
        Test worker fails when no scan reference.
        """
        # Setup mocks
        mock_queue = Mock(spec=BatchedQueue)
        mock_queue.is_drained.side_effect = [False, True]
        mock_queue.get.return_value = [{"event": 1}]

        mock_sender = Mock(spec=EventSender)
        mock_streaming_sender = Mock(spec=StreamingSender)
        mock_streaming_sender.scan_ref = None  # No scan created

        streaming_context._queue = mock_queue
        streaming_context._sender = mock_sender
        streaming_context._streaming_sender = mock_streaming_sender

        # Call worker
        streaming_context._worker()

        # Verify error set
        assert streaming_context._error is not None
        assert isinstance(streaming_context._error, RuntimeError)
        assert "No scan created" in str(streaming_context._error)

    def test_worker_connection_error(self, streaming_context: StreamingContext) -> None:
        """
        Test worker handles connection errors.
        """
        # Setup mocks
        mock_queue = Mock(spec=BatchedQueue)
        mock_queue.is_drained.side_effect = [False, True]
        mock_queue.get.return_value = [{"event": 1}]

        mock_sender = Mock(spec=EventSender)
        connection_error = ConnectionError("Network error")
        mock_sender.send_batch.side_effect = connection_error

        mock_streaming_sender = Mock(spec=StreamingSender)
        mock_streaming_sender.scan_ref = "test-scan"

        streaming_context._queue = mock_queue
        streaming_context._sender = mock_sender
        streaming_context._streaming_sender = mock_streaming_sender

        # Call worker
        streaming_context._worker()

        # Verify error handling
        cast(Mock, streaming_context.callbacks.connection_change).assert_called_with(
            StreamingStatus.RECONNECTING
        )
        cast(Mock, streaming_context.callbacks.error).assert_called_with(
            "Connection lost during batch send", connection_error
        )
        assert streaming_context._error == connection_error

    def test_worker_general_exception(
        self, streaming_context: StreamingContext
    ) -> None:
        """
        Test worker handles general exceptions.
        """
        # Setup mocks
        mock_queue = Mock(spec=BatchedQueue)
        mock_queue.is_drained.side_effect = [False, True]
        mock_queue.get.return_value = [{"event": 1}]

        mock_sender = Mock(spec=EventSender)
        general_error = ValueError("Invalid data")
        mock_sender.send_batch.side_effect = general_error

        mock_streaming_sender = Mock(spec=StreamingSender)
        mock_streaming_sender.scan_ref = "test-scan"

        streaming_context._queue = mock_queue
        streaming_context._sender = mock_sender
        streaming_context._streaming_sender = mock_streaming_sender

        # Call worker
        streaming_context._worker()

        # Verify error handling
        cast(Mock, streaming_context.callbacks.error).assert_called_with(
            "Batch send failed: Invalid data", general_error
        )
        assert streaming_context._error == general_error

    def test_worker_empty_batch_handling(
        self, streaming_context: StreamingContext
    ) -> None:
        """
        Test worker handles empty batches correctly.
        """
        # Setup mocks
        mock_queue = Mock(spec=BatchedQueue)
        mock_queue.is_drained.side_effect = [False, False, True]
        mock_queue.get.side_effect = [None, None]  # Empty batches

        mock_sender = Mock(spec=EventSender)
        mock_streaming_sender = Mock(spec=StreamingSender)

        streaming_context._queue = mock_queue
        streaming_context._sender = mock_sender
        streaming_context._streaming_sender = mock_streaming_sender

        # Call worker
        streaming_context._worker()

        # Verify no batch sent
        mock_sender.send_batch.assert_not_called()
        cast(Mock, streaming_context.callbacks.batch_sent).assert_not_called()

    def test_notify_connection(self, streaming_context: StreamingContext) -> None:
        """
        Test connection status notification.
        """
        streaming_context._notify_connection(StreamingStatus.CONNECTING)

        cast(
            Mock, streaming_context.callbacks.connection_change
        ).assert_called_once_with(StreamingStatus.CONNECTING)

    @patch("safety.system_scan.scanner.sinks.streaming.background.EventSender")
    @patch("safety.system_scan.scanner.sinks.streaming.background.BatchedQueue")
    @patch("safety.system_scan.scanner.sinks.streaming.background.ThreadPoolExecutor")
    def test_full_context_workflow(
        self,
        mock_thread_pool: Mock,
        mock_batched_queue_class: Mock,
        mock_event_sender_class: Mock,
        streaming_context: StreamingContext,
    ) -> None:
        """
        Test complete context manager workflow.
        """
        # Setup mocks
        mock_sender = Mock(spec=EventSender)
        mock_sender.__enter__ = Mock(return_value=mock_sender)
        mock_sender.__exit__ = Mock()
        mock_event_sender_class.return_value = mock_sender

        mock_queue = Mock(spec=BatchedQueue)
        mock_batched_queue_class.return_value = mock_queue

        mock_pool = Mock(spec=ThreadPoolExecutor)
        mock_thread_pool.return_value = mock_pool

        # Use context manager
        with streaming_context as streaming_sender:
            assert isinstance(streaming_sender, StreamingSender)

        # Verify complete lifecycle
        mock_sender.__enter__.assert_called_once()
        mock_sender.__exit__.assert_called_once()
        mock_queue.close.assert_called_once()
        mock_pool.shutdown.assert_called_once_with(wait=True)

        # Verify status notifications
        connection_calls = cast(
            Mock, streaming_context.callbacks.connection_change
        ).call_args_list
        assert len(connection_calls) == 3
        assert connection_calls[0][0][0] == StreamingStatus.CONNECTING
        assert connection_calls[1][0][0] == StreamingStatus.STREAMING
        assert connection_calls[2][0][0] == StreamingStatus.COMPLETE
