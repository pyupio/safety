from __future__ import annotations

import pytest
from unittest.mock import Mock, patch
import uuid

import httpx

from safety.system_scan.scanner.sinks.streaming.http import (
    EventSender,
    RetryableHTTPError,
    RETRYABLE_EXCEPTIONS,
)


@pytest.mark.unit
class TestEventSender:
    """
    Test HTTP event sender functionality.
    """

    @pytest.fixture
    def base_url(self) -> str:
        """
        Test base URL.
        """
        return "https://api.safetycli.com"

    @pytest.fixture
    def mock_client(self) -> Mock:
        """
        Mock HTTP client.
        """
        return Mock(spec=httpx.Client)

    @pytest.fixture
    def sender(self, base_url: str, mock_client: Mock) -> EventSender:
        """
        EventSender instance with mocked client.
        """
        return EventSender(base_url=base_url, http_client=mock_client)

    def test_init_strips_trailing_slash(self, mock_client: Mock) -> None:
        """
        Test URL normalization removes trailing slash.
        """
        sender = EventSender("https://api.test.com/", mock_client)
        assert sender.base_url == "https://api.test.com"

    def test_context_manager_lifecycle(
        self, sender: EventSender, mock_client: Mock
    ) -> None:
        """
        Test context manager doesn't close injected client.
        """
        with sender as s:
            assert s == sender

        # Client should not be closed as it's injected
        mock_client.close.assert_not_called()

    def test_create_scan_success(self, sender: EventSender, mock_client: Mock) -> None:
        """
        Test successful scan creation.
        """
        expected_scan_id = str(uuid.uuid4())
        mock_response = Mock()
        mock_response.json.return_value = {"system_scan_id": expected_scan_id}
        mock_client.post.return_value = mock_response

        scan_id = sender.create_scan({"machine_id": "test-machine"})

        assert scan_id == expected_scan_id
        mock_client.post.assert_called_once_with(
            f"{sender.base_url}/api/system-scans/", json={"machine_id": "test-machine"}
        )
        mock_response.raise_for_status.assert_called_once()

    def test_create_scan_with_none_metadata(
        self, sender: EventSender, mock_client: Mock
    ) -> None:
        """
        Test scan creation with None metadata defaults to empty dict.
        """
        mock_response = Mock()
        mock_response.json.return_value = {"system_scan_id": "test-id"}
        mock_client.post.return_value = mock_response

        sender.create_scan(None)

        mock_client.post.assert_called_once_with(
            f"{sender.base_url}/api/system-scans/", json={}
        )

    def test_send_batch_empty_events(
        self, sender: EventSender, mock_client: Mock
    ) -> None:
        """
        Test sending empty events list does nothing.
        """
        sender.send_batch("scan-123", [])

        mock_client.post.assert_not_called()

    def test_send_batch_success(self, sender: EventSender, mock_client: Mock) -> None:
        """
        Test successful batch sending.
        """
        events = [
            {"type": "test", "data": "value1"},
            {"type": "test", "data": "value2"},
        ]
        mock_response = Mock()
        mock_response.status_code = 201
        mock_client.post.return_value = mock_response

        sender.send_batch("scan-123", events)

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[1]["json"] == events
        assert call_args[1]["headers"]["X-Scan-Ref"] == "scan-123"
        assert "X-Batch-Id" in call_args[1]["headers"]

    def test_send_with_split_on_413_error(
        self, sender: EventSender, mock_client: Mock
    ) -> None:
        """
        Test payload splitting on 413 Too Large error.
        """
        events = [{"data": "1"}, {"data": "2"}, {"data": "3"}, {"data": "4"}]

        # Mock 413 error first, then success
        error_response = Mock()
        error_response.status_code = 413
        success_response = Mock()
        success_response.status_code = 201

        http_error = httpx.HTTPStatusError(
            "Payload too large", request=Mock(), response=error_response
        )

        # First call raises 413, subsequent calls succeed
        mock_client.post.side_effect = [http_error, success_response, success_response]

        sender.send_batch("scan-123", events)

        # Should be called 3 times: original + 2 splits
        assert mock_client.post.call_count == 3

    @pytest.mark.parametrize("status_code", [408, 429, 500, 502, 503, 504])
    def test_retryable_http_errors(
        self, sender: EventSender, mock_client: Mock, status_code: int
    ) -> None:
        """
        Test retryable HTTP status codes trigger retry logic.
        """
        events = [{"test": "data"}]

        # Mock responses: retryable error then success
        error_response = Mock()
        error_response.status_code = status_code
        error_response.headers = {}

        success_response = Mock()
        success_response.status_code = 201

        mock_client.post.side_effect = [error_response, success_response]

        with patch.object(sender, "_wait_retry_after"):
            sender.send_batch("scan-123", events)

        assert mock_client.post.call_count == 2

    @pytest.mark.parametrize("exception_type", RETRYABLE_EXCEPTIONS)
    def test_retryable_network_exceptions(
        self, sender: EventSender, mock_client: Mock, exception_type: type
    ) -> None:
        """
        Test retryable network exceptions trigger retry logic.
        """
        events = [{"test": "data"}]

        # Mock network error then success
        success_response = Mock()
        success_response.status_code = 201

        mock_client.post.side_effect = [
            exception_type("Network error"),
            success_response,
        ]

        sender.send_batch("scan-123", events)

        assert mock_client.post.call_count == 2

    def test_retry_after_header_handling(self, sender: EventSender) -> None:
        """
        Test handling of Retry-After header.
        """
        mock_response = Mock()
        mock_response.headers = {"Retry-After": "5"}

        with patch("time.sleep") as mock_sleep:
            sender._wait_retry_after(mock_response)
            mock_sleep.assert_called_once_with(5)

    def test_retry_after_header_capped_at_60(self, sender: EventSender) -> None:
        """
        Test Retry-After header is capped at 60 seconds.
        """
        mock_response = Mock()
        mock_response.headers = {"Retry-After": "120"}

        with patch("time.sleep") as mock_sleep:
            sender._wait_retry_after(mock_response)
            mock_sleep.assert_called_once_with(60)

    def test_retry_after_invalid_value(self, sender: EventSender) -> None:
        """
        Test invalid Retry-After header is ignored.
        """
        mock_response = Mock()
        mock_response.headers = {"Retry-After": "invalid"}

        with patch("time.sleep") as mock_sleep:
            sender._wait_retry_after(mock_response)
            mock_sleep.assert_not_called()

    def test_retry_after_no_header(self, sender: EventSender) -> None:
        """
        Test behavior when no Retry-After header is present.
        """
        mock_response = Mock()
        mock_response.headers = {}

        with patch("time.sleep") as mock_sleep:
            sender._wait_retry_after(mock_response)
            mock_sleep.assert_not_called()

    def test_create_scan_http_error(
        self, sender: EventSender, mock_client: Mock
    ) -> None:
        """
        Test scan creation handles HTTP errors.
        """
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad request", request=Mock(), response=Mock()
        )
        mock_client.post.return_value = mock_response

        with pytest.raises(httpx.HTTPStatusError):
            sender.create_scan({"machine_id": "test-machine"})

    def test_send_batch_non_retryable_error(
        self, sender: EventSender, mock_client: Mock
    ) -> None:
        """
        Test non-retryable HTTP errors are raised immediately.
        """
        events = [{"test": "data"}]

        error_response = Mock()
        error_response.status_code = 400  # Non-retryable
        error_response.headers = {}
        # Mock raise_for_status to raise HTTPStatusError for 400 status
        error_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad request", request=Mock(), response=error_response
        )

        mock_client.post.return_value = error_response

        with pytest.raises(httpx.HTTPStatusError):
            sender.send_batch("scan-123", events)

        # Should only be called once (no retry)
        assert mock_client.post.call_count == 1


@pytest.mark.unit
class TestRetryableHTTPError:
    """
    Test custom retry exception.
    """

    def test_retryable_error_creation(self) -> None:
        """
        Test RetryableHTTPError creation and attributes.
        """
        error = RetryableHTTPError(503)

        assert error.status_code == 503
        assert "Retryable HTTP 503" in str(error)

    def test_retryable_error_inheritance(self) -> None:
        """
        Test RetryableHTTPError inherits from Exception.
        """
        error = RetryableHTTPError(503)
        assert isinstance(error, Exception)


@pytest.mark.unit
class TestRetryableExceptions:
    """
    Test the retryable exceptions constant.
    """

    def test_retryable_exceptions_tuple(self) -> None:
        """
        Test RETRYABLE_EXCEPTIONS contains expected exception types.
        """
        expected_exceptions = (
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.RemoteProtocolError,
        )

        assert RETRYABLE_EXCEPTIONS == expected_exceptions

    def test_all_retryable_exceptions_are_httpx_exceptions(self) -> None:
        """
        Test all retryable exceptions inherit from httpx exceptions.
        """
        for exc_type in RETRYABLE_EXCEPTIONS:
            # All should be subclasses of httpx base exception types
            assert issubclass(exc_type, (httpx.RequestError, httpx.HTTPError))
