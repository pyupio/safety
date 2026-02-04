from __future__ import annotations

import pytest
from unittest.mock import Mock, patch

from safety.system_scan.scanner.sinks.platform import SafetyPlatformSink
from safety.system_scan.scanner.sinks.streaming import SenderConfig, StreamingCallbacks
from safety.system_scan.scanner.events import SystemScanAction


@pytest.mark.unit
class TestSafetyPlatformSink:
    """
    Test SafetyPlatformSink implementation.
    """

    @pytest.fixture
    def sender_config(self) -> SenderConfig:
        """
        Mock sender configuration.
        """
        return Mock(spec=SenderConfig)

    @pytest.fixture
    def http_client(self) -> Mock:
        """
        Mock HTTP client.
        """
        return Mock()

    @pytest.fixture
    def callbacks(self) -> Mock:
        """
        Mock streaming callbacks.
        """
        return Mock(spec=StreamingCallbacks)

    @pytest.fixture
    def platform_sink(
        self, sender_config: Mock, http_client: Mock, callbacks: Mock
    ) -> SafetyPlatformSink:
        """
        Create SafetyPlatformSink instance for testing.
        """
        return SafetyPlatformSink(
            sender_config=sender_config,
            http_client=http_client,
            callbacks=callbacks,
        )

    def test_sink_name(self) -> None:
        """
        Test sink has correct name.
        """
        assert SafetyPlatformSink.name == "safety_platform"

    def test_init(
        self, sender_config: Mock, http_client: Mock, callbacks: Mock
    ) -> None:
        """
        Test sink initialization.
        """
        sink = SafetyPlatformSink(
            sender_config=sender_config,
            http_client=http_client,
            callbacks=callbacks,
        )

        assert sink.sender_config == sender_config
        assert sink.http_client == http_client
        assert sink.callbacks == callbacks
        assert sink._ctx_mgr is None
        assert sink._sender is None
        assert sink.scan_id is None

    @patch("safety.system_scan.scanner.sinks.platform.StreamingContext")
    def test_open(
        self, mock_streaming_context: Mock, platform_sink: SafetyPlatformSink
    ) -> None:
        """
        Test opening the sink creates streaming context and scan.
        """
        # Setup mocks
        mock_ctx_mgr = Mock()
        mock_ctx_mgr.__enter__ = Mock(return_value=Mock())
        mock_ctx_mgr.__exit__ = Mock(return_value=None)
        mock_sender = mock_ctx_mgr.__enter__.return_value
        mock_streaming_context.return_value = mock_ctx_mgr
        mock_sender.create_scan.return_value = "test-scan-123"

        # Call open
        scan_id = platform_sink.open("machine-456", "test-hostname")

        # Verify behavior
        mock_streaming_context.assert_called_once_with(
            platform_sink.sender_config,
            platform_sink.http_client,
            platform_sink.callbacks,
        )
        mock_ctx_mgr.__enter__.assert_called_once()
        mock_sender.create_scan.assert_called_once_with(
            metadata={
                "subtype": "HOST",
                "machine_id": "machine-456",
                "hostname": "test-hostname",
            }
        )

        assert scan_id == "test-scan-123"
        assert platform_sink.scan_id == "test-scan-123"
        assert platform_sink._ctx_mgr == mock_ctx_mgr
        assert platform_sink._sender == mock_sender

    @patch("safety.system_scan.scanner.sinks.platform.build_discovered_event")
    def test_write(
        self, mock_build_event: Mock, platform_sink: SafetyPlatformSink
    ) -> None:
        """
        Test writing item builds event and sends it.
        """
        # Setup sink with mocked sender
        mock_sender = Mock()
        platform_sink._sender = mock_sender
        platform_sink.scan_id = "test-scan-789"

        # Setup mock event
        mock_event = {"type": "discovery", "data": "test"}
        mock_build_event.return_value = mock_event

        # Test data
        test_item = Mock()

        # Call write
        platform_sink.write(test_item)

        # Verify behavior
        mock_build_event.assert_called_once_with(test_item, "test-scan-789")
        mock_sender.send.assert_called_once_with(mock_event)

    def test_write_without_sender_raises_assertion(
        self, platform_sink: SafetyPlatformSink
    ) -> None:
        """
        Test writing without sender raises AssertionError.
        """
        platform_sink.scan_id = "test-scan"

        with pytest.raises(AssertionError):
            platform_sink.write(Mock())

    def test_write_without_scan_id_raises_assertion(
        self, platform_sink: SafetyPlatformSink
    ) -> None:
        """
        Test writing without scan_id raises AssertionError.
        """
        platform_sink._sender = Mock()

        with pytest.raises(AssertionError):
            platform_sink.write(Mock())

    @patch("safety.system_scan.scanner.sinks.platform.build_system_scan_event")
    def test_close_success(
        self, mock_build_system_event: Mock, platform_sink: SafetyPlatformSink
    ) -> None:
        """
        Test closing sink with success sends final event.
        """
        # Setup mocks
        mock_sender = Mock()
        mock_ctx_mgr = Mock()
        mock_ctx_mgr.__exit__ = Mock(return_value=None)
        platform_sink._sender = mock_sender
        platform_sink._ctx_mgr = mock_ctx_mgr
        platform_sink.scan_id = "test-scan-close"

        mock_final_event = {"type": "system_scan", "action": "SUCCEEDED"}
        mock_build_system_event.return_value = mock_final_event

        # Call close with success
        platform_sink.close(True)

        # Verify behavior
        mock_build_system_event.assert_called_once_with(
            "test-scan-close", SystemScanAction.SUCCEEDED
        )
        mock_sender.send.assert_called_once_with(mock_final_event)
        mock_sender.finish.assert_called_once()
        mock_ctx_mgr.__exit__.assert_called_once_with(None, None, None)

    @patch("safety.system_scan.scanner.sinks.platform.build_system_scan_event")
    def test_close_failure(
        self, mock_build_system_event: Mock, platform_sink: SafetyPlatformSink
    ) -> None:
        """
        Test closing sink with failure sends failure event.
        """
        # Setup mocks
        mock_sender = Mock()
        mock_ctx_mgr = Mock()
        mock_ctx_mgr.__exit__ = Mock(return_value=None)
        platform_sink._sender = mock_sender
        platform_sink._ctx_mgr = mock_ctx_mgr
        platform_sink.scan_id = "test-scan-fail"

        mock_final_event = {"type": "system_scan", "action": "FAILED"}
        mock_build_system_event.return_value = mock_final_event

        # Call close with failure
        platform_sink.close(False)

        # Verify behavior
        mock_build_system_event.assert_called_once_with(
            "test-scan-fail", SystemScanAction.FAILED
        )
        mock_sender.send.assert_called_once_with(mock_final_event)
        mock_sender.finish.assert_called_once()
        mock_ctx_mgr.__exit__.assert_called_once_with(None, None, None)

    def test_close_without_sender(self, platform_sink: SafetyPlatformSink) -> None:
        """
        Test closing without sender does nothing.
        """
        platform_sink._ctx_mgr = Mock()
        platform_sink.scan_id = "test-scan"

        # Should not raise and do nothing
        platform_sink.close(True)

    def test_close_without_ctx_mgr(self, platform_sink: SafetyPlatformSink) -> None:
        """
        Test closing without context manager does nothing.
        """
        platform_sink._sender = Mock()
        platform_sink.scan_id = "test-scan"

        # Should not raise and do nothing
        platform_sink.close(True)

    def test_close_without_scan_id(self, platform_sink: SafetyPlatformSink) -> None:
        """
        Test closing without scan_id does nothing.
        """
        platform_sink._sender = Mock()
        platform_sink._ctx_mgr = Mock()

        # Should not raise and do nothing
        platform_sink.close(True)

    def test_close_partial_setup(self, platform_sink: SafetyPlatformSink) -> None:
        """
        Test closing with only some components set up does nothing.
        """
        # Test with only sender
        platform_sink._sender = Mock()
        platform_sink.close(True)

        # Test with only ctx_mgr
        platform_sink._sender = None
        platform_sink._ctx_mgr = Mock()
        platform_sink.close(True)

        # Test with only scan_id
        platform_sink._ctx_mgr = None
        platform_sink.scan_id = "test"
        platform_sink.close(True)

    @patch("safety.system_scan.scanner.sinks.platform.StreamingContext")
    @patch("safety.system_scan.scanner.sinks.platform.build_discovered_event")
    @patch("safety.system_scan.scanner.sinks.platform.build_system_scan_event")
    def test_full_workflow(
        self,
        mock_build_system_event: Mock,
        mock_build_discovered_event: Mock,
        mock_streaming_context: Mock,
        platform_sink: SafetyPlatformSink,
    ) -> None:
        """
        Test complete workflow from open to close.
        """
        # Setup streaming context mock
        mock_ctx_mgr = Mock()
        mock_sender = Mock()
        mock_ctx_mgr.__enter__ = Mock(return_value=mock_sender)
        mock_ctx_mgr.__exit__ = Mock(return_value=None)
        mock_streaming_context.return_value = mock_ctx_mgr
        mock_sender.create_scan.return_value = "workflow-scan-123"

        # Setup event mocks
        mock_discovery_event = {"type": "discovery"}
        mock_system_event = {"type": "system_scan"}
        mock_build_discovered_event.return_value = mock_discovery_event
        mock_build_system_event.return_value = mock_system_event

        # Complete workflow
        scan_id = platform_sink.open("machine-workflow", "workflow-host")

        test_item = Mock()
        platform_sink.write(test_item)
        platform_sink.write(test_item)  # Write twice

        platform_sink.close(True)

        # Verify complete workflow
        assert scan_id == "workflow-scan-123"
        assert mock_sender.send.call_count == 3  # 2 discoveries + 1 system event
        mock_sender.finish.assert_called_once()
        mock_ctx_mgr.__exit__.assert_called_once_with(None, None, None)
