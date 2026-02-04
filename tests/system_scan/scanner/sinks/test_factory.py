from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import Mock

from safety.system_scan.scanner.sinks.factory import build_sink
from safety.system_scan.scanner.sinks.config import (
    SafetyPlatformSinkConfig,
    JsonlSinkConfig,
    NullSinkConfig,
)
from safety.system_scan.scanner.sinks.platform import SafetyPlatformSink
from safety.system_scan.scanner.sinks.jsonl import JsonlSink
from safety.system_scan.scanner.sinks.null import NullSink
from safety.system_scan.scanner.sinks.streaming.callbacks import StreamingCallbacks


@pytest.mark.unit
class TestBuildSink:
    """
    Test build_sink factory function.
    """

    @pytest.fixture
    def mock_callbacks(self) -> Mock:
        """
        Mock streaming callbacks.
        """
        return Mock(spec=StreamingCallbacks)

    def test_build_safety_platform_sink(self, mock_callbacks: Mock) -> None:
        """
        Test building SafetyPlatformSink.
        """
        mock_client = Mock()
        config = SafetyPlatformSinkConfig(
            base_url="https://test.example.com",
            timeout=30,
            http_client=mock_client,
        )

        sink = build_sink(config, mock_callbacks)

        assert isinstance(sink, SafetyPlatformSink)

    def test_build_jsonl_sink_with_file_path(self, mock_callbacks: Mock) -> None:
        """
        Test building JsonlSink with file path.
        """
        config = JsonlSinkConfig(path="/test/output.jsonl")

        sink = build_sink(config, mock_callbacks)

        assert isinstance(sink, JsonlSink)
        assert sink.path == Path("/test/output.jsonl")

    def test_build_jsonl_sink_with_directory_path(self, mock_callbacks: Mock) -> None:
        """
        Test building JsonlSink with directory path.
        """
        config = JsonlSinkConfig(path="/test/output/")

        sink = build_sink(config, mock_callbacks)

        assert isinstance(sink, JsonlSink)
        assert sink.path == Path("/test/output/")

    def test_build_null_sink(self, mock_callbacks: Mock) -> None:
        """
        Test building NullSink.
        """
        config = NullSinkConfig()

        sink = build_sink(config, mock_callbacks)

        assert isinstance(sink, NullSink)

    def test_build_sink_unsupported_config_type(self, mock_callbacks: Mock) -> None:
        """
        Test build_sink raises TypeError for unsupported config.
        """

        class UnsupportedConfig:
            pass

        config = UnsupportedConfig()

        with pytest.raises(TypeError, match="Unsupported sink config"):
            build_sink(config, mock_callbacks)  # type: ignore

    def test_build_safety_platform_sink_creates_correct_config(
        self, mock_callbacks: Mock
    ) -> None:
        """
        Test SafetyPlatformSink is created with correct SenderConfig.
        """
        mock_client = Mock()
        config = SafetyPlatformSinkConfig(
            base_url="https://api.safety.com",
            timeout=60,
            http_client=mock_client,
        )

        sink = build_sink(config, mock_callbacks)

        assert isinstance(sink, SafetyPlatformSink)
        # Verify the sink was created with the expected configuration
        assert sink.sender_config.base_url == "https://api.safety.com"
        assert sink.sender_config.timeout == 60
        assert sink.sender_config.workers == 3
        assert sink.sender_config.batch.max_events == 500
        assert sink.sender_config.batch.max_bytes == 500_000
        assert sink.sender_config.batch.flush_interval == 0.8
        assert sink.sender_config.batch.max_pending_events == 3000

    def test_safety_platform_sink_imports_streaming_configs(
        self, mock_callbacks: Mock
    ) -> None:
        """
        Test that SafetyPlatformSink creation imports streaming configs correctly.
        """
        mock_client = Mock()
        config = SafetyPlatformSinkConfig(
            base_url="https://test.safetycli.com",
            timeout=45,
            http_client=mock_client,
        )

        # This should not raise ImportError
        sink = build_sink(config, mock_callbacks)

        assert isinstance(sink, SafetyPlatformSink)
        assert sink.http_client == mock_client
        assert sink.callbacks == mock_callbacks
