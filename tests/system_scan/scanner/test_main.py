import pytest
from unittest.mock import Mock, patch
from typing import cast

from safety.system_scan.scanner.main import SystemScanner
from safety.system_scan.scanner.context import Config
from safety.system_scan.scanner.callbacks import NullCallbacks
from safety.system_scan.scanner.sinks import NullSinkConfig


@pytest.mark.unit
class TestSystemScanner:
    """
    Test SystemScanner initialization and core functionality.
    """

    @pytest.fixture
    def config(self) -> Config:
        """
        Minimal valid configuration.
        """
        return Config(max_depth=3, prune_dirs=[".git"])

    @pytest.fixture
    def scanner(self, config: Config) -> SystemScanner:
        """
        Basic scanner instance.
        """
        mock_callbacks = Mock()
        return SystemScanner(config=config, callbacks=mock_callbacks)

    def test_init_with_minimal_config(self, config: Config) -> None:
        """
        Test scanner initialization with minimal configuration.
        """
        scanner = SystemScanner(config=config)

        assert scanner.config == config
        assert isinstance(scanner.callbacks, NullCallbacks)
        assert isinstance(scanner.sink_cfg, NullSinkConfig)
        assert scanner.detectors is None
        assert scanner.stages is None

    def test_init_with_custom_components(self, config: Config) -> None:
        """
        Test scanner initialization with custom components.
        """
        mock_callbacks = Mock()
        mock_sink_cfg = Mock()
        mock_detectors = [Mock()]
        mock_stages = [Mock()]

        scanner = SystemScanner(
            config=config,
            callbacks=mock_callbacks,
            sink_cfg=mock_sink_cfg,
            detectors=mock_detectors,
            stages=mock_stages,
        )

        assert scanner.callbacks == mock_callbacks
        assert scanner.sink_cfg == mock_sink_cfg
        assert scanner.detectors == mock_detectors
        assert scanner.stages == mock_stages

    @patch("safety.system_scan.scanner.main.ExecutionContextDetector")
    def test_build_fails_when_no_execution_context(
        self, mock_detector: Mock, scanner: SystemScanner
    ) -> None:
        """
        Test build fails gracefully when execution context detection fails.
        """
        mock_instance = mock_detector.return_value
        mock_instance.detect.return_value = []

        with pytest.raises(RuntimeError, match="Failed to detect execution context"):
            scanner.build()

        cast(Mock, scanner.callbacks).error.assert_called_once()

    @patch("safety.system_scan.scanner.main.ExecutionContextDetector")
    @patch("safety.system_scan.scanner.main.build_sink")
    @patch("safety.system_scan.scanner.main.PythonDependencyDetector")
    @patch("safety.system_scan.scanner.main.PythonRuntimeDetector")
    @patch("safety.system_scan.scanner.main.PythonEnvironmentDetector")
    @patch("safety.system_scan.scanner.main.ToolDetector")
    def test_build_success(
        self,
        mock_tool_detector: Mock,
        mock_env_detector: Mock,
        mock_runtime_detector: Mock,
        mock_dep_detector: Mock,
        mock_build_sink: Mock,
        mock_exec_detector: Mock,
        scanner: SystemScanner,
    ) -> None:
        """
        Test successful build with execution context.
        """
        # Mock execution context detection
        mock_detection = Mock()
        mock_detection.meta.machine_id = "test-machine"
        mock_detection.meta.hostname = "test-host"
        mock_exec_detector.return_value.detect.return_value = [mock_detection]

        mock_sink = Mock()
        mock_build_sink.return_value = mock_sink

        stages, sink, exec_ctx_detection = scanner.build()

        assert len(stages) == 2  # CandidatesStage, DetectStageSerial
        assert sink == mock_sink
        assert exec_ctx_detection == mock_detection

        # Verify detectors are instantiated
        mock_dep_detector.assert_called_once()
        mock_tool_detector.assert_called_once()
        mock_runtime_detector.assert_called_once()
        mock_env_detector.assert_called_once()

    @patch("safety.system_scan.scanner.main.ExecutionContextDetector")
    @patch("safety.system_scan.scanner.main.build_sink")
    @patch("safety.system_scan.scanner.main.run_pipeline")
    def test_run_success(
        self,
        mock_pipeline: Mock,
        mock_build_sink: Mock,
        mock_exec_detector: Mock,
        scanner: SystemScanner,
    ) -> None:
        """
        Test successful scanner run workflow.
        """
        # Mock execution context detection
        mock_detection = Mock()
        mock_detection.meta.machine_id = "test-machine"
        mock_detection.meta.hostname = "test-host"
        mock_exec_detector.return_value.detect.return_value = [mock_detection]

        # Mock sink
        mock_sink = Mock()
        mock_sink.open.return_value = "scan-123"
        mock_build_sink.return_value = mock_sink

        # Mock pipeline detections
        mock_detections = [Mock(), Mock(), Mock()]
        mock_pipeline.return_value = iter(mock_detections)

        scanner.run()

        # Verify workflow
        cast(Mock, scanner.callbacks).phase.assert_any_call("init")
        cast(Mock, scanner.callbacks).phase.assert_any_call("sink_open")
        cast(Mock, scanner.callbacks).phase.assert_any_call("working")

        mock_sink.open.assert_called_once_with(
            machine_id="test-machine", hostname="test-host"
        )

        cast(Mock, scanner.callbacks).scan_id.assert_called_once_with(
            scan_id="scan-123"
        )

        # Verify detections are processed
        assert (
            cast(Mock, scanner.callbacks).detection.call_count == 4
        )  # exec_ctx + 3 detections
        assert mock_sink.write.call_count == 4  # exec_ctx + 3 detections

        cast(Mock, scanner.callbacks).complete.assert_called_once()
        mock_sink.close.assert_called_once_with(ok=True)

    @patch("safety.system_scan.scanner.main.ExecutionContextDetector")
    @patch("safety.system_scan.scanner.main.build_sink")
    @patch("safety.system_scan.scanner.main.run_pipeline")
    def test_run_handles_pipeline_exception(
        self,
        mock_pipeline: Mock,
        mock_build_sink: Mock,
        mock_exec_detector: Mock,
        scanner: SystemScanner,
    ) -> None:
        """
        Test scanner handles pipeline exceptions gracefully.
        """
        # Mock execution context detection
        mock_detection = Mock()
        mock_detection.meta.machine_id = "test-machine"
        mock_detection.meta.hostname = "test-host"
        mock_exec_detector.return_value.detect.return_value = [mock_detection]

        # Mock sink
        mock_sink = Mock()
        mock_sink.open.return_value = "scan-123"
        mock_build_sink.return_value = mock_sink

        # Mock pipeline to raise exception
        mock_pipeline.return_value = iter([Mock()])

        def raise_exception():
            yield Mock()
            raise ValueError("Pipeline error")

        mock_pipeline.return_value = raise_exception()

        with pytest.raises(ValueError, match="Pipeline error"):
            scanner.run()

        # Verify sink is closed with ok=False
        mock_sink.close.assert_called_once_with(ok=False)

        # Verify complete callback is still called
        cast(Mock, scanner.callbacks).complete.assert_called_once()
