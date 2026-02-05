from __future__ import annotations

import pytest
import subprocess
import sys
from unittest.mock import Mock, patch
from datetime import datetime

import typer

from safety.system_scan.main import (
    run_non_interactive,
    run_in_background,
    run_interactive,
)


@pytest.mark.unit
class TestRunNonInteractive:
    """
    Test run_non_interactive function.
    """

    @patch("safety.system_scan.main.SystemScanner")
    @patch("safety.system_scan.main.console")
    def test_run_non_interactive_creates_scanner_and_runs(
        self, mock_console: Mock, mock_scanner_class: Mock
    ) -> None:
        """
        Test run_non_interactive creates scanner and calls run.
        """
        mock_auth = Mock()
        mock_config = Mock()
        mock_sink_cfg = Mock()
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner

        run_non_interactive(auth=mock_auth, config=mock_config, sink_cfg=mock_sink_cfg)

        # Verify scanner was called with config, sink_cfg, and callbacks
        mock_scanner_class.assert_called_once()
        args, kwargs = mock_scanner_class.call_args
        assert kwargs["config"] == mock_config
        assert kwargs["sink_cfg"] == mock_sink_cfg
        assert "callbacks" in kwargs
        assert kwargs["callbacks"] is not None
        mock_scanner.run.assert_called_once()

        # Verify summary was printed
        assert mock_console.print.call_count == 3  # Empty line, summary, empty line


@pytest.mark.unit
class TestRunInBackground:
    """
    Test run_in_background function.
    """

    @pytest.fixture
    def mock_context(self) -> Mock:
        """
        Mock typer context with parameters.
        """
        ctx = Mock(spec=typer.Context)
        ctx.params = {
            "sink": "platform",
            "platform_url": "https://test.example.com",
            "jsonl_path": "/test/path",
            "background": False,
        }
        return ctx

    @pytest.fixture
    def mock_context_no_params(self) -> Mock:
        """
        Mock typer context with no parameters.
        """
        ctx = Mock(spec=typer.Context)
        ctx.params = None
        return ctx

    @patch("safety.system_scan.main.subprocess.Popen")
    @patch("safety.system_scan.main.platform.system")
    @patch(
        "safety.system_scan.main.subprocess.CREATE_NEW_PROCESS_GROUP", 512, create=True
    )
    def test_run_in_background_windows_creates_process_group(
        self, mock_platform: Mock, mock_popen: Mock, mock_context: Mock
    ) -> None:
        """
        Test run_in_background creates new process group on Windows.
        """
        mock_platform.return_value = "Windows"
        mock_proc = Mock()
        mock_popen.return_value = mock_proc

        result = run_in_background(mock_context)

        assert result == mock_proc
        expected_args = [
            sys.executable,
            "-m",
            "safety",
            "system-scan",
            "run",
            "--sink",
            "platform",
            "--platform-url",
            "https://test.example.com",
            "--jsonl-path",
            "/test/path",
        ]
        mock_popen.assert_called_once_with(
            expected_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=512,
        )

    @patch("safety.system_scan.main.subprocess.Popen")
    @patch("safety.system_scan.main.platform.system")
    def test_run_in_background_unix_starts_new_session(
        self, mock_platform: Mock, mock_popen: Mock, mock_context: Mock
    ) -> None:
        """
        Test run_in_background starts new session on Unix.
        """
        mock_platform.return_value = "Linux"
        mock_proc = Mock()
        mock_popen.return_value = mock_proc

        result = run_in_background(mock_context)

        assert result == mock_proc
        expected_args = [
            sys.executable,
            "-m",
            "safety",
            "system-scan",
            "run",
            "--sink",
            "platform",
            "--platform-url",
            "https://test.example.com",
            "--jsonl-path",
            "/test/path",
        ]
        mock_popen.assert_called_once_with(
            expected_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

    @patch("safety.system_scan.main.subprocess.Popen")
    @patch("safety.system_scan.main.platform.system")
    def test_run_in_background_no_params(
        self, mock_platform: Mock, mock_popen: Mock, mock_context_no_params: Mock
    ) -> None:
        """
        Test run_in_background handles None parameters.
        """
        mock_platform.return_value = "Linux"
        mock_proc = Mock()
        mock_popen.return_value = mock_proc

        result = run_in_background(mock_context_no_params)

        assert result == mock_proc
        expected_args = [sys.executable, "-m", "safety", "system-scan", "run"]
        mock_popen.assert_called_once_with(
            expected_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

    @patch("safety.system_scan.main.subprocess.Popen")
    @patch("safety.system_scan.main.platform.system")
    def test_run_in_background_filters_background_param(
        self, mock_platform: Mock, mock_popen: Mock
    ) -> None:
        """
        Test run_in_background excludes background parameter from command.
        """
        mock_platform.return_value = "Linux"
        mock_proc = Mock()
        mock_popen.return_value = mock_proc

        ctx = Mock(spec=typer.Context)
        ctx.params = {
            "background": True,  # Should be excluded
            "sink": "jsonl",
        }

        result = run_in_background(ctx)

        assert result == mock_proc
        expected_args = [
            sys.executable,
            "-m",
            "safety",
            "system-scan",
            "run",
            "--sink",
            "jsonl",
        ]
        mock_popen.assert_called_once_with(
            expected_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

    @patch("safety.system_scan.main.subprocess.Popen")
    @patch("safety.system_scan.main.platform.system")
    def test_run_in_background_handles_boolean_flags(
        self, mock_platform: Mock, mock_popen: Mock
    ) -> None:
        """
        Test run_in_background handles boolean parameters correctly.
        """
        mock_platform.return_value = "Linux"
        mock_proc = Mock()
        mock_popen.return_value = mock_proc

        ctx = Mock(spec=typer.Context)
        ctx.params = {
            "verbose": True,  # Should become --verbose
            "quiet": False,  # Should be ignored
            "sink": "platform",  # Should become --sink platform
        }

        result = run_in_background(ctx)

        assert result == mock_proc
        expected_args = [
            sys.executable,
            "-m",
            "safety",
            "system-scan",
            "run",
            "--verbose",
            "--sink",
            "platform",
        ]
        mock_popen.assert_called_once_with(
            expected_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

    @patch("safety.system_scan.main.subprocess.Popen")
    @patch("safety.system_scan.main.platform.system")
    def test_run_in_background_raises_on_subprocess_error(
        self, mock_platform: Mock, mock_popen: Mock, mock_context: Mock
    ) -> None:
        """
        Test run_in_background raises OSError when subprocess fails.
        """
        mock_platform.return_value = "Linux"
        mock_popen.side_effect = OSError("Failed to start process")

        with pytest.raises(OSError, match="Failed to start background process"):
            run_in_background(mock_context)


@pytest.mark.unit
class TestRunInteractive:
    """
    Test run_interactive function.
    """

    @patch("safety.system_scan.main.live")
    @patch("safety.system_scan.main.SystemScanner")
    @patch("safety.system_scan.main.CliSafetyPlatformSinkCallbacks")
    @patch("safety.system_scan.main.CliCallbacks")
    @patch("safety.system_scan.main.ScanState")
    @patch("safety.system_scan.main.datetime")
    def test_run_interactive_creates_state_and_scanner(
        self,
        mock_datetime: Mock,
        mock_scan_state: Mock,
        mock_cli_callbacks: Mock,
        mock_sink_callbacks: Mock,
        mock_scanner_class: Mock,
        mock_live: Mock,
    ) -> None:
        """
        Test run_interactive sets up state, callbacks and runs scanner.
        """
        mock_auth = Mock()
        mock_auth.org_name = "Test Org"
        mock_auth.email = "test@example.com"
        mock_config = Mock()
        mock_sink_cfg = Mock()

        mock_now = datetime(2025, 1, 28, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        mock_state = Mock()
        mock_scan_state.return_value = mock_state

        mock_callbacks = Mock()
        mock_cli_callbacks.return_value = mock_callbacks

        mock_sink_cb = Mock()
        mock_sink_callbacks.return_value = mock_sink_cb

        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner

        run_interactive(auth=mock_auth, config=mock_config, sink_cfg=mock_sink_cfg)

        # Verify state creation
        mock_scan_state.assert_called_once_with(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="Requesting a scan id...",
            start_time=mock_now,
        )

        # Verify callbacks creation
        mock_sink_callbacks.assert_called_once_with(state=mock_state)
        mock_cli_callbacks.assert_called_once_with(state=mock_state)

        # Verify scanner creation
        mock_scanner_class.assert_called_once_with(
            config=mock_config,
            sink_cfg=mock_sink_cfg,
            callbacks=mock_callbacks,
            sink_callbacks=mock_sink_cb,
        )

        # Verify live UI is called
        mock_live.assert_called_once_with(
            system_scan_fn=mock_scanner.run, state=mock_state
        )

    @patch("safety.system_scan.main.live")
    @patch("safety.system_scan.main.SystemScanner")
    @patch("safety.system_scan.main.CliSafetyPlatformSinkCallbacks")
    @patch("safety.system_scan.main.CliCallbacks")
    @patch("safety.system_scan.main.ScanState")
    @patch("safety.system_scan.main.datetime")
    def test_run_interactive_handles_none_auth_fields(
        self,
        mock_datetime: Mock,
        mock_scan_state: Mock,
        mock_cli_callbacks: Mock,
        mock_sink_callbacks: Mock,
        mock_scanner_class: Mock,
        mock_live: Mock,
    ) -> None:
        """
        Test run_interactive handles None auth fields gracefully.
        """
        mock_auth = Mock()
        mock_auth.org_name = None
        mock_auth.email = None
        mock_config = Mock()
        mock_sink_cfg = Mock()

        mock_now = datetime(2025, 1, 28, 12, 0, 0)
        mock_datetime.now.return_value = mock_now

        run_interactive(auth=mock_auth, config=mock_config, sink_cfg=mock_sink_cfg)

        # Verify state creation with default values
        mock_scan_state.assert_called_once_with(
            organization="Unknown",
            user_email="Unknown",
            scan_id="Requesting a scan id...",
            start_time=mock_now,
        )
