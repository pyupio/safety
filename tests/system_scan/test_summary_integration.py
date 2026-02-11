from __future__ import annotations

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from safety.system_scan.main import run_non_interactive, run_interactive
from safety.system_scan.ui.main import live
from safety.system_scan.ui.state import ScanState


@pytest.mark.unit
class TestSummaryIntegration:
    """Integration tests for summary functionality across different modes."""

    @patch("safety.system_scan.main.SystemScanner")
    @patch("safety.system_scan.main.console")
    def test_run_non_interactive_prints_summary(
        self, mock_console: Mock, mock_scanner_class: Mock
    ):
        """Test that run_non_interactive prints summary with correct data."""
        # Setup
        mock_auth = Mock()
        mock_auth.org_name = "Test Organization"
        mock_config = Mock()
        mock_sink_cfg = Mock()

        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner

        # Execute
        run_non_interactive(auth=mock_auth, config=mock_config, sink_cfg=mock_sink_cfg)

        # Verify scanner was called with callbacks
        mock_scanner_class.assert_called_once()
        args, kwargs = mock_scanner_class.call_args
        assert "callbacks" in kwargs
        assert kwargs["callbacks"] is not None

        # Verify summary was printed
        assert mock_console.print.call_count == 3  # Empty line, summary, empty line
        summary_call = mock_console.print.call_args_list[
            1
        ]  # Middle call has the summary
        printed_content = summary_call[0][0]
        assert "Safety System Scan Complete ✓" in printed_content
        assert "Test Organization" in printed_content
        assert "Total: 0 assets sent to Safety Platform" in printed_content

    @patch("safety.system_scan.main.SystemScanner")
    @patch("safety.system_scan.main.console")
    def test_run_non_interactive_handles_missing_org_name(
        self, mock_console: Mock, mock_scanner_class: Mock
    ):
        """Test that run_non_interactive handles None org_name gracefully."""
        # Setup
        mock_auth = Mock()
        mock_auth.org_name = None  # Simulate missing org name
        mock_config = Mock()
        mock_sink_cfg = Mock()

        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner

        # Execute
        run_non_interactive(auth=mock_auth, config=mock_config, sink_cfg=mock_sink_cfg)

        # Verify fallback was used
        assert mock_console.print.call_count == 3  # Empty line, summary, empty line
        summary_call = mock_console.print.call_args_list[
            1
        ]  # Middle call has the summary
        printed_content = summary_call[0][0]
        assert "Unknown" in printed_content

    @patch("safety.system_scan.ui.main.Live")
    @patch("safety.system_scan.ui.main.console")
    def test_live_prints_summary_after_completion(
        self, mock_console: Mock, mock_live_class: Mock
    ):
        """Test that live() prints summary after TUI exits when scan is completed."""
        # Setup
        mock_live_instance = Mock()
        mock_live_class.return_value.__enter__ = Mock(return_value=mock_live_instance)
        mock_live_class.return_value.__exit__ = Mock(return_value=None)

        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=datetime.now(),
            is_completed=True,
            dependencies=5,
            runtimes=2,
        )

        mock_scan_fn = Mock()

        # Execute
        live(system_scan_fn=mock_scan_fn, state=state)

        # Verify summary was printed
        assert mock_console.print.call_count == 3  # Empty line, summary, empty line
        summary_call = mock_console.print.call_args_list[
            1
        ]  # Middle call has the summary
        printed_content = summary_call[0][0]
        assert "Safety System Scan Complete ✓" in printed_content
        assert "test-scan-123" in printed_content
        assert "Test Org" in printed_content
        assert "5 Dependencies" in printed_content
        assert "2 Runtimes" in printed_content

    @patch("safety.system_scan.ui.main.Live")
    @patch("safety.system_scan.ui.main.console")
    def test_live_prints_summary_on_keyboard_interrupt_if_completed(
        self, mock_console: Mock, mock_live_class: Mock
    ):
        """Test that live() prints summary on KeyboardInterrupt if scan completed."""

        # Setup - simulate KeyboardInterrupt during countdown
        def side_effect(*args, **kwargs):
            raise KeyboardInterrupt()

        mock_live_instance = Mock()
        mock_live_class.return_value.__enter__ = Mock(return_value=mock_live_instance)
        mock_live_class.return_value.__exit__ = Mock(return_value=None)

        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=datetime.now(),
            is_completed=True,
        )

        # Mock time.sleep to raise KeyboardInterrupt
        with patch("time.sleep", side_effect=side_effect):
            with pytest.raises(KeyboardInterrupt):
                live(system_scan_fn=Mock(), state=state)

        # Verify summary was still printed
        assert mock_console.print.call_count == 3  # Empty line, summary, empty line
        summary_call = mock_console.print.call_args_list[
            1
        ]  # Middle call has the summary
        printed_content = summary_call[0][0]
        assert "Safety System Scan Complete ✓" in printed_content

    @patch("safety.system_scan.ui.main.Live")
    @patch("safety.system_scan.ui.main.console")
    def test_live_does_not_print_summary_if_not_completed(
        self, mock_console: Mock, mock_live_class: Mock
    ):
        """Test that live() does not print summary if scan not completed."""
        # Setup
        mock_live_instance = Mock()
        mock_live_class.return_value.__enter__ = Mock(return_value=mock_live_instance)
        mock_live_class.return_value.__exit__ = Mock(return_value=None)

        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            is_completed=False,  # Not completed
        )

        mock_scan_fn = Mock()

        # Execute
        live(system_scan_fn=mock_scan_fn, state=state)

        # Verify summary was NOT printed
        mock_console.print.assert_not_called()

    @patch("safety.system_scan.main.live")
    @patch("safety.system_scan.main.SystemScanner")
    def test_run_interactive_passes_correct_parameters(
        self, mock_scanner_class: Mock, mock_live: Mock
    ):
        """Test that run_interactive sets up state and calls live correctly."""
        # Setup
        mock_auth = Mock()
        mock_auth.org_name = "Interactive Org"
        mock_auth.email = "user@example.com"
        mock_config = Mock()
        mock_sink_cfg = Mock()

        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner

        # Execute
        run_interactive(auth=mock_auth, config=mock_config, sink_cfg=mock_sink_cfg)

        # Verify live was called with correct parameters
        mock_live.assert_called_once()
        args, kwargs = mock_live.call_args

        assert "system_scan_fn" in kwargs
        assert "state" in kwargs

        state = kwargs["state"]
        assert state.organization == "Interactive Org"
        assert state.user_email == "user@example.com"
        assert isinstance(state.start_time, datetime)
