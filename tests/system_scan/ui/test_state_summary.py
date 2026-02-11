from __future__ import annotations

import pytest
from datetime import datetime

from safety.system_scan.ui.state import ScanState


@pytest.mark.unit
class TestScanStateSummary:
    """Test ScanState summary formatting functionality."""

    def test_format_plain_summary_with_breakdown_complete_data(self):
        """Test summary formatting with all data present."""
        start_time = datetime(2024, 1, 1, 12, 0, 0)
        completion_time = datetime(2024, 1, 1, 12, 2, 30)  # 2:30 duration

        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=start_time,
            completion_time=completion_time,
            is_completed=True,
            contexts=1,
            runtimes=3,
            environments=2,
            dependencies=15,
            tools=5,
        )

        result = state.format_plain_summary_with_breakdown()

        expected_lines = [
            "Safety System Scan Complete ✓",
            "",
            "  Scan ID:        test-scan-123",
            "  Organization:   Test Org",
            "  Duration:       02:30",
            "",
            "  Assets Discovered:",
            "    • 15 Dependencies",
            "    • 3 Runtimes",
            "    • 2 Environments",
            "    • 1 Contexts",
            "    • 5 Tools",
            "",
            "  Total: 26 assets sent to Safety Platform",
        ]
        expected = "\n".join(expected_lines)

        assert result == expected

    def test_format_plain_summary_with_breakdown_missing_scan_id(self):
        """Test summary formatting when scan_id is None."""
        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id=None,
            start_time=datetime.now(),
        )

        result = state.format_plain_summary_with_breakdown()

        assert "  Scan ID:        N/A" in result

    def test_format_plain_summary_with_breakdown_zero_discoveries(self):
        """Test summary formatting with no assets found."""
        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=datetime.now(),
            contexts=0,
            runtimes=0,
            environments=0,
            dependencies=0,
            tools=0,
        )

        result = state.format_plain_summary_with_breakdown()

        assert "    • 0 Dependencies" in result
        assert "    • 0 Runtimes" in result
        assert "    • 0 Environments" in result
        assert "    • 0 Contexts" in result
        assert "    • 0 Tools" in result
        assert "  Total: 0 assets sent to Safety Platform" in result

    def test_format_plain_summary_includes_duration(self):
        """Test that summary includes properly formatted duration."""
        start_time = datetime(2024, 1, 1, 12, 0, 0)
        completion_time = datetime(2024, 1, 1, 13, 1, 5)  # 1:01:05 duration

        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=start_time,
            completion_time=completion_time,
            is_completed=True,
        )

        result = state.format_plain_summary_with_breakdown()

        assert "  Duration:       1:01:05" in result

    def test_format_plain_summary_asset_counts_match_total_discovered(self):
        """Test that individual counts add up to total_discovered."""
        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=datetime.now(),
            contexts=2,
            runtimes=4,
            environments=3,
            dependencies=10,
            tools=1,
        )

        result = state.format_plain_summary_with_breakdown()

        # Total should be 2+4+3+10+1 = 20
        assert "  Total: 20 assets sent to Safety Platform" in result
        assert state.total_discovered == 20

    def test_format_plain_summary_without_breakdown(self):
        """Test summary formatting without breakdown for non-interactive mode."""
        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=datetime(2024, 1, 1, 12, 0, 0),
            completion_time=datetime(2024, 1, 1, 12, 2, 30),  # 2:30 duration
            is_completed=True,
            dependencies=15,
        )

        result = state.format_plain_summary(include_breakdown=False)

        assert "Safety System Scan Complete ✓" in result
        assert "test-scan-123" in result
        assert "Test Org" in result
        assert "02:30" in result
        assert "Total: 15 assets sent to Safety Platform" in result
        # Should NOT have breakdown
        assert "Assets Discovered:" not in result
        assert "Dependencies" not in result

    def test_format_plain_summary_with_breakdown_flag(self):
        """Test summary formatting with breakdown flag set to True."""
        state = ScanState(
            organization="Test Org",
            user_email="test@example.com",
            scan_id="test-scan-123",
            start_time=datetime.now(),
            dependencies=5,
            runtimes=2,
        )

        result = state.format_plain_summary(include_breakdown=True)

        assert "Assets Discovered:" in result
        assert "5 Dependencies" in result
        assert "2 Runtimes" in result
