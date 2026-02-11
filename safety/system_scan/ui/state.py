from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque


from .models import Asset, LogEntry, LogLevel, ConnectionState


@dataclass
class ScanState:
    """
    Centralized UI state. All fields are updated via callbacks.
    Rich Live renders this state periodically (10fps).

    Thread-safety: All mutations happen on main thread via callbacks,
    Rich Live reads from background thread. Python's GIL makes
    simple attribute reads/writes atomic enough for our purposes.
    """

    # --- Header ---
    organization: str = ""
    user_email: str = ""
    connection: ConnectionState = ConnectionState.CONNECTING

    # --- Scan Info ---
    scan_id: str | None = None
    start_time: datetime | None = None
    completion_time: datetime | None = None

    # --- Subtitle ---
    action: str = "Initializing scanner..."

    # --- Progress ---
    progress_current: int = 0
    progress_total: int = 0

    # --- Metrics ---
    contexts: int = 0
    runtimes: int = 0
    environments: int = 0
    dependencies: int = 0
    tools: int = 0

    # --- Discoveries ---
    discoveries: Deque[Asset] = field(default_factory=lambda: deque(maxlen=400))

    # --- Log ---
    logs: Deque[LogEntry] = field(default_factory=lambda: deque(maxlen=5))

    # --- Footer ---
    sent: int = 0
    queued: int = 0

    # --- Queue pressure ---
    queue_pressure: str = "low"  # low, medium, high, critical
    queue_max: int = 0
    backend_status: str = "normal"  # normal, slow, issues

    # --- App info ---
    version: str = "v1.0"

    # --- Completion state ---
    is_completed: bool = False
    completion_countdown: int = 10

    # --- Rich Live reference (set externally) ---
    _live: Any | None = field(default=None, repr=False)

    # === Computed Properties ===

    @property
    def total_discovered(self) -> int:
        """
        Total number of discovered assets.
        """
        return (
            self.contexts
            + self.runtimes
            + self.environments
            + self.dependencies
            + self.tools
        )

    @property
    def elapsed(self) -> float:
        """
        Elapsed seconds since scan start.
        """
        if not self.start_time:
            return 0.0

        # If completed, use completion time; otherwise use current time
        if self.is_completed and self.completion_time:
            reference_time = self.completion_time
        else:
            reference_time = datetime.now()

        return (reference_time - self.start_time).total_seconds()

    def format_elapsed(self) -> str:
        total = int(self.elapsed)
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    @property
    def phase_display(self) -> str:
        phase_map = {
            "init": "Initializing scanner...",
            "sink_open": "Requesting a scan id from Safety Platform...",
            "working": "Discovering assets...",
            "complete": "Scan complete",
        }
        return phase_map.get(self.action, self.action)

    # === Mutators (called by callbacks) ===

    def increment_asset_count(self, asset_kind: str) -> None:
        """Increment counter for the given asset kind."""
        if asset_kind == "execution_context" or asset_kind == "context":
            self.contexts += 1
        elif asset_kind == "runtime":
            self.runtimes += 1
        elif asset_kind == "environment":
            self.environments += 1
        elif asset_kind == "dependency":
            self.dependencies += 1
        elif asset_kind == "tool":
            self.tools += 1

    def add_asset(self, asset: Asset) -> None:
        """Add discovered asset and update counts."""
        self.discoveries.append(asset)
        self.increment_asset_count(asset.kind.value)
        self._refresh()

    def set_phase(self, phase: str) -> None:
        self.action = phase
        self._refresh()

    def set_progress(self, current: int, total: int) -> None:
        self.progress_current = current
        self.progress_total = total
        # Don't refresh on every progress tick - let timer handle it

    def set_connection(self, status: ConnectionState) -> None:
        self.connection = status
        if status == ConnectionState.DISCONNECTED:
            self.log(LogLevel.ERROR, "Connection lost")
        elif status == ConnectionState.RECONNECTING:
            self.log(LogLevel.WARNING, "Reconnecting...")
        elif status == ConnectionState.COMPLETE:
            self.log(
                LogLevel.SUCCESS, f"Scan complete — {self.total_discovered} assets"
            )
        self._refresh()

    def log(self, level: LogLevel, message: str, path: str = "") -> None:
        from datetime import timedelta

        entry = LogEntry(
            level=level,
            message=message,
            elapsed=timedelta(seconds=self.elapsed),
        )
        self.logs.append(entry)
        self._refresh()

    def batch_sent(self, count: int) -> None:
        self.sent += count
        self.queued = max(0, self.queued - count)
        self.log(LogLevel.SUCCESS, f"Batch sent ({count} assets)")

    def batch_queued(self, total_queued: int) -> None:
        self.queued = total_queued

    def queue_pressure_changed(
        self, pressure: str, current: int, max_size: int
    ) -> None:
        self.queue_pressure = pressure
        self.queue_max = max_size

        # Update backend status based on pressure
        if pressure == "critical":
            self.backend_status = "slow"
            self.log(
                LogLevel.ERROR,
                f"Slow ingestion - queue at {current}/{max_size} ({int(current / max_size * 100)}%)",
            )
        elif pressure == "high":
            self.backend_status = "slow"
            self.log(
                LogLevel.WARNING,
                f"Slow ingestion - queue building up ({int(current / max_size * 100)}%)",
            )
        elif pressure == "medium":
            self.backend_status = "normal"
            if hasattr(self, "_last_pressure") and self._last_pressure in [
                "high",
                "critical",
            ]:
                self.log(LogLevel.INFO, "Ingestion performance improving")
        else:  # low
            self.backend_status = "normal"

        self._last_pressure = pressure
        self._refresh()

    def set_live(self, live: Any) -> None:
        self._live = live

    def complete_scan(self) -> None:
        self.is_completed = True
        self.completion_time = datetime.now()  # Freeze the timer
        self.action = "complete"  # This will show "Scan complete" in subtitle
        self.set_connection(ConnectionState.COMPLETE)
        self._refresh()

    def update_countdown(self, seconds_remaining: int) -> None:
        self.completion_countdown = seconds_remaining
        self._refresh()

    def _refresh(self) -> None:
        try:
            if self._live:
                from .renderer import render_tui

                self._live.update(render_tui(self))
        except Exception:
            pass

    def _format_duration_for_display(self) -> str:
        """Format elapsed time as HH:MM:SS or MM:SS."""
        total = int(self.elapsed)
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    def format_plain_summary(self, include_breakdown: bool = False) -> str:
        """
        Generate plain text summary for terminal output.

        Args:
            include_breakdown: Whether to include asset breakdown by type

        Returns:
            Formatted summary string
        """
        lines = [
            "Safety System Scan Complete ✓",
            "",
            f"  Scan ID:        {self.scan_id or 'N/A'}",
            f"  Organization:   {self.organization}",
            f"  Duration:       {self._format_duration_for_display()}",
            "",
        ]

        if include_breakdown:
            lines.extend(
                [
                    "  Assets Discovered:",
                    f"    • {self.dependencies} Dependencies",
                    f"    • {self.runtimes} Runtimes",
                    f"    • {self.environments} Environments",
                    f"    • {self.contexts} Contexts",
                    f"    • {self.tools} Tools",
                    "",
                ]
            )

        lines.append(f"  Total: {self.total_discovered} assets sent to Safety Platform")

        return "\n".join(lines)

    def format_plain_summary_with_breakdown(self) -> str:
        """
        Generate plain text summary with asset breakdown for interactive mode.

        Returns:
            Formatted summary string with breakdown by asset type.
        """
        return self.format_plain_summary(include_breakdown=True)
