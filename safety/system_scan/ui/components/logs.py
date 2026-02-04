from datetime import timedelta

from rich.text import Text

from .base import BaseComponent
from ..models import LogEntry, LOG_STYLES


def format_timestamp(td: timedelta) -> str:
    """
    Format timedelta as MM:SS.
    """
    total = int(td.total_seconds())
    m, s = divmod(total, 60)
    return f"{m:02d}:{s:02d}"


class LogRowComponent(BaseComponent):
    """
    Renders a single log entry.
    """

    def __init__(self, entry: LogEntry, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.entry = entry

    def render(self) -> Text:
        """
        Example:
        ✓ Batch sent (5 assets)                                          00:11
        """
        symbol, color = LOG_STYLES[self.entry.level]
        ts = format_timestamp(self.entry.elapsed)
        used = 2 + 2 + len(self.entry.message)
        padding = self.width - used - len(ts)

        t = Text("  ")
        t.append(f"{symbol} ", style=color)
        t.append(self.entry.message)
        t.append(" " * max(padding, 1))
        t.append(ts, style="dim")
        return t


class LogsComponent(BaseComponent):
    """
    Renders the logs section.
    """

    MAX_LOGS = 3

    def render(self) -> Text:
        """
        Render log entries.
        """
        lines: list[Text] = []
        # Convert deque to list and slice
        all_logs = list(self.state.logs)
        recent_logs = all_logs[-self.MAX_LOGS :]

        for entry in recent_logs:
            row_component = LogRowComponent(entry, self.state, self.console)
            lines.append(row_component.render())

        # Pad to maintain consistent height
        while len(lines) < self.MAX_LOGS:
            lines.append(Text(""))

        t = Text()
        for i, line in enumerate(lines):
            t.append_text(line)
            if i < len(lines) - 1:
                t.append("\n")
        return t
