from rich.text import Text

from .base import BaseComponent
from ..models import CONNECTION_STYLES


class HeaderComponent(BaseComponent):
    """
    Renders the header section with organization info and connection status.
    """

    def render(self) -> Text:
        """
        Example:
        Safety Cybersecurity › yeison@safetycli.com             ● Streaming
        """
        left = f"{self.state.organization} › {self.state.user_email}"
        status, color = CONNECTION_STYLES[self.state.connection]
        padding = self.width - len(left) - len(status)

        t = Text("  ")
        t.append(self.state.organization)
        t.append(" › ", style="dim")
        t.append(self.state.user_email)
        t.append(" " * max(padding, 1))
        t.append(status, style=color)
        return t


class ScanInfoComponent(BaseComponent):
    """
    Renders scan ID and elapsed time.
    """

    def render(self) -> Text:
        """
        Scan a7Xk9-3Qm2                                    00:12
        """
        scan_id = self.state.scan_id or "—"
        elapsed = self.state.format_elapsed()
        left = f"Scan {scan_id}"
        padding = self.width - len(left) - len(elapsed)

        t = Text("  ")
        t.append("Scan ", style="dim")
        t.append(scan_id)
        t.append(" " * max(padding, 1))
        t.append(elapsed, style="dim")
        return t


class TitleComponent(BaseComponent):
    """
    Renders the main title.
    """

    def render(self) -> Text:
        """
        Supply Chain Asset Discovery
        """
        t = Text("  ")
        t.append("Supply Chain Asset Discovery", style="bold")
        return t


class SubtitleComponent(BaseComponent):
    """
    Renders the current action.
    """

    def render(self) -> Text:
        """
        Example:
        Scanning for secrets...
        """
        t = Text("  ")
        t.append(self.state.phase_display, style="dim")
        return t
