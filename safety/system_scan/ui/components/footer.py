from rich.text import Text

from .base import BaseComponent


class SeparatorComponent(BaseComponent):
    """
    Renders a horizontal line separator.
    """

    def render(self) -> Text:
        return Text("  " + "─" * self.width, style="dim")


class FooterComponent(BaseComponent):
    """
    Renders the footer with statistics and controls.
    """

    def render(self) -> Text:
        """
        Example:
        13 sent · 2 queued                  [q] Quit  [?] Help
        or when completed:
        ✓ Completed • CTRL+C to close or will exit in 45 seconds
        """
        t = Text("  ")

        if self.state.is_completed:
            # Show completion message with countdown
            completion_msg = f"✓ Completed • CTRL+C to close or will exit in {self.state.completion_countdown} seconds"
            # Center the completion message
            padding = max(0, (self.width - len(completion_msg) - 4) // 2)
            t.append(" " * padding)
            t.append("✓ Completed", style="green bold")
            t.append(" • CTRL+C to close or will exit in ", style="dim")
            t.append(f"{self.state.completion_countdown}", style="yellow")
            t.append(" seconds", style="dim")
        else:
            # Show normal footer with queue pressure indication
            stats = f"{self.state.sent} sent · {self.state.queued} queued"

            # Add queue pressure indicator
            pressure_indicator = ""
            pressure_style = "dim"

            if self.state.queue_pressure == "critical":
                pressure_indicator = " 🔴"
                pressure_style = "red"
            elif self.state.queue_pressure == "high":
                pressure_indicator = " 🟠"
                pressure_style = "yellow"
            elif self.state.queue_pressure == "medium":
                pressure_indicator = " 🟡"
                pressure_style = "yellow dim"
            else:  # low
                pressure_indicator = " 🟢"
                pressure_style = "green dim"

            # Add backend status
            backend_msg = ""
            if self.state.backend_status == "issues":
                backend_msg = " backend issues"
            elif self.state.backend_status == "slow":
                backend_msg = " backend slow"

            full_stats = stats + pressure_indicator + backend_msg

            # Calculate spacing
            total_content = len(full_stats)
            total_padding = self.width - total_content
            left_pad = max(2, total_padding // 2)
            right_pad = max(2, total_padding - left_pad)

            # Render stats with pressure indicator
            t.append(stats, style="dim")
            t.append(pressure_indicator, style=pressure_style)
            if backend_msg:
                t.append(backend_msg, style="yellow dim")

            t.append(" " * left_pad)
            t.append(" " * right_pad)

        return t
