from __future__ import annotations

from rich.text import Text

from .base import BaseComponent


def pluralize(count: int, singular: str, plural: str | None = None) -> str:
    """
    Return singular or plural form based on count.
    """
    if count == 1:
        return singular
    return plural or singular + "s"


class MetricsComponent(BaseComponent):
    """
    Renders the metrics box showing asset counts.
    """

    def render(self) -> Text:
        t = Text()
        metrics = [
            (self.state.contexts, pluralize(self.state.contexts, "Context")),
            (self.state.runtimes, pluralize(self.state.runtimes, "Runtime")),
            (
                self.state.environments,
                pluralize(self.state.environments, "Environment"),
            ),
            (
                self.state.dependencies,
                pluralize(self.state.dependencies, "Dependency", "Dependencies"),
            ),
            (self.state.tools, pluralize(self.state.tools, "Tool")),
        ]

        inner = Text()
        for i, (count, label) in enumerate(metrics):
            inner.append(f"{count}", style="bold")
            inner.append(f" {label}")
            if i < len(metrics) - 1:
                inner.append("    ")

        content = inner.plain
        box_width = len(content) + 4  # padding for inner content
        total_box_width = box_width + 2  # including box borders

        # Center the box within available width
        center_padding = max(0, (self.width - total_box_width) // 2)
        left_pad = " " * center_padding

        t.append(left_pad + "┌" + "─" * box_width + "┐\n", style="dim")
        t.append(left_pad + "│  ", style="dim")
        t.append_text(inner)
        t.append("  │\n", style="dim")
        t.append(left_pad + "└" + "─" * box_width + "┘", style="dim")

        return t
