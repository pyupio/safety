import os
import random
from collections import defaultdict

from rich.text import Text

from .base import BaseComponent
from ..models import Asset, ASSET_STYLES


def truncate_path(path: str, max_len: int = 30) -> str:
    """
    Truncate path intelligently.
    - Replace $HOME with ~
    - Collapse middle segments if too long
    """
    home = os.path.expanduser("~")
    if path.startswith(home):
        path = "~" + path[len(home) :]

    if len(path) <= max_len:
        return path

    parts = path.split("/")
    if len(parts) <= 3:
        return path[: max_len - 1] + "…"

    # Keep first segment and last two
    return f"{parts[0]}/…/{'/'.join(parts[-2:])}"


def truncate_id(value: str, max_len: int = 15) -> str:
    """
    Truncate UUIDs or IDs with ellipsis.
    """
    return value if len(value) <= max_len else value[:max_len] + "…"


class DiscoveriesHeaderComponent(BaseComponent):
    """
    Renders the discoveries section header with legend.
    """

    def render(self) -> Text:
        """
        Example:
        Recent Discoveries                                                   4509
        ◇ Context  ◆ Runtime  ○ Environment  ■ Dependency  ● Tool
        """
        # Main header line
        label = "Recent Discoveries"
        count = str(self.state.total_discovered)
        padding = self.width - len(label) - len(count)

        header = Text("  ")
        header.append(label)
        header.append(" " * max(padding, 1))
        header.append(count, style="dim")

        # Legend line
        legend = Text("  ")
        legend_items = [
            ("◇", "dim", "Context"),
            ("◆", "blue", "Runtime"),
            ("○", "yellow", "Environment"),
            ("■", "cyan", "Dependency"),
            ("●", "cyan", "Tool"),
        ]

        for i, (symbol, color, name) in enumerate(legend_items):
            legend.append(symbol, style=color)
            legend.append(f" {name}", style="dim")
            if i < len(legend_items) - 1:
                legend.append("  ")

        # Combine header and legend
        result = Text()
        result.append_text(header)
        result.append("\n")
        result.append_text(legend)
        return result


class DiscoveryRowComponent(BaseComponent):
    """
    Renders a single discovery row.
    """

    # Layout constants
    SUBTYPE_WIDTH = 20

    def __init__(self, asset: Asset, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.asset = asset

    def render(self) -> Text:
        """
        Example:
        ◆ python@3.11.7        /usr/bin/python3.11
        """
        symbol, color = ASSET_STYLES[self.asset.kind]
        subtype = self.asset.subtype[: self.SUBTYPE_WIDTH].ljust(self.SUBTYPE_WIDTH)
        path = (
            truncate_path(self.asset.path)
            if "/" in self.asset.path
            else truncate_id(self.asset.path)
        )

        t = Text("    ")
        t.append(f"{symbol} ", style=color)
        t.append(subtype)
        t.append(path, style="dim")

        # Linked runtime (right-aligned)
        if self.asset.linked_runtime:
            used = 4 + 2 + self.SUBTYPE_WIDTH + len(path)
            padding = self.width - used - len(self.asset.linked_runtime)
            if padding > 1:
                t.append(" " * padding)
                t.append(self.asset.linked_runtime, style="dim")

        return t


class DiscoveriesComponent(BaseComponent):
    """
    Renders the complete discoveries section.
    """

    MAX_DISCOVERIES = 32

    def render(self) -> Text:
        # Convert deque to list
        all_discoveries = list(self.state.discoveries)

        if not all_discoveries:
            items = []
        elif len(all_discoveries) <= self.MAX_DISCOVERIES:
            # Not enough items for diversity, just show all
            items = all_discoveries
        else:
            # Group by asset type for diversity
            by_type = defaultdict(list)
            for asset in all_discoveries:
                by_type[asset.kind].append(asset)

            if self.state.is_completed:
                # When complete, show a stable final summary view
                items = []
                types_with_assets = sorted(
                    by_type.keys(), key=lambda x: x.value
                )  # Consistent order
                slots_per_type = max(1, self.MAX_DISCOVERIES // len(types_with_assets))

                for asset_type in types_with_assets:
                    # Take most recent items from this type
                    type_assets = by_type[asset_type]
                    recent_count = min(slots_per_type, len(type_assets))
                    items.extend(type_assets[-recent_count:])

                # Fill remaining slots with most recent overall
                if len(items) < self.MAX_DISCOVERIES:
                    remaining_slots = self.MAX_DISCOVERIES - len(items)
                    included_paths = {item.path for item in items}
                    remaining = [
                        a for a in all_discoveries if a.path not in included_paths
                    ]
                    if remaining:
                        items.extend(remaining[-remaining_slots:])
            else:
                # During scanning, sample with variety and randomness
                items = []
                types_with_assets = list(by_type.keys())
                slots_per_type = max(1, self.MAX_DISCOVERIES // len(types_with_assets))

                for asset_type in types_with_assets:
                    # Take recent items from this type (prefer newer)
                    type_assets = by_type[asset_type]
                    recent_count = min(slots_per_type, len(type_assets))
                    items.extend(type_assets[-recent_count:])

                # If we have space left, fill with most recent overall
                if len(items) < self.MAX_DISCOVERIES:
                    remaining_slots = self.MAX_DISCOVERIES - len(items)
                    # Get items not already included
                    included_paths = {item.path for item in items}
                    remaining = [
                        a for a in all_discoveries if a.path not in included_paths
                    ]
                    if remaining:
                        items.extend(remaining[-remaining_slots:])

                # Shuffle for visual variety while scanning
                random.shuffle(items)

        lines = []

        for asset in items:
            row_component = DiscoveryRowComponent(asset, self.state, self.console)
            lines.append(row_component.render())

        # Pad to maintain consistent height
        while len(lines) < self.MAX_DISCOVERIES:
            lines.append(Text(""))

        t = Text()
        for i, line in enumerate(lines):
            t.append_text(line)
            if i < len(lines) - 1:
                t.append("\n")
        return t
