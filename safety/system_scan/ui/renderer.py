from rich.console import Group, RenderableType
from rich.text import Text

from .components import (
    DiscoveriesComponent,
    DiscoveriesHeaderComponent,
    FooterComponent,
    HeaderComponent,
    LogsComponent,
    MetricsComponent,
    ScanInfoComponent,
    SeparatorComponent,
    SubtitleComponent,
    TitleComponent,
)
from .state import ScanState


def render_tui(state: ScanState) -> RenderableType:
    """
    Compose the complete TUI using existing components.
    """
    # Create a mock console for components (they need it for width calculation)
    from rich.console import Console

    console = Console()

    # Initialize all components with state
    header = HeaderComponent(state, console)
    scan_info = ScanInfoComponent(state, console)
    title = TitleComponent(state, console)
    subtitle = SubtitleComponent(state, console)
    metrics = MetricsComponent(state, console)
    discoveries_header = DiscoveriesHeaderComponent(state, console)
    discoveries = DiscoveriesComponent(state, console)
    separator = SeparatorComponent(state, console)
    logs = LogsComponent(state, console)
    footer = FooterComponent(state, console)

    return Group(
        Text(""),
        header.render(),
        scan_info.render(),
        Text(""),
        title.render(),
        subtitle.render(),
        Text(""),
        metrics.render(),
        Text(""),
        discoveries_header.render(),
        Text(""),
        discoveries.render(),
        Text(""),
        separator.render(),
        logs.render(),
        Text(""),
        footer.render(),
        Text(""),
    )
