from rich.live import Live
from typing import Callable

from safety.console import main_console as console

from .state import ScanState
from .renderer import render_tui


def live(system_scan_fn: Callable[..., None], state: ScanState):
    try:
        with Live(render_tui(state), refresh_per_second=10, screen=True) as live:
            state.set_live(live)

            system_scan_fn()

            if state.is_completed:
                import time

                for remaining in range(10, 0, -1):
                    state.update_countdown(remaining)
                    time.sleep(1)

        # Print persistent summary after TUI exits
        if state.is_completed:
            console.print()
            console.print(state.format_plain_summary_with_breakdown())
            console.print()

    except KeyboardInterrupt:
        # Ensure summary is printed even on interruption if scan completed
        if state.is_completed:
            console.print()
            console.print(state.format_plain_summary_with_breakdown())
            console.print()
        raise
    finally:
        pass
