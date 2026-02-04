from rich.live import Live
from typing import Callable

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

                # Auto-exit after countdown
                return

    finally:
        pass
