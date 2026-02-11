from __future__ import annotations

import typer

import sys
import platform
import subprocess

from typing import Any, TYPE_CHECKING
from datetime import datetime

from safety.console import main_console as console

from .scanner import Config, SystemScanner, SinkConfig
from .callbacks import (
    CliCallbacks,
    CliSafetyPlatformSinkCallbacks,
    NonInteractiveCallbacks,
)
from .ui.main import live
from .ui.state import ScanState

if TYPE_CHECKING:
    from safety.auth.models import Auth


def run_non_interactive(auth: Auth, config: Config, sink_cfg: SinkConfig):
    """
    Run system scan in non-interactive mode with summary output.

    Args:
        auth: Authentication object with org and user info
        config: Scanner configuration
        sink_cfg: Sink configuration for output
    """
    # Create state for tracking (same as interactive but no UI updates)
    state = ScanState(
        organization=auth.org_name or "Unknown",
        user_email=auth.email or "Unknown",
        start_time=datetime.now(),
    )

    callbacks = NonInteractiveCallbacks(state=state)
    scanner = SystemScanner(config=config, sink_cfg=sink_cfg, callbacks=callbacks)
    scanner.run()

    # Print summary after completion - with breakdown now available!
    console.print()
    console.print(state.format_plain_summary(include_breakdown=True))
    console.print()


def run_in_background(ctx: typer.Context) -> subprocess.Popen[str]:
    """
    Run the system scan in the background.

    This will spawn a subprocess running the same command without the background flag.

    Args:
        ctx (typer.Context): The Typer context object containing CLI parameters.

    Returns:
        subprocess.Popen[str]: The background process handle.

    Raises:
        OSError: If subprocess creation fails.
    """
    cmd_args: list[str] = [sys.executable, "-m", "safety", "system-scan", "run"]

    # Add any other args that were passed (except --background)
    if ctx.params is not None:
        for param, value in ctx.params.items():
            if param != "background" and value is not None:
                if isinstance(value, bool) and value:
                    cmd_args.append(f"--{param.replace('_', '-')}")
                elif not isinstance(value, bool):
                    cmd_args.extend([f"--{param.replace('_', '-')}", str(value)])

    popen_kwargs: dict[str, Any] = {}

    if platform.system() == "Windows":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            **popen_kwargs,
        )
        return proc
    except OSError as e:
        raise OSError(f"Failed to start background process: {e}") from e


def run_interactive(auth: Auth, config: Config, sink_cfg: SinkConfig):
    state = ScanState(
        organization=auth.org_name or "Unknown",
        user_email=auth.email or "Unknown",
        scan_id="Requesting a scan id...",
        start_time=datetime.now(),
    )

    sink_callbacks = CliSafetyPlatformSinkCallbacks(state=state)
    callbacks = CliCallbacks(state=state)

    scanner = SystemScanner(
        config=config,
        sink_cfg=sink_cfg,
        callbacks=callbacks,
        sink_callbacks=sink_callbacks,
    )

    live(system_scan_fn=scanner.run, state=state)
