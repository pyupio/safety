import sys
import os


def is_interactive_terminal() -> bool:
    """
    Auto-detect if we should run in interactive mode.

    Interactive mode is enabled when:
    - stdout is a TTY (not redirected to file/pipe)
    - Not running in CI environment (CI=true/1)
    - Not a dumb terminal (TERM=dumb)
    """
    return (
        sys.stdout.isatty()
        and not os.getenv("CI")
        and os.getenv("TERM", "").lower() != "dumb"  # Avoid dumb terminals
    )
