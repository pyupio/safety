"""
Package tool interception (firewall) subsystem.

This package intercepts package-management commands (pip install, poetry add,
uv add, npm install, etc.) so Safety can:

  1. **Verify** that packages being installed are not known to be vulnerable
     or malicious (typosquatting protection).
  2. **Track** environment changes (package additions, removals, updates)
     for audit / rollback support.
  3. **Emit** security events to the Safety Platform for monitoring.

Architecture
------------
Each supported tool has its own sub-package (``pip/``, ``poetry/``, ``uv/``,
``npm/``) containing:

  - ``command.py``   — CLI command definition (Typer)
  - ``parser.py``    — Command-line parser (ToolCommandLineParser subclass)
  - ``main.py``      — ToolCommandBase subclass implementing the interception

The interception lifecycle is:

  ``before()`` → Typosquatting check & diff tracking setup
  ``execute()`` → Run the real tool via subprocess
  ``after()`` → Diff computation & event emission

The ``interceptors/`` sub-package provides OS-level process interception
(unix, windows) for the firewall mode.
"""

from .tool_inspector import ToolInspector
from .main import tool_commands
from .main import configure_system, configure_alias
from .base import ToolResult


__all__ = [
    "ToolInspector",
    "tool_commands",
    "configure_system",
    "configure_alias",
    "ToolResult",
]
