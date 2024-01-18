import logging
import os
from rich.console import Console
from rich.theme import Theme

LOG = logging.getLogger(__name__)

SAFETY_THEME = {
    "file_title": "bold default on default",
    "dep_name": "bold yellow on default",
    "scan_meta_title": "bold default on default",
    "vuln_brief": "red on default",
    "rem_brief": "bold green on default",
    "rem_severity": "bold red on default",
    "brief_severity": "bold default on default",
    "status.spinner": "green",
    "recommended_ver": "bold cyan on default",
    "vuln_id": "bold default on default",
    "number": "bold cyan on default",
    "link": "underline bright_blue on default",
    "tip": "bold default on default",
    "specifier": "bold cyan on default",
    "vulns_found_number": "red on default",
}

non_interactive = os.getenv('NON_INTERACTIVE') == '1'

console_kwargs = {"theme": Theme(SAFETY_THEME, inherit=False)}

if non_interactive:
    LOG.info("NON_INTERACTIVE environment variable is set, forcing non-interactive mode")
    console_kwargs.update({"force_terminal": True, "force_interactive": False})


main_console = Console(**console_kwargs)
