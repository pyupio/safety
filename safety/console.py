from functools import lru_cache
import logging
import os
import sys
from typing import TYPE_CHECKING, List, Dict, Any, Optional, Union
from rich.console import Console
from rich.theme import Theme
from safety.emoji import load_emoji


if TYPE_CHECKING:
    from rich.console import HighlighterType, JustifyMethod, OverflowMethod
    from rich.style import Style
    from rich.text import Text


LOG = logging.getLogger(__name__)


@lru_cache()
def should_use_ascii():
    """
    Check if we should use ASCII alternatives for emojis
    """
    encoding = getattr(sys.stdout, "encoding", "").lower()

    if encoding in {"utf-8", "utf8", "cp65001", "utf-8-sig"}:
        return False

    return True


def get_spinner_animation() -> List[str]:
    """
    Get the spinner animation based on the encoding
    """
    if should_use_ascii():
        spinner = [
            "[    ]",
            "[=   ]",
            "[==  ]",
            "[=== ]",
            "[====]",
            "[ ===]",
            "[  ==]",
            "[   =]",
        ]
    else:
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    return spinner


def replace_non_ascii_chars(text: str):
    """
    Replace non-ascii characters with ascii alternatives
    """
    CHARS_MAP = {
        "━": "-",
        "’": "'",
    }

    for char, replacement in CHARS_MAP.items():
        text = text.replace(char, replacement)

    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        LOG.warning("No handled non-ascii characters detected, encoding with replace")
        text = text.encode("ascii", "replace").decode("ascii")

    return text


class SafeConsole(Console):
    """
    Console subclass that handles emoji encoding issues by detecting
    problematic encoding environments and replacing emojis with ASCII alternatives.
    Uses string replacement for custom emoji namespace to avoid private API usage.
    """

    def render_str(
        self,
        text: str,
        *,
        style: Union[str, "Style"] = "",
        justify: Optional["JustifyMethod"] = None,
        overflow: Optional["OverflowMethod"] = None,
        emoji: Optional[bool] = None,
        markup: Optional[bool] = None,
        highlight: Optional[bool] = None,
        highlighter: Optional["HighlighterType"] = None,
    ) -> "Text":
        """
        Override render_str to pre-process our custom emojis before Rich handles the text.
        """

        use_ascii = should_use_ascii()
        text = load_emoji(text, use_ascii=use_ascii)

        if use_ascii:
            text = replace_non_ascii_chars(text)

        # Let Rich handle everything else normally
        return super().render_str(
            text,
            style=style,
            justify=justify,
            overflow=overflow,
            emoji=emoji,
            markup=markup,
            highlight=highlight,
            highlighter=highlighter,
        )


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


non_interactive = os.getenv("NON_INTERACTIVE") == "1"

console_kwargs: Dict[str, Any] = {
    "theme": Theme(SAFETY_THEME, inherit=False),
    "emoji": not should_use_ascii(),
}

if non_interactive:
    LOG.info(
        "NON_INTERACTIVE environment variable is set, forcing non-interactive mode"
    )
    console_kwargs["force_terminal"] = True
    console_kwargs["force_interactive"] = False

main_console = SafeConsole(**console_kwargs)
