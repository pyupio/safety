import platform
import time
from safety.console import main_console as console


def load_emoji(emoji):
    """
    Return the most appropriate emoji symbol based on terminal environment.

    Args:
        emoji (str): The emoji character to display, if supported

    Returns:
        str: The emoji if supported, or an appropriate alternative
    """
    # On non-Windows platforms, return the original emoji
    if platform.system() != "Windows":
        return emoji

    # Windows emoji mapping - add supported emojis or provide alternatives
    emoji_map = {
        "✓": "+",
        "🛡": "SHIELD",
        "⚠️": "!",
        "❌": "X",
        "ℹ️": "i",
        "🔒": "LOCK",
        "🔑": "KEY",
    }

    # Return the mapped version if it exists, otherwise return original
    # This allows Windows to display emojis it actually supports
    return emoji_map.get(emoji, emoji)


def typed_print(text, delay=0.02, console=console, style="bold", end_line=True):
    for char in text:
        console.print(char, end="", style=style)
        if char != "\n":
            time.sleep(delay)
    if end_line:
        console.line()


def progressive_print(sections, pause_between=0.7):
    for section in sections:
        console.print(section)
        time.sleep(pause_between)


def render_header(title, emoji="🛡", margin_left=0, margin_right=2):
    """
    Create a modern header with emoji that works cross-platform
    """
    header_text = f"{' ' * margin_left}{emoji}{title}{' ' * margin_right}"
    underline = (
        f"[blue]{'━' * (margin_left + len(emoji) + len(title) + margin_right)}[/blue]"
    )

    console.print()
    typed_print(header_text, style="bold white", delay=0.01, console=console)
    console.print(underline)
    console.print()
