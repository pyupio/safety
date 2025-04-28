import platform
import time

from rich.prompt import Prompt
import typer
from safety.console import main_console as console
from safety.events.utils.emission import (
    emit_codebase_setup_response_created,
    emit_firewall_setup_response_created,
)
from safety.init.constants import (
    MSG_SETUP_CODEBASE_PROMPT,
    MSG_SETUP_CONTINUE_PROMPT,
    MSG_SETUP_PACKAGE_FIREWALL_PROMPT,
)


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


def ask_firewall_setup(ctx: typer.Context, prompt_user: bool = True) -> bool:
    """
    Ask the user if they want to set up Safety Firewall.

    As a side effect, this function emits an event with the response.

    Args:
        ctx: The CLI context
        prompt_user: Whether to prompt the user for input

    Returns:
        bool: True if the user wants to set up Safety Firewall, False otherwise
    """
    firewall_choice = "y"

    if prompt_user:
        firewall_choice = Prompt.ask(
            MSG_SETUP_PACKAGE_FIREWALL_PROMPT,
            choices=["y", "n", "Y", "N"],
            default="y",
            show_default=False,
            show_choices=False,
            console=console,
        ).lower()

    should_setup_firewall = firewall_choice == "y"

    emit_firewall_setup_response_created(
        event_bus=ctx.obj.event_bus,
        ctx=ctx,
        user_consent_requested=prompt_user,
        user_consent=should_setup_firewall if prompt_user else None,
    )

    return should_setup_firewall


def ask_codebase_setup(ctx: typer.Context, prompt_user: bool = True) -> bool:
    """
    Ask the user if they want to set up a codebase.

    As a side effect, this function emits an event with the response.

    Args:
        ctx: The CLI context
        prompt_user: Whether to prompt the user for input

    Returns:
        bool: True if the user wants to set up a codebase, False otherwise
    """
    codebase_response = "y"

    if prompt_user:
        codebase_response = Prompt.ask(
            MSG_SETUP_CODEBASE_PROMPT,
            choices=["y", "n", "Y", "N"],
            default="y",
            show_default=False,
            show_choices=False,
            console=console,
        ).lower()

    should_setup_codebase = codebase_response == "y"

    emit_codebase_setup_response_created(
        event_bus=ctx.obj.event_bus,
        ctx=ctx,
        user_consent_requested=prompt_user,
        user_consent=should_setup_codebase if prompt_user else None,
    )

    return should_setup_codebase


def ask_continue(ctx: typer.Context, prompt_user: bool = True) -> bool:
    """
    Ask the user if they want to continue by typing enter

    Args:
        ctx: The CLI context
        prompt_user: Whether to prompt the user for input

    Returns:
        bool: True if the user wants to continue, False otherwise
    """
    if prompt_user:
        return (
            Prompt.ask(
                MSG_SETUP_CONTINUE_PROMPT,
                choices=["y", "Y"],
                default="y",
                show_default=False,
                show_choices=False,
                console=console,
            ).lower()
            == "y"
        )

    return True
