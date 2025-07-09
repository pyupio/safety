import time
from typing import List, Union

from rich.console import RenderableType
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


def typed_print(
    text: str, delay: float = 0.02, console=console, style="bold", end_line=True
):
    rich_text = console.render_str(text)
    text = rich_text.plain

    for char in text:
        console.print(char, end="", style=style)
        if char != "\n":
            time.sleep(delay)
    if end_line:
        console.line()


def progressive_print(
    sections: Union[List[str], List[RenderableType]],
    pause_between: float = 0.7,
    console=console,
):
    for section in sections:
        obj = section

        if isinstance(section, str):
            obj = console.render_str(section)

        console.print(obj)
        time.sleep(pause_between)


def render_header(
    title, emoji=":shield:", margin_left=0, margin_right=2, console=console
):
    """
    Create a modern header with emoji that works cross-platform
    """
    content = f"{' ' * margin_left}{emoji}{title}{' ' * margin_right}"
    rendered_content = console.render_str(content)
    plain_text = rendered_content.plain

    underline = console.render_str(f"[blue]{'━' * len(plain_text)}[/blue]")

    console.print()
    typed_print(plain_text, style="bold white", delay=0.01, console=console)
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
