from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from rich.console import Console


def render_initialization_result(
    console: "Console",
    codebase_init_status: Optional[str] = None,
    codebase_id: Optional[str] = None,
):
    if not codebase_init_status or not codebase_id:
        console.print("Error: unable to initialize codebase")
        return

    message = None

    if codebase_init_status == "created":
        from safety.codebase.constants import CODEBASE_INIT_CREATED

        message = CODEBASE_INIT_CREATED

    if codebase_init_status == "linked":
        from safety.codebase.constants import CODEBASE_INIT_LINKED

        message = CODEBASE_INIT_LINKED

    if codebase_init_status == "reinitialized":
        from safety.codebase.constants import CODEBASE_INIT_REINITIALIZED

        message = CODEBASE_INIT_REINITIALIZED

    if message:
        console.print(message.format(codebase_name=codebase_id))
