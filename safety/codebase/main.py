from typing import TYPE_CHECKING, Optional
from ..codebase_utils import load_unverified_project_from_config
from safety.errors import SafetyError, SafetyException
from pathlib import Path
from safety.codebase.constants import (
    CODEBASE_INIT_ERROR,
    CODEBASE_INIT_NOT_FOUND_LINK_TO,
    CODEBASE_INIT_NOT_FOUND_PROJECT_FILE,
)
from safety.init.main import create_project
from typer import Context
from rich.console import Console
import sys

if TYPE_CHECKING:
    from ..codebase_utils import UnverifiedProjectModel


def initialize_codebase(
    ctx: Context,
    console: Console,
    codebase_path: Path,
    unverified_codebase: "UnverifiedProjectModel",
    org_slug: str,
    link_to: Optional[str] = None,
    should_enable_firewall: bool = False,
):
    is_interactive = sys.stdin.isatty()
    link_behavior = "prompt"
    create_if_missing = True
    is_codebase_file_created = unverified_codebase.created

    if link_to or is_codebase_file_created:
        link_behavior = "always"
        create_if_missing = False
    elif not is_interactive:
        link_behavior = "never"

    project_file_created, project_status = create_project(
        ctx=ctx,
        console=console,
        target=codebase_path,
        unverified_project=unverified_codebase,
        create_if_missing=create_if_missing,
        link_behavior=link_behavior,
    )

    if project_status == "not_found":
        codebase_name = "Unknown"
        msg = "Codebase not found."

        if link_to:
            msg = CODEBASE_INIT_NOT_FOUND_LINK_TO
            codebase_name = link_to
        elif is_codebase_file_created:
            msg = CODEBASE_INIT_NOT_FOUND_PROJECT_FILE
            codebase_name = unverified_codebase.id

        raise SafetyError(msg.format(codebase_name=codebase_name))
    elif project_status == "found" and not is_interactive:
        # Non-TTY mode: Project exists but we can't link (link_behavior="never")
        suggested_name = unverified_codebase.id
        raise SafetyError(
            f"Project '{suggested_name}' already exists. "
            f"In non-interactive mode, use --link-to '{suggested_name}' to link to the existing project, "
            f"or use --name with a different project name to create a new one."
        )

    if not ctx.obj.project:
        raise SafetyException(CODEBASE_INIT_ERROR)

    if should_enable_firewall:
        from ..tool.main import configure_local_directory

        configure_local_directory(codebase_path, org_slug, ctx.obj.project.id)

    return project_file_created, project_status


def fail_if_codebase_name_mismatch(
    provided_name: str,
    unverified_codebase: "UnverifiedProjectModel",
) -> None:
    """
    Useful to prevent the user from overwriting an existing codebase by mistyping the name.
    """
    if unverified_codebase.id and provided_name != unverified_codebase.id:
        from safety.codebase.constants import CODEBASE_INIT_ALREADY_EXISTS

        raise SafetyError(CODEBASE_INIT_ALREADY_EXISTS)


def prepare_unverified_codebase(
    codebase_path: Path,
    user_provided_name: Optional[str] = None,
    user_provided_link_to: Optional[str] = None,
) -> "UnverifiedProjectModel":
    """
    Prepare the unverified codebase object based on the provided name and link to.
    """
    unverified_codebase = load_unverified_project_from_config(
        project_root=codebase_path
    )

    provided_name = user_provided_name or user_provided_link_to

    if provided_name:
        fail_if_codebase_name_mismatch(
            provided_name=provided_name,
            unverified_codebase=unverified_codebase,
        )

        unverified_codebase.id = provided_name

    return unverified_codebase
