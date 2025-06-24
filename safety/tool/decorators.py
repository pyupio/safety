from functools import wraps
from pathlib import Path

from rich.console import Console
from safety_schemas.models import ProjectModel

from safety.console import main_console
from safety.tool.constants import (
    MSG_NOT_AUTHENTICATED_TOOL,
    MSG_NOT_AUTHENTICATED_TOOL_NO_TTY,
)

from ..codebase_utils import load_unverified_project_from_config
from ..scan.util import GIT


def prepare_tool_execution(func):
    @wraps(func)
    def inner(ctx, target: Path, *args, **kwargs):
        ctx.obj.console = main_console
        ctx.params.pop("console", None)

        if not ctx.obj.auth.is_valid():
            tool_name = ctx.command.name.title()
            if ctx.obj.console.is_interactive:
                ctx.obj.console.line()
                ctx.obj.console.print(
                    MSG_NOT_AUTHENTICATED_TOOL.format(tool_name=tool_name)
                )
                ctx.obj.console.line()

                from safety.cli_util import process_auth_status_not_ready

                process_auth_status_not_ready(
                    console=main_console, auth=ctx.obj.auth, ctx=ctx
                )
            else:
                stderr_console = Console(stderr=True)
                stderr_console.print(
                    MSG_NOT_AUTHENTICATED_TOOL_NO_TTY.format(tool_name=tool_name)
                )

        unverified_project = load_unverified_project_from_config(project_root=target)

        if prj_id := unverified_project.id:
            ctx.obj.project = ProjectModel(
                id=prj_id,
                name=unverified_project.name,
                project_path=unverified_project.project_path,
            )

            git_data = GIT(root=target).build_git_data()
            ctx.obj.project.git = git_data

        return func(ctx, target=target, *args, **kwargs)

    return inner
