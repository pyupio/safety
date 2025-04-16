from functools import wraps
from pathlib import Path

from safety_schemas.models import ProjectModel

from safety.console import main_console

from ..scan.util import GIT


def optional_project_command(func):
    @wraps(func)
    def inner(ctx, target: Path, *args, **kwargs):
        ctx.obj.console = main_console
        ctx.params.pop("console", None)

        if not ctx.obj.auth.is_valid():
            from safety.cli_util import process_auth_status_not_ready

            process_auth_status_not_ready(
                console=main_console, auth=ctx.obj.auth, ctx=ctx
            )

        upload_request_id = kwargs.pop("upload_request_id", None)
        from safety.init.main import load_unverified_project_from_config

        # Load .safety-project.ini
        unverified_project = load_unverified_project_from_config(project_root=target)

        # We need to always verify the project
        #  and not unverified_project.created
        if ctx.obj.platform_enabled:
            from safety.init.main import verify_project

            stage = ctx.obj.auth.stage
            session = ctx.obj.auth.client
            git_data = GIT(root=target).build_git_data()
            origin = None

            if git_data:
                origin = git_data.origin

            verify_project(
                main_console, ctx, session, unverified_project, stage, origin
            )

            ctx.obj.project.git = git_data
        else:
            ctx.obj.project = ProjectModel(
                id="",
                name="Undefined project",
                project_path=unverified_project.project_path,
            )

        ctx.obj.project.upload_request_id = upload_request_id

        return func(ctx, target=target, *args, **kwargs)

    return inner
