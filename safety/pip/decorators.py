from functools import wraps
from pathlib import Path

from safety_schemas.models import ProjectModel

from safety.console import main_console

from ..cli_util import process_auth_status_not_ready
from ..init.main import load_unverified_project_from_config, verify_project
from ..scan.util import GIT


def optional_project_command(func):
    @wraps(func)
    def inner(ctx, target: Path, *args, **kwargs):
        ctx.obj.console = main_console
        ctx.params.pop("console", None)

        if not ctx.obj.auth.is_valid():
            process_auth_status_not_ready(
                console=main_console, auth=ctx.obj.auth, ctx=ctx
            )

        upload_request_id = kwargs.pop("upload_request_id", None)

        # Load .safety-project.ini
        unverified_project = load_unverified_project_from_config(project_root=target)

        if ctx.obj.platform_enabled and not unverified_project.created:
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


def register_event_handlers(func):
    @wraps(func)
    def inner(ctx, *args, **kwargs):
        if event_bus := ctx.obj.event_bus:
            from safety_schemas.models.events import EventType

            event_bus.subscribe(
                [
                    EventType.PACKAGE_UNINSTALLED,
                    EventType.PACKAGE_INSTALLED,
                    EventType.PACKAGE_UPDATED,
                    EventType.TOOL_COMMAND_EXECUTED,
                ],
                ctx.obj.security_events_handler,
            )

        return func(ctx, *args, **kwargs)

    return inner
