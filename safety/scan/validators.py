
import os
from pathlib import Path
from typing import Optional, Tuple
import typer
from safety.scan.main import save_project_info
from safety.scan.models import ScanExport, ScanOutput, UnverifiedProjectModel
from safety.scan.render import print_wait_project_verification, prompt_project_id, prompt_link_project

from safety_schemas.models import AuthenticationType, ProjectModel, Stage
from safety.auth.utils import SafetyAuthSession


MISSING_SPDX_EXTENSION_MSG = "spdx extra is not installed, please install it with: pip install safety[spdx]"


def raise_if_not_spdx_extension_installed() -> None:
    """
    Raises an error if the spdx extension is not installed.
    """
    try:
        import spdx_tools.spdx
    except Exception as e:
        raise typer.BadParameter(MISSING_SPDX_EXTENSION_MSG)


def save_as_callback(save_as: Optional[Tuple[ScanExport, Path]]) -> Tuple[Optional[str], Optional[Path]]:
    """
    Callback function to handle save_as parameter and validate if spdx extension is installed.

    Args:
        save_as (Optional[Tuple[ScanExport, Path]]): The export type and path.

    Returns:
        Tuple[Optional[str], Optional[Path]]: The validated export type and path.
    """
    export_type, export_path = save_as if save_as else (None, None)

    if ScanExport.is_format(export_type, ScanExport.SPDX):
        raise_if_not_spdx_extension_installed()

    return (export_type.value, export_path) if export_type and export_path else (export_type, export_path)

def output_callback(output: ScanOutput) -> str:
    """
    Callback function to handle output parameter and validate if spdx extension is installed.

    Args:
        output (ScanOutput): The output format.

    Returns:
        str: The validated output format.
    """
    if ScanOutput.is_format(output, ScanExport.SPDX):
        raise_if_not_spdx_extension_installed()

    return output.value


def fail_if_not_allowed_stage(ctx: typer.Context):
    """
    Fail the command if the authentication type is not allowed in the current stage.

    Args:
        ctx (typer.Context): The context of the Typer command.
    """
    if ctx.resilient_parsing:
        return

    stage = ctx.obj.auth.stage
    auth_type: AuthenticationType = ctx.obj.auth.client.get_authentication_type()

    if os.getenv("SAFETY_DB_DIR"):
        return

    if not auth_type.is_allowed_in(stage):
        raise typer.BadParameter(f"'{auth_type.value}' auth type isn't allowed with " \
                                 f"the '{stage}' stage.")


def save_verified_project(ctx: typer.Context, slug: str, name: Optional[str], project_path: Path, url_path: Optional[str]):
    """
    Save the verified project information to the context and project info file.

    Args:
        ctx (typer.Context): The context of the Typer command.
        slug (str): The project slug.
        name (Optional[str]): The project name.
        project_path (Path): The project path.
        url_path (Optional[str]): The project URL path.
    """
    ctx.obj.project = ProjectModel(
        id=slug,
        name=name,
        project_path=project_path,
        url_path=url_path
    )
    if ctx.obj.auth.stage is Stage.development:
        save_project_info(project=ctx.obj.project,
                          project_path=project_path)


def check_project(console, ctx: typer.Context, session: SafetyAuthSession,
                  unverified_project: UnverifiedProjectModel, stage: Stage,
                  git_origin: Optional[str], ask_project_id: bool = False) -> dict:
    """
    Check the project against the session and stage, verifying the project if necessary.

    Args:
        console: The console for output.
        ctx (typer.Context): The context of the Typer command.
        session (SafetyAuthSession): The authentication session.
        unverified_project (UnverifiedProjectModel): The unverified project model.
        stage (Stage): The current stage.
        git_origin (Optional[str]): The Git origin URL.
        ask_project_id (bool): Whether to prompt for the project ID.

    Returns:
        dict: The result of the project check.
    """
    stage = ctx.obj.auth.stage
    source = ctx.obj.telemetry.safety_source if ctx.obj.telemetry else None
    data = {"scan_stage": stage, "safety_source": source}

    PRJ_SLUG_KEY = "project_slug"
    PRJ_SLUG_SOURCE_KEY = "project_slug_source"
    PRJ_GIT_ORIGIN_KEY = "git_origin"

    if git_origin:
        data[PRJ_GIT_ORIGIN_KEY] = git_origin

    if unverified_project.id:
        data[PRJ_SLUG_KEY] = unverified_project.id
        data[PRJ_SLUG_SOURCE_KEY] = ".safety-project.ini"
    elif not git_origin or ask_project_id:
        # Set a project id for this scan (no spaces). If empty Safety will use: pyupio:
        parent_root_name = None
        if unverified_project.project_path.parent.name:
            parent_root_name = unverified_project.project_path.parent.name

        unverified_project.id = prompt_project_id(console, stage, parent_root_name)
        data[PRJ_SLUG_KEY] = unverified_project.id
        data[PRJ_SLUG_SOURCE_KEY] = "user"

    status = print_wait_project_verification(console, data[PRJ_SLUG_KEY] if data.get(PRJ_SLUG_KEY, None) else "-",
                                    (session.check_project, data), on_error_delay=1)

    return status


def verify_project(console, ctx: typer.Context, session: SafetyAuthSession,
                   unverified_project: UnverifiedProjectModel, stage: Stage,
                   git_origin: Optional[str]):
    """
    Verify the project, linking it if necessary and saving the verified project information.

    Args:
        console: The console for output.
        ctx (typer.Context): The context of the Typer command.
        session (SafetyAuthSession): The authentication session.
        unverified_project (UnverifiedProjectModel): The unverified project model.
        stage (Stage): The current stage.
        git_origin (Optional[str]): The Git origin URL.
    """

    verified_prj = False

    link_prj = True

    while not verified_prj:
        result = check_project(console, ctx, session, unverified_project, stage, git_origin, ask_project_id=not link_prj)

        unverified_slug = result.get("slug")

        project = result.get("project", None)
        user_confirm = result.get("user_confirm", False)

        if user_confirm:
            if project and link_prj:
                prj_name = project.get("name", None)
                prj_admin_email = project.get("admin", None)

                link_prj = prompt_link_project(prj_name=prj_name,
                                    prj_admin_email=prj_admin_email,
                                    console=console)

                if not link_prj:
                    continue

        verified_prj = print_wait_project_verification(
            console, unverified_slug, (session.project,
                                       {"project_id": unverified_slug}),
                                       on_error_delay=1)

        if verified_prj and isinstance(verified_prj, dict) and verified_prj.get("slug", None):
            save_verified_project(ctx, verified_prj["slug"], verified_prj.get("name", None),
                                  unverified_project.project_path, verified_prj.get("url", None))
        else:
            verified_prj = False
