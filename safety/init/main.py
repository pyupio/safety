import logging
import uuid
import typer
from rich.console import Console

from .models import UnverifiedProjectModel

import configparser
from pathlib import Path
from safety_schemas.models import ProjectModel, Stage
from safety.scan.util import GIT
from ..auth.utils import SafetyAuthSession

from typing import Optional
from safety.scan.render import (
    print_wait_project_verification,
    prompt_project_id,
    prompt_link_project,
)

PROJECT_CONFIG = ".safety-project.ini"
PROJECT_CONFIG_SECTION = "project"
PROJECT_CONFIG_ID = "id"
PROJECT_CONFIG_URL = "url"
PROJECT_CONFIG_NAME = "name"


LOG = logging.getLogger(__name__)


def check_project(
    ctx: typer.Context,
    session: SafetyAuthSession,
    console: Console,
    unverified_project: UnverifiedProjectModel,
    git_origin: Optional[str],
    ask_project_id: bool = False,
) -> dict:
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
        default_id = unverified_project.project_path.parent.name

        if not default_id:
            # Sometimes the parent directory is empty, so we generate
            # a random ID
            default_id = str(uuid.uuid4())[:10]

        unverified_project.id = prompt_project_id(console, default_id)
        data[PRJ_SLUG_KEY] = unverified_project.id
        data[PRJ_SLUG_SOURCE_KEY] = "user"

    status = print_wait_project_verification(
        console,
        data[PRJ_SLUG_KEY] if data.get(PRJ_SLUG_KEY, None) else "-",
        (session.check_project, data),
        on_error_delay=1,
    )

    return status


def verify_project(
    console: Console,
    ctx: typer.Context,
    session: SafetyAuthSession,
    unverified_project: UnverifiedProjectModel,
    stage: Stage,
    git_origin: Optional[str],
):
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
        result = check_project(
            ctx,
            session,
            console,
            unverified_project,
            git_origin,
            ask_project_id=not link_prj,
        )

        unverified_slug = result.get("slug")

        project = result.get("project", None)
        user_confirm = result.get("user_confirm", False)

        if user_confirm:
            if project and link_prj:
                prj_name = project.get("name", None)
                prj_admin_email = project.get("admin", None)

                link_prj = prompt_link_project(
                    prj_name=prj_name, prj_admin_email=prj_admin_email, console=console
                )

                if not link_prj:
                    continue

        verified_prj = print_wait_project_verification(
            console,
            unverified_slug,  # type: ignore
            (session.project, {"project_id": unverified_slug}),
            on_error_delay=1,
        )

        if (
            verified_prj
            and isinstance(verified_prj, dict)
            and verified_prj.get("slug", None)
        ):
            save_verified_project(
                ctx,
                verified_prj["slug"],
                verified_prj.get("name", None),
                unverified_project.project_path,
                verified_prj.get("url", None),
                verified_prj.get("organization", None),
            )
        else:
            verified_prj = False


def load_unverified_project_from_config(project_root: Path) -> UnverifiedProjectModel:
    """
    Loads an unverified project from the configuration file located at the project root.

    Args:
        project_root (Path): The root directory of the project.

    Returns:
        UnverifiedProjectModel: An instance of UnverifiedProjectModel.
    """
    config = configparser.ConfigParser()
    project_path = project_root / PROJECT_CONFIG
    config.read(project_path)
    id = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_ID, fallback=None)
    url = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_URL, fallback=None)
    name = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_NAME, fallback=None)
    created = True
    if id:
        created = False

    return UnverifiedProjectModel(
        id=id, url_path=url, name=name, project_path=project_path, created=created
    )


def save_verified_project(
    ctx: typer.Context,
    slug: str,
    name: Optional[str],
    project_path: Path,
    url_path: Optional[str],
    organization: Optional[dict],
):
    """
    Save the verified project information to the context and project info file.

    Args:
        ctx (typer.Context): The context of the Typer command.
        slug (str): The project slug.
        name (Optional[str]): The project name.
        project_path (Path): The project path.
        url_path (Optional[str]): The project URL path.
        organization (Optional[str]): The project organization.
    """
    ctx.obj.project = ProjectModel(
        id=slug, name=name, project_path=project_path, url_path=url_path
    )

    save_project_info(project=ctx.obj.project, project_path=project_path)

    ctx.obj.org = {}
    if organization:
        ctx.obj.org = {
            "name": organization.get("name"),
            "slug": organization.get("slug"),
        }


def save_project_info(project: ProjectModel, project_path: Path) -> bool:
    """
    Saves the project information to the configuration file.

    Args:
        project (ProjectModel): The ProjectModel object containing project
                                information.
        project_path (Path): The path to the configuration file.

    Returns:
        bool: True if the project information was saved successfully, False
              otherwise.
    """
    config = configparser.ConfigParser()
    config.read(project_path)

    if PROJECT_CONFIG_SECTION not in config.sections():
        config[PROJECT_CONFIG_SECTION] = {}

    config[PROJECT_CONFIG_SECTION][PROJECT_CONFIG_ID] = project.id
    if project.url_path:
        config[PROJECT_CONFIG_SECTION][PROJECT_CONFIG_URL] = project.url_path
    if project.name:
        config[PROJECT_CONFIG_SECTION][PROJECT_CONFIG_NAME] = project.name

    try:
        with open(project_path, "w") as configfile:
            config.write(configfile)
    except Exception:
        LOG.exception("Error saving project info")
        return False

    return True


def create_project(ctx: typer.Context, console: Console, target: Path):
    """
    Loads existing project from the specified target locations or creates a new project.

    Args:
        ctx: The CLI context
        session: The authentication session
        console: The console object
        target (Path): The target location
    """
    # Load .safety-project.ini
    unverified_project = load_unverified_project_from_config(project_root=target)

    stage = ctx.obj.auth.stage
    session = ctx.obj.auth.client
    git_data = GIT(root=target).build_git_data()
    origin = None

    if git_data:
        origin = git_data.origin

    if ctx.obj.platform_enabled:
        verify_project(console, ctx, session, unverified_project, stage, origin)
    else:
        console.print("Project creation is not supported for your account.")
