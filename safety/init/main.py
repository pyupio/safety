import logging
import uuid
from rich.prompt import Prompt
from rich.text import Text
import typer
from rich.console import Console

from safety.events.utils.emission import emit_firewall_setup_completed
from safety.init.render import load_emoji, progressive_print

from ..tool import configure_system, configure_alias

from .constants import (
    MSG_AUTH_PROMPT,
    MSG_NEED_AUTHENTICATION,
    MSG_SETUP_INCOMPLETE,
    MSG_SETUP_PACKAGE_FIREWALL_NOTE_STATUS,
    MSG_SETUP_PACKAGE_FIREWALL_RESULT,
)

from .models import UnverifiedProjectModel

import configparser
from pathlib import Path
from safety_schemas.models import ProjectModel, Stage
from safety_schemas.models.events.types import ToolType
from safety.scan.util import GIT
from ..auth.utils import SafetyAuthSession

from typing import TYPE_CHECKING, Any, Optional, Tuple
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

if TYPE_CHECKING:
    from safety.models import SafetyCLI
    from .types import FirewallConfigStatus

logger = logging.getLogger(__name__)


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
) -> Tuple[bool, Optional[str]]:
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
    project_status = (True, "created")

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

                if link_prj:
                    project_status = (True, "linked")

                if not link_prj:
                    continue
        else:
            project_status = (True, "linked")

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
            project_status = (False, None)

    return project_status


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
    if not id:
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
        logger.exception("Error saving project info")
        return False

    return True


def create_project(
    ctx: typer.Context, console: Console, target: Path
) -> Tuple[bool, Optional[str]]:
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
        result = verify_project(
            console, ctx, session, unverified_project, stage, origin
        )
        ctx.obj.project.git = git_data
        return result
    else:
        console.print("Project creation is not supported for your account.")
        return (False, None)


def launch_auth_if_needed(ctx: typer.Context, console: Console) -> Optional[str]:
    """
    Launch the authentication flow if needed.

    Args:
        ctx: The CLI context

    Returns:
        Optional[str]: The organization slug if authentication is successful
    """
    obj: "SafetyCLI" = ctx.obj
    org_slug = None

    if (
        not obj.auth
        or not obj.auth.client
        or not obj.auth.client.is_using_auth_credentials()
    ):
        console.print(MSG_NEED_AUTHENTICATION)
        auth_choice = Prompt.ask(
            MSG_AUTH_PROMPT,
            choices=["r", "l", "R", "L"],
            default="L",
            show_choices=False,
            show_default=True,
            console=console,
        ).lower()

        from safety.auth.cli import auth_app
        from safety.cli_util import get_command_for

        login_command = get_command_for(name="login", typer_instance=auth_app)
        register_command = get_command_for(name="register", typer_instance=auth_app)

        ctx.obj.only_auth_msg = True

        if auth_choice == "r":
            ctx.invoke(register_command)
        else:
            ctx.invoke(login_command)
    else:
        data = None
        try:
            data = ctx.obj.auth.client.initialize()
        except Exception:
            logger.exception("Unable to load data on the init command")

        if data:
            org_slug = data.get("organization-data", {}).get("slug")

    return org_slug


def setup_firewall(
    ctx: Any, status: "FirewallConfigStatus", org_slug: Optional[str], console: Console
) -> Tuple[str, bool, bool, "FirewallConfigStatus"]:
    """
    Setup the firewall, this function also handles the output.

    Args:
        ctx: The CLI context
        status: The current status of the firewall
        org_slug: The organization slug
        console: The console object

    Returns:
        Tuple[bool, bool, FirewallConfigStatus]: A tuple containing the following:
            - bool: True if all tools are configured, False otherwise
            - bool: True if all tools are missing, False otherwise
            - FirewallConfigStatus: The current status of the firewall
    """
    emoji_check = f"[green]{load_emoji('✓')}[/green]"

    configured_index = configure_system(org_slug)
    configured_alias = configure_alias()
    if configured_alias is None:
        configured_alias = []

    console.line()

    configured = {}
    if configured_index:
        configured["index"] = configured_index

    if configured_alias:
        configured["alias"] = configured_alias

    if any([item[1] for item in configured_index]) or any(
        [item[1] for item in configured_alias]
    ):
        for config_type, results in configured.items():
            for tool_type, path in results:
                tool_name = tool_type.value
                index_type = "global"

                tool_config = status[tool_type]
                is_configured = False

                if path:
                    if config_type == "index":
                        msg = f"Configured {tool_name}’s {index_type} index"
                    else:
                        msg = f"Aliased {tool_name} to safety"

                    is_configured = True
                    configured_msg = f"{emoji_check} {msg}"

                    path = path.resolve()

                    if len(path.parts) > 1:
                        progressive_print([f"{configured_msg} (`{path}`)"])
                    else:
                        progressive_print([configured_msg])
                else:
                    if config_type == "index":
                        msg = f"{tool_name}’s {index_type} index"
                    else:
                        msg = f"{tool_name} alias"

                    prefix_msg = "Failed to configure"
                    emoji = {"text": "x ", "style": "red bold"}

                    # If there is a non-compatible global index
                    if tool_type in [ToolType.POETRY]:
                        prefix_msg = "Skipped"
                        msg += " - not supported by poetry"
                        emoji = {"text": "- ", "style": "gray bold"}
                        # TODO: Set None for now, to avoid mixing
                        # no configured error with skipped.
                        tool_config[config_type] = None
                    else:
                        is_configured = False

                    error = Text()
                    error.append(**emoji)
                    error.append(f"{prefix_msg} {msg}")
                    progressive_print([error])

                if config_obj := tool_config[config_type]:
                    config_obj.is_configured = is_configured

        console.line()
    else:
        error = Text()
        error.append("x ", style="red bold")
        error.append("Failed to configure system")
        progressive_print([error])

    completed = []
    missing = []
    for tool_type, tool_status in status.items():
        for config_type, config_obj in tool_status.items():
            if config_obj:
                if config_obj.is_configured:
                    completed.append(config_obj)
                else:
                    missing.append(config_obj)

    all_completed = not missing
    all_missing = not completed

    tools = [tool_type.value.title() for tool_type in status]
    completed_tools = (
        ", ".join(tools[:-1]) + " and " + tools[-1] if len(tools) > 1 else tools[0]
    )

    if all_completed:
        console.print(
            f"{emoji_check} {completed_tools} {MSG_SETUP_PACKAGE_FIREWALL_RESULT}"
        )
        console.print(MSG_SETUP_PACKAGE_FIREWALL_NOTE_STATUS)
    else:
        error = Text()
        error.append(Text.from_markup(MSG_SETUP_INCOMPLETE))
        progressive_print([error])

    console.line()

    emit_firewall_setup_completed(
        event_bus=ctx.obj.event_bus,
        ctx=ctx,
        status=status,
    )

    return completed_tools, all_completed, all_missing, status
