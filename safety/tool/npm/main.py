import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from safety.tool.constants import (
    NPMJS_PUBLIC_REPOSITORY_URL,
    NPMJS_ORGANIZATION_REPOSITORY_URL,
    NPMJS_PROJECT_REPOSITORY_URL,
)
from safety.tool.resolver import get_unwrapped_command
from safety.utils.pyapp_utils import get_path, get_env

from safety.console import main_console
from safety.tool.auth import build_index_url

logger = logging.getLogger(__name__)


class Npm:
    @classmethod
    def is_installed(cls) -> bool:
        """
        Checks if the NPM program is installed

        Returns:
            True if NPM is installed on system, or false otherwise
        """
        return shutil.which("npm", path=get_path()) is not None

    @classmethod
    def configure_project(
        cls,
        project_path: Path,
        org_slug: Optional[str],
        project_id: Optional[str],
        console: Console = main_console,
    ) -> Optional[Path]:
        """
        Configures Safety index url for specified npmrc file.

        Args:
            file (Path): Path to npmrc file.
            org_slug (str): Organization slug.
            project_id (str): Project identifier.
            console (Console): Console instance.
        """
        if not cls.is_installed():
            logger.error("NPM is not installed.")
            return None

        repository_url = (
            NPMJS_PROJECT_REPOSITORY_URL.format(org_slug, project_id)
            if project_id and org_slug
            else (
                NPMJS_ORGANIZATION_REPOSITORY_URL.format(org_slug)
                if org_slug
                else NPMJS_PUBLIC_REPOSITORY_URL
            )
        )

        project_root = project_path.resolve()
        if not project_root.is_dir():
            project_root = project_path.parent

        result = subprocess.run(
            [
                get_unwrapped_command(name="npm"),
                "config",
                "set",
                "registry",
                repository_url,
                "--location",
                "project",
            ],
            capture_output=True,
            cwd=project_root,
            env=get_env(),
        )

        if result.returncode != 0:
            logger.error(
                f"Failed to configure NPM project settings: {result.stderr.decode('utf-8')}"
            )
            return None

        return project_root

    @classmethod
    def configure_system(
        cls, org_slug: Optional[str], console: Console = main_console
    ) -> Optional[Path]:
        """
        Configures NPM system to use to Safety index url.
        """
        if not cls.is_installed():
            logger.error("NPM is not installed.")
            return None

        try:
            repository_url = (
                NPMJS_ORGANIZATION_REPOSITORY_URL.format(org_slug)
                if org_slug
                else NPMJS_PUBLIC_REPOSITORY_URL
            )
            result = subprocess.run(
                [
                    get_unwrapped_command(name="npm"),
                    "config",
                    "set",
                    "-g",
                    "registry",
                    repository_url,
                ],
                capture_output=True,
                env=get_env(),
            )

            if result.returncode != 0:
                logger.error(
                    f"Failed to configure NPM global settings: {result.stderr.decode('utf-8')}"
                )
                return None

            query_config_result = subprocess.run(
                [
                    get_unwrapped_command(name="npm"),
                    "config",
                    "get",
                    "globalconfig",
                ],
                capture_output=True,
                env=get_env(),
            )
            config_file_path = query_config_result.stdout.decode("utf-8").strip()

            if config_file_path:
                return Path(config_file_path)

            logger.error("Failed to match the config file path written by NPM.")
            return Path()
        except Exception:
            logger.exception("Failed to configure NPM global settings.")

        return None

    @classmethod
    def reset_system(cls, console: Console = main_console):
        # TODO: Move this logic and implement it in a more robust way
        try:
            subprocess.run(
                [
                    get_unwrapped_command(name="npm"),
                    "config",
                    "set",
                    "-g",
                    "registry",
                ],
                capture_output=True,
                env=get_env(),
            )
        except Exception:
            console.print("Failed to reset NPM global settings.")

    @classmethod
    def build_index_url(cls, ctx: typer.Context, index_url: Optional[str]) -> str:
        return build_index_url(ctx, index_url, "npm")
