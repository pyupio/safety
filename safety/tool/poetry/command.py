from pathlib import Path
import sys
from typing import TYPE_CHECKING, List, Optional, Tuple
import logging
import typer

from safety.tool.utils import PoetryPyprojectConfigurator

from .constants import MSG_SAFETY_SOURCE_ADDED, MSG_SAFETY_SOURCE_NOT_ADDED
from .parser import PoetryParser

from ..base import BaseCommand, ToolIntentionType

from ..environment_diff import EnvironmentDiffTracker, PipEnvironmentDiffTracker
from safety_schemas.models.events.types import ToolType

from safety.console import main_console as console

PO_LOCK = "safety-po.lock"

if TYPE_CHECKING:
    from ..environment_diff import EnvironmentDiffTracker

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

logger = logging.getLogger(__name__)


class PoetryCommand(BaseCommand):
    """
    Main class for hooks into poetry commands.
    """

    def get_tool_type(self) -> ToolType:
        return ToolType.POETRY

    def get_command_name(self) -> List[str]:
        return ["poetry"]

    def get_lock_path(self) -> str:
        return PO_LOCK

    def get_diff_tracker(self) -> "EnvironmentDiffTracker":
        # pip diff tracker will be enough for poetry
        return PipEnvironmentDiffTracker()

    def should_track_state(self) -> bool:
        """
        Determine if the Poetry command will change package dependencies in the virtual environment.

        Returns:
            bool: True if command will modify installed packages, False otherwise
        """
        command_str = " ".join(self._args).lower()

        package_modifying_commands = [
            "add",
            "remove",
            "install",
            "uninstall",
            "update",
            "sync",
        ]

        return any(cmd in command_str for cmd in package_modifying_commands)

    def get_package_list_command(self) -> List[str]:
        """
        Get the package list of a poetry virtual environment.

        This implementation uses pip to list packages.

        Returns:
            List[str]: Command to list packages in JSON format
        """
        return ["poetry", "run", "pip", "list", "--format=json"]

    def _has_safety_source_in_pyproject(self) -> bool:
        """
        Check if 'safety' source exists in pyproject.toml
        """
        if not Path("pyproject.toml").exists():
            return False

        try:
            # Parse the TOML file
            with open("pyproject.toml", "rb") as f:
                pyproject = tomllib.load(f)

            poetry_config = pyproject.get("tool", {}).get("poetry", {})

            sources = poetry_config.get("source", [])
            if isinstance(sources, dict):
                return "safety" in sources
            else:
                return any(source.get("name") == "safety" for source in sources)

        except (FileNotFoundError, KeyError, tomllib.TOMLDecodeError):
            return False

    def before(self, ctx: typer.Context):
        super().before(ctx)

        if self._intention and self._intention.intention_type in [
            ToolIntentionType.SYNC_PACKAGES,
            ToolIntentionType.ADD_PACKAGE,
        ]:
            if not self._has_safety_source_in_pyproject():
                org_slug = None
                try:
                    data = ctx.obj.auth.client.initialize()
                    org_slug = data.get("organization-data", {}).get("slug")
                except Exception:
                    logger.exception(
                        "Unable to pull the org slug from the initialize endpoint."
                    )

                try:
                    configurator = PoetryPyprojectConfigurator()
                    prj_slug = ctx.obj.project.id if ctx.obj.project else None
                    if configurator.configure(
                        Path("pyproject.toml"), org_slug, prj_slug
                    ):
                        console.print(
                            MSG_SAFETY_SOURCE_ADDED,
                        )
                except Exception:
                    logger.exception("Unable to configure the pyproject.toml file.")
                    console.print(
                        MSG_SAFETY_SOURCE_NOT_ADDED,
                    )

    @classmethod
    def from_args(cls, args: List[str], **kwargs):
        parser = PoetryParser()

        if intention := parser.parse(args):
            kwargs["intention"] = intention
            if intention.intention_type is ToolIntentionType.ADD_PACKAGE:
                return PoetryAddCommand(args, **kwargs)

        return PoetryGenericCommand(args, **kwargs)


class PoetryGenericCommand(PoetryCommand):
    pass


class PoetryAddCommand(PoetryCommand):
    def patch_source_option(
        self, args: List[str], new_source: str = "safety"
    ) -> Tuple[Optional[str], List[str]]:
        """
        Find --source argument and its value in a list of args, create a modified copy
        with your custom source, and return both.

        Args:
            args: List[str] - Command line arguments

        Returns:
            tuple: (source_value, modified_args, original_args)
        """
        source_value = None
        modified_args = args.copy()

        for i in range(len(args)):
            if args[i].startswith("--source="):
                # Handle --source=value format
                source_value = args[i].split("=", 1)[1]
                modified_args[i] = f"--source={new_source}"
                break
            elif args[i] == "--source" and i < len(args) - 1:
                # Handle --source value format
                source_value = args[i + 1]
                modified_args[i + 1] = new_source
                break

        return source_value, modified_args

    def before(self, ctx: typer.Context):
        super().before(ctx)

        _, modified_args = self.patch_source_option(self._args)
        self._args = modified_args
