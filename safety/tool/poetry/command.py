from pathlib import Path
import sys
from typing import TYPE_CHECKING, List, Optional, Tuple

import typer

from safety.tool.poetry.parser import PoetryParser

from ..base import BaseCommand, ToolIntentionType

from ..environment_diff import EnvironmentDiffTracker, PipEnvironmentDiffTracker
from safety_schemas.models.events.types import ToolType

from safety.console import main_console as console

PO_LOCK = "po_lock"

if TYPE_CHECKING:
    from ..environment_diff import EnvironmentDiffTracker


if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


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

    @classmethod
    def from_args(cls, args: List[str]):
        parser = PoetryParser()

        if intention := parser.parse(args):
            if intention.intention_type is ToolIntentionType.ADD_PACKAGE:
                return PoetryAddCommand(args, intention=intention)

        return PoetryGenericCommand(args)


class PoetryGenericCommand(PoetryCommand):
    pass


class PoetryAddCommand(PoetryCommand):
    def has_safety_source_in_pyproject(self) -> bool:
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

        if not self.has_safety_source_in_pyproject():
            console.print(
                "\nError: 'safety' source is not configured in pyproject.toml, run 'safety init' to fix this.",
            )
            sys.exit(1)

        _, modified_args = self.patch_source_option(self._args)
        self._args = modified_args
        print(self._args)
