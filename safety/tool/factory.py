"""
Factory for creating and registering package manager commands.
"""

import importlib
import logging
from pathlib import Path
import sys
from typing import TYPE_CHECKING, cast

import typer

from safety.decorators import notify
from safety.error_handlers import handle_cmd_exception
from safety.tool.decorators import prepare_tool_execution

from .definitions import TOOLS, ToolCommandModel

try:
    from typing import Annotated  # type: ignore[import]
except ImportError:
    from typing_extensions import Annotated


if TYPE_CHECKING:
    from safety.cli_util import SafetyCLILegacyGroup
    from safety.tool import ToolResult
    from safety.cli_util import CustomContext

logger = logging.getLogger(__name__)


class ToolCommandFactory:
    """
    Factory for creating command apps per tool.
    """

    def _get_command_class_name(self, pkg_name: str) -> str:
        """
        Get the command class name for a package manager.

        Args:
            pkg_name: Name of the package manager

        Returns:
            str: Command class name
        """
        return f"{pkg_name.capitalize()}Command"

    def _create_tool_group(
        self,
        *,
        tool_command: ToolCommandModel,
        command_class_name: str,
    ) -> typer.Typer:
        """
        Create a standard app for a package manager based on tool command model.

        Args:
            tool_command: Tool command model with configuration
            command_class_name: Name of the command class

        Returns:
            typer.Typer: The created Typer group
        """
        # Get command settings from the tool command model
        cmd_settings = tool_command.get_command_settings()

        from safety.cli_util import SafetyCLICommand, SafetyCLISubGroup

        app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)

        # Main command
        @app.command(
            cls=SafetyCLICommand,
            help=cmd_settings.help,
            name=cmd_settings.name,
            options_metavar=cmd_settings.options_metavar,
            context_settings=cmd_settings.context_settings.as_dict(),
        )
        @handle_cmd_exception
        @prepare_tool_execution
        @notify
        def tool_main_command(
            ctx: typer.Context,
            target: Annotated[
                Path,
                typer.Option(
                    exists=True,
                    file_okay=False,
                    dir_okay=True,
                    writable=False,
                    readable=True,
                    resolve_path=True,
                    show_default=False,
                ),  # type: ignore
            ] = Path("."),
        ):
            """
            Base command handler that forwards to the appropriate command class.

            Args:
                ctx: Typer context
            """
            # Get the command class directly using importlib
            module_name = f"safety.tool.{tool_command.name}.command"
            try:
                module = importlib.import_module(module_name)
                command_class = getattr(module, command_class_name, None)
            except ImportError:
                logger.error(f"Could not import {module_name}")
                command_class = None

            if not command_class:
                typer.echo(f"Command class {command_class_name} not found")
                return

            parent_ctx = cast("CustomContext", ctx.parent)
            command = command_class.from_args(
                ctx.args,
                command_alias_used=parent_ctx.command_alias_used,
            )
            if not command.is_installed():
                typer.echo(f"Tool {tool_command.name} is not installed.")
                sys.exit(1)

            result: "ToolResult" = command.execute(ctx)

            if result.process.returncode != 0:
                sys.exit(result.process.returncode)

        # We can support subcommands in the future
        return app

    def auto_register_tools(self, group: "SafetyCLILegacyGroup") -> None:
        """
        Auto-register commands from the definitions configuration.

        Args:
            group: The main Safety CLI group

        Returns:
            Dict[str, typer.Typer]: Dictionary of registered apps
        """
        for tool_command_config in TOOLS:
            tool_name = tool_command_config.name
            # Get the command class name
            command_class_name = self._get_command_class_name(tool_name)

            tool_app = None
            # First check if custom_app is specified in the tool model
            if tool_command_config.custom_app:
                try:
                    module_path, attr_name = tool_command_config.custom_app.rsplit(
                        ".", 1
                    )
                    module = importlib.import_module(module_path)
                    tool_app = getattr(module, attr_name, None)

                    if not tool_app:
                        logger.error(
                            f"Custom app {attr_name} not found in {module_path}"
                        )

                except (ImportError, AttributeError, ValueError) as e:
                    logger.exception(
                        f"Failed to import custom app for {tool_name}: {e}"
                    )

            # If no custom_app or it failed, create the tool app
            if not tool_app:
                tool_app = self._create_tool_group(
                    tool_command=tool_command_config,
                    command_class_name=command_class_name,
                )

            # We can support subcommands in the future

            # Register the tool app
            group.add_command(typer.main.get_command(tool_app), name=tool_name)

            logger.info(f"Registered auto-generated command for {tool_name}")


tool_commands = ToolCommandFactory()
