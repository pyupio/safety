from abc import ABC, abstractmethod
import json
import os
import sys
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
from filelock import FileLock
import typer
from safety.constants import USER_CONFIG_DIR
from safety.events.utils import emit_tool_command_executed
from safety.init.command import init_scan_ui
from safety.models import ToolResult
from safety.tool.constants import (
    PROJECT_CONFIG,
    MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES,
)
from safety.tool.typosquatting import TyposquattingProtection

from .environment_diff import EnvironmentDiffTracker
from .intents import CommandToolIntention, ToolIntentionType
from .resolver import get_unwrapped_command

from safety_schemas.models.events.types import ToolType

from safety.events.utils import emit_diff_operations

from .utils import (
    is_os_supported,
)

import logging

logger = logging.getLogger(__name__)


class BaseCommand(ABC):
    """
    Abstract base class for tool commands.
    Requires subclasses to implement all required attributes.
    """

    def __init__(
        self,
        args: List[str],
        capture_output: bool = False,
        intention: Optional[CommandToolIntention] = None,
        command_alias_used: Optional[str] = None,
    ) -> None:
        """
        Initialize the command.

        Args:
            args: Command arguments
            capture_output: Whether to capture command output
        """
        self._args = args
        self._intention = intention
        self._capture_output = capture_output
        self._command_alias_used = command_alias_used

        self._tool_type = self.get_tool_type()
        self._lock_path = USER_CONFIG_DIR / self.get_lock_path()
        self._filelock = FileLock(self._lock_path, 10)
        self.__typosquatting_protection = TyposquattingProtection(
            MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES
        )

        self._diff_tracker = self.get_diff_tracker()
        self._should_track_state = self.should_track_state()

    @abstractmethod
    def get_tool_type(self) -> ToolType:
        """
        Get the tool type for this command type.
        Must be implemented by subclasses.

        Returns:
            ToolType: Tool type
        """
        pass

    @abstractmethod
    def get_command_name(self) -> List[str]:
        """
        Get the command name for this command type.
        Must be implemented by subclasses.

        Returns:
            List[str]: Command name as a list (e.g. ["pip"])
        """
        pass

    @abstractmethod
    def get_lock_path(self) -> str:
        """
        Get the lock path for this command type.
        Must be implemented by subclasses.

        Returns:
            str: Path to the lock file
        """
        pass

    @abstractmethod
    def get_diff_tracker(self) -> EnvironmentDiffTracker:
        """
        Get the diff tracker instance for this command type.
        Must be implemented by subclasses.

        Returns:
            EnvironmentDiffTracker: Diff tracker instance
        """
        pass

    def should_track_state(self) -> bool:
        """
        Determine if this command should track state changes.
        Subclasses can override for more sophisticated logic.

        Returns:
            bool: True if state changes should be tracked
        """
        # Default implementation checks for common installation commands
        command_str = " ".join(self._args).lower()
        return any(
            cmd in command_str
            for cmd in ["install", "uninstall", "add", "remove", "sync"]
        )

    def get_package_list_command(self) -> List[str]:
        """
        Get the command to list installed packages.
        Subclasses must override this to provide the correct command.

        Returns:
            List[str]: Command to list packages in JSON format
        """
        # Default implementation, should be overridden by subclasses
        return [*self.get_command_name(), "list", "--format=json"]

    def parse_package_list_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse the output of the package list command.
        Subclasses can override this for custom parsing logic.

        Args:
            output: Command output

        Returns:
            List[Dict[str, Any]]: List of package dictionaries
        """
        # Default implementation assumes JSON output
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            # Log error and return empty list
            logger.exception(f"Error parsing package list output: {output[:100]}...")
            return []

    def _initialize_diff_tracker(self, ctx: typer.Context):
        """
        Common implementation to initialize the diff tracker.
        Can be called by child classes in their before() implementation.
        """
        current_packages = self._get_installed_packages(ctx)
        self._diff_tracker.set_before_state(current_packages)

    def __run_scan_if_needed(self, ctx: typer.Context, silent: bool = True):
        if not is_os_supported():
            return

        target = Path.cwd()
        if (target / PROJECT_CONFIG).is_file():
            if silent:
                self.__run_silent_scan(ctx, target)
            else:
                init_scan_ui(ctx, prompt_user=True)

    def __run_silent_scan(self, ctx: typer.Context, target: Path):
        """
        Run a scan silently without displaying progress.
        """
        target_arg = str(target.resolve())
        CMD = ("safety", "scan", "--target", target_arg)

        logger.info(f"Launching silent scan: {CMD}")

        try:
            kwargs = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "stdin": subprocess.DEVNULL,
                "shell": False,
            }

            if sys.platform == "win32":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True

            subprocess.Popen(CMD, **kwargs)
        except Exception as e:
            logger.error(f"Failed to start independent scan: {e}")

    def _handle_command_result(self, ctx: typer.Context, result: ToolResult):
        """
        Common implementation to handle command results.
        Can be called by child classes in their after() implementation.
        """
        process = result.process
        if process:
            if process.returncode == 0 and self._should_track_state:
                self._perform_diff(ctx)
                self.__run_scan_if_needed(ctx, silent=True)

            emit_tool_command_executed(
                ctx.obj.event_bus,
                ctx,  # type: ignore
                tool=self._tool_type,
                result=result,
            )

    def is_installed(self) -> bool:
        """
        Checks if the tool program is reachable

        Returns:
            True if the tool is reachable on system, or false otherwise
        """
        cmd_name = self.get_command_name()[0]
        return shutil.which(cmd_name) is not None

    def before(self, ctx: typer.Context):
        if self._should_track_state:
            self._initialize_diff_tracker(ctx)

        if self._intention and self._intention.packages:
            for dep in self._intention.packages:
                if reviewed_name := self.__typosquatting_protection.coerce(dep.name):
                    dep.corrected_text = dep.original_text.replace(
                        dep.name, reviewed_name
                    )
                    dep.name = reviewed_name
                    self._args[dep.arg_index] = dep.corrected_text

    def after(self, ctx: typer.Context, result: ToolResult):
        self._handle_command_result(ctx, result)

    def execute(self, ctx: typer.Context) -> ToolResult:
        with self._filelock:
            self.before(ctx)
            # TODO: Safety should redirect to the proper pip/tool, if the user is
            # using pip3, it should be redirected to pip3, not pip to avoid any
            # issues.

            cmd = self.get_command_name()
            cmd_name = cmd[0]
            pre_args = [get_unwrapped_command(name=cmd_name)] + cmd[1:]
            args = pre_args + self.__remove_safety_args(self._args)

            started_at = time.monotonic()
            process = subprocess.run(
                args, capture_output=self._capture_output, env=self.env(ctx)
            )

            duration_ms = int((time.monotonic() - started_at) * 1000)

            result = ToolResult(process=process, duration_ms=duration_ms)

            self.after(ctx, result)

            return result

    def env(self, ctx: typer.Context):
        """
        Returns the environment.
        Args:
            ctx (typer.Context): The context.
        Returns:
            dict: The environment.
        """
        return os.environ.copy()

    def __remove_safety_args(self, args: List[str]):
        return [arg for arg in args if not arg.startswith("--safety")]

    def _get_installed_packages(self, ctx: typer.Context) -> List[Dict[str, Any]]:
        """
        Get currently installed packages
        """
        command = self.get_package_list_command()
        base_cmd = [get_unwrapped_command(name=command[0])]
        args = base_cmd + command[1:]

        result = subprocess.run(args, capture_output=True, env=self.env(ctx), text=True)
        return self.parse_package_list_output(result.stdout)

    def _perform_diff(self, ctx: typer.Context):
        """
        Perform the diff operation.
        Can be called by child classes when appropriate.
        """
        current_packages = self._get_installed_packages(ctx)
        self._diff_tracker.set_after_state(current_packages)
        added, removed, updated = self._diff_tracker.get_diff()

        emit_diff_operations(
            ctx.obj.event_bus,
            ctx,  # type: ignore
            added=added,
            removed=removed,
            updated=updated,
            by_tool=self._tool_type,
        )


class ToolCommandLineParser(ABC):
    """
    Abstract base class for tool command line parsers
    """

    def __init__(self):
        self._tool_name = self.get_tool_name()

    @abstractmethod
    def get_tool_name(self) -> str:
        """
        Name of the tool
        """
        pass

    @property
    @abstractmethod
    def intention_mapping(self) -> Dict[str, ToolIntentionType]:
        """
        Maps commands to intention types
        """
        pass

    def can_handle(self, args: List[str]) -> bool:
        """
        Check if this parser can handle the given arguments
        """
        if not args or len(args) < 1:
            return False

        return args[0].lower() in self.intention_mapping

    @abstractmethod
    def parse(self, args: List[str]) -> Optional[CommandToolIntention]:
        """
        Parse the command line arguments

        Args:
            args: Command line arguments

        Returns:
            CommandToolIntention: Parsed command with normalized intention
        """
        pass

    def map_intention(self, command: str) -> ToolIntentionType:
        """
        Map a command to its corresponding intention type

        Args:
            command: Command to map

        Returns:
            ToolIntentionType: Normalized intention type
        """
        return self.intention_mapping.get(command.lower(), ToolIntentionType.UNKNOWN)
