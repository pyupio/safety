from abc import ABC, abstractmethod
import json
import os
import sys
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
import typer
from safety.events.utils import emit_tool_command_executed
from safety.models import ToolResult
from safety.tool.constants import (
    PROJECT_CONFIG,
    MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES,
)
from safety.tool.typosquatting import TyposquattingProtection

from .environment_diff import EnvironmentDiffTracker
from .intents import CommandToolIntention, ToolIntentionType, Dependency
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
        if self._intention:
            return self._intention.modifies_packages()

        return False

    def get_package_list_command(self) -> List[str]:
        """
        Get the command to list installed packages.
        Subclasses must override this to provide the correct command.

        Returns:
            List[str]: Command to list packages in JSON format
        """
        # Default implementation, should be overridden by subclasses
        return [*self.get_command_name(), "list", "-v", "--format=json"]

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
                from safety.init.command import init_scan_ui

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
                self._perform_diff(ctx, result.tool_path)
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

        if (
            self._intention
            and self._intention.packages
            and self._intention.intention_type is not ToolIntentionType.REMOVE_PACKAGE
        ):
            for dep in self._intention.packages:
                if reviewed_name := self.__typosquatting_protection.coerce(
                    self._intention, dep.name
                ):
                    dep.corrected_text = dep.original_text.replace(
                        dep.name, reviewed_name
                    )
                    # NOTE: Mutation here is a workaround, it should be improved in the future.
                    dep.name = reviewed_name
                    self._args[dep.arg_index] = dep.corrected_text

    def after(self, ctx: typer.Context, result: ToolResult):
        self._handle_command_result(ctx, result)

    def execute(self, ctx: typer.Context) -> ToolResult:
        self.before(ctx)
        # TODO: Safety should redirect to the proper pip/tool, if the user is
        # using pip3, it should be redirected to pip3, not pip to avoid any
        # issues.

        cmd = self.get_command_name()
        cmd_name = cmd[0]
        tool_path = get_unwrapped_command(name=cmd_name)
        pre_args = [tool_path] + cmd[1:]
        args = pre_args + self.__remove_safety_args(self._args)

        started_at = time.monotonic()
        process = subprocess.run(
            args, capture_output=self._capture_output, env=self.env(ctx)
        )

        duration_ms = int((time.monotonic() - started_at) * 1000)

        result = ToolResult(
            process=process, duration_ms=duration_ms, tool_path=tool_path
        )

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

    def _perform_diff(self, ctx: typer.Context, tool_path: Optional[str] = None):
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
            tool_path=tool_path,
            by_tool=self._tool_type,
        )


@dataclass
class ParsedCommand:
    """
    Represents a parsed command with its hierarchy
    """

    chain: List[str]  # e.g., ['pip', 'install'] or ['add']
    intention: ToolIntentionType
    remaining_args_start: int  # Where options/packages start


class ToolCommandLineParser(ABC):
    """
    Base implementation of a command line parser for tools
    """

    def __init__(self):
        self._tool_name = self.get_tool_name()

    @abstractmethod
    def get_tool_name(self) -> str:
        pass

    @abstractmethod
    def get_command_hierarchy(self) -> Dict[str, Union[ToolIntentionType, Dict]]:
        """
        Return command hierarchy only. No option definitions needed.

        Example:
        {
            'add': ToolIntentionType.ADD_PACKAGE,
            'pip': {
                'install': ToolIntentionType.ADD_PACKAGE,
                'uninstall': ToolIntentionType.REMOVE_PACKAGE
            }
        }
        """
        pass

    @abstractmethod
    def get_known_flags(self) -> Dict[str, Set[str]]:
        """
        Return known flags that don't take values.
        Format: {command_path: {flag_names}}

        Example:
        {
            'global': {'verbose', 'v', 'quiet', 'q', 'help', 'h'},
            'install': {'upgrade', 'U', 'dry-run', 'no-deps', 'user'}
        }
        """
        pass

    def parse(
        self, args: List[str], start_from: int = 0
    ) -> Optional[CommandToolIntention]:
        """
        Main parsing method
        """

        parsed_command = self._parse_command_hierarchy(args, start_from)
        if not parsed_command:
            return None

        remaining_args = args[parsed_command.remaining_args_start :]
        options, packages = self._parse_options_and_packages(
            remaining_args, parsed_command
        )

        return CommandToolIntention(
            tool=self._tool_name,
            command=" ".join(parsed_command.chain),
            command_chain=parsed_command.chain,
            intention_type=parsed_command.intention,
            packages=packages,
            options=options,
            raw_args=args.copy(),
        )

    def _is_known_flag(self, option_key: str, command_chain: List[str]) -> bool:
        """
        Check if option is a known flag using command context
        """
        known_flags = self.get_known_flags()

        # Try command-specific flags first, then global
        candidates = []
        if command_chain:
            for i in range(len(command_chain), 0, -1):
                candidates.append(".".join(command_chain[:i]))
        candidates.append("global")

        for candidate in candidates:
            if candidate in known_flags and option_key in known_flags[candidate]:
                return True

        return False

    def _parse_command_hierarchy(
        self, args: List[str], start_from: int
    ) -> Optional[ParsedCommand]:
        """
        Parse the command hierarchy - stop at first non-command
        """
        if not args or start_from >= len(args):
            return None

        hierarchy = self.get_command_hierarchy()
        command_chain = []
        current_level = hierarchy
        i = start_from

        while i < len(args):
            arg = args[i].lower()

            # Check if this argument is a valid command at current level
            if isinstance(current_level, dict) and arg in current_level:
                command_chain.append(arg)
                current_level = current_level[arg]

                # If we hit an intention type, we're done with commands
                if isinstance(current_level, ToolIntentionType):
                    return ParsedCommand(
                        chain=command_chain,
                        intention=current_level,
                        remaining_args_start=i + 1,
                    )

            i += 1

        # Check if we ended on a valid intention
        if isinstance(current_level, ToolIntentionType):
            return ParsedCommand(
                chain=command_chain, intention=current_level, remaining_args_start=i
            )

        return None

    def _parse_options_and_packages(
        self, args: List[str], parsed_command: ParsedCommand
    ) -> Tuple[Dict[str, Any], List[Dependency]]:
        """
        Simple parsing: hyphens = options, everything else = packages/args
        """

        options = {}
        packages = []

        i = 0
        while i < len(args):
            arg = args[i]

            if arg.startswith("-"):
                option_key, option_data, consumed = self._parse_option(
                    args, i, parsed_command
                )
                options[option_key] = option_data
                i += consumed
            else:
                arg_index = parsed_command.remaining_args_start + i

                dep = self._try_parse_package(arg, arg_index, parsed_command)

                if dep:
                    packages.append(dep)
                else:
                    self._store_unknown_argument(options, arg, arg_index)

                i += 1

        return options, packages

    def _parse_option(
        self, args: List[str], i: int, parsed_command: ParsedCommand
    ) -> Tuple[str, Dict[str, Any], int]:
        """
        Parse a single option, args[i] is expected to be a hyphenated option
        """
        arg = args[i]
        arg_index = parsed_command.remaining_args_start + i

        # Handle --option=value format
        if "=" in arg:
            option_part, value_part = arg.split("=", 1)
            option_key = option_part.lstrip("-")
            option_data = {
                "arg_index": arg_index,
                "raw_option": option_part,
                "value": value_part,
            }
            return option_key, option_data, 1

        # Handle --option, -option formats for known flags
        option_key = arg.lstrip("-")

        if self._is_known_flag(option_key, parsed_command.chain):
            # It's a flag - doesn't take value
            option_data = {
                "arg_index": arg_index,
                "raw_option": arg,
                "value": True,
            }
            return option_key, option_data, 1

        # Handle --option value, -option value formats
        if i + 1 < len(args) and not args[i + 1].startswith("-"):
            option_data = {
                "arg_index": arg_index,
                "raw_option": arg,
                "value": args[i + 1],
                "value_index": arg_index + 1,
            }
            return option_key, option_data, 2

        # Handle --option, -option formats for unknown flags
        option_data = {
            "arg_index": arg_index,
            "raw_option": arg,
            "value": True,
        }
        return option_key, option_data, 1

    def _should_parse_as_package(self, intention: ToolIntentionType) -> bool:
        """
        Check if arguments should be parsed as packages
        """
        return intention in [
            ToolIntentionType.ADD_PACKAGE,
            ToolIntentionType.REMOVE_PACKAGE,
            ToolIntentionType.DOWNLOAD_PACKAGE,
            ToolIntentionType.SEARCH_PACKAGES,
        ]

    def _try_parse_package(
        self, arg: str, index: int, parsed_command: ParsedCommand
    ) -> Optional[Dependency]:
        """
        Try to parse argument as package, return None if fails
        """
        if self._should_parse_as_package(parsed_command.intention):
            return self._parse_package_spec(arg, index)

        return None

    def _store_unknown_argument(self, options: Dict, arg: str, index: int):
        """
        Store non-package arguments in options as unknown
        """
        key = f"unknown_{len([k for k in options.keys() if k.startswith('unknown_')])}"
        options[key] = {
            "arg_index": index,
            "value": arg,
        }

    def _parse_package_spec(
        self, spec_str: str, arg_index: int
    ) -> Optional[Dependency]:
        try:
            from packaging.requirements import Requirement

            # TODO: pip install . should be excluded
            req = Requirement(spec_str)

            return Dependency(
                name=req.name,
                version_constraint=str(req.specifier),
                extras=req.extras,
                arg_index=arg_index,
                original_text=spec_str,
            )
        except Exception:
            # If spec parsing fails, just ignore for now
            return None
