import abc
import json
import os.path
import re
import subprocess
from pathlib import Path
from sys import platform
from tempfile import mkstemp
import time

import nltk
import typer
from filelock import FileLock
from rich.padding import Padding
from rich.prompt import Prompt

from safety.console import main_console as console
from safety.constants import PIP_LOCK
from safety.models import ToolResult
from safety.tool.constants import (
    MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES,
    PROJECT_CONFIG,
)
from safety.tool.pip import Pip
from safety.tool.poetry import Poetry
from safety.tool.resolver import get_unwrapped_command
from safety.tool.environment_diff import PipEnvironmentDiffTracker

from safety.events.utils import emit_diff_operations, emit_tool_command_executed

from safety_schemas.models.events.types import ToolType

from typing_extensions import List

from typing import Any, Dict, TYPE_CHECKING, Optional

if TYPE_CHECKING:
    pass


def is_os_supported():
    return platform in ["linux", "linux2", "darwin", "win32"]


class BuildFileConfigurator(abc.ABC):
    @abc.abstractmethod
    def is_supported(self, file: Path) -> bool:
        """
        Returns whether a specific file is supported by this class.
        Args:
            file (str): The file to check.
        Returns:
            bool: Whether the file is supported by this class.
        """
        pass

    @abc.abstractmethod
    def configure(
        self, file: Path, org_slug: Optional[str], project_id: Optional[str]
    ) -> None:
        """
        Configures specific file.
        Args:
            file (str): The file to configure.
            org_slug (str): The organization slug.
            project_id (str): The project id.
        """
        pass


class PipRequirementsConfigurator(BuildFileConfigurator):
    __file_name_pattern = re.compile("^([a-zA-Z_-]+)?requirements([a-zA-Z_-]+)?.txt$")

    def is_supported(self, file: Path) -> bool:
        return self.__file_name_pattern.match(os.path.basename(file)) is not None

    def configure(
        self, file: Path, org_slug: Optional[str], project_id: Optional[str]
    ) -> None:
        Pip.configure_requirements(file, org_slug, project_id)  # type: ignore


class PoetryPyprojectConfigurator(BuildFileConfigurator):
    __file_name_pattern = re.compile("^pyproject.toml$")

    def is_supported(self, file: Path) -> bool:
        return self.__file_name_pattern.match(
            os.path.basename(file)
        ) is not None and Poetry.is_poetry_project_file(file)

    def configure(
        self, file: Path, org_slug: Optional[str], project_id: Optional[str]
    ) -> None:
        Poetry.configure_pyproject(file, org_slug, project_id)  # type: ignore


# TODO: Review if we should move this/hook up this into interceptors.
class ToolConfigurator(abc.ABC):
    @abc.abstractmethod
    def configure(self, org_slug: Optional[str]) -> None:
        """
        Configures specific tool.
        Args:
            org_slug (str): The organization slug.
        """
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        """
        Resets specific tool.
        """
        pass


class PipConfigurator(ToolConfigurator):
    def configure(self, org_slug: Optional[str]) -> None:
        Pip.configure_system(org_slug)

    def reset(self) -> None:
        Pip.reset_system()


class BaseCommand(abc.ABC):
    @abc.abstractmethod
    def execute(self, ctx: typer.Context) -> None:
        """
        Executes the command.
        Args:
            ctx (typer.Context): The context.
        """
        pass

    @abc.abstractmethod
    def before(self, ctx: typer.Context) -> None:
        """
        Executes before the command.
        Args:
            ctx (typer.Context): The context.
        """
        pass

    @abc.abstractmethod
    def after(self, ctx: typer.Context, result: ToolResult) -> None:
        """
        Executes after the command.
        Args:
            ctx (typer.Context): The context.
            result (ToolResult): The result.
        """
        pass

    @abc.abstractmethod
    def env(self, ctx: typer.Context) -> dict:
        """
        Returns the environment.
        Args:
            ctx (typer.Context): The context.
        Returns:
            dict: The environment.
        """
        pass


class PipCommand(BaseCommand):
    def __init__(self, args: List[str], capture_output: bool = False) -> None:
        self._args = args
        self.__capture_output = capture_output
        self.__filelock = FileLock(PIP_LOCK, 10)
        self._diff_tracker = PipEnvironmentDiffTracker()
        self._name = ["pip"]

    def _initialize_diff_tracker(self, ctx: typer.Context):
        """
        Common implementation to initialize the diff tracker.
        Can be called by child classes in their before() implementation.
        """
        current_packages = self._get_installed_packages(ctx)
        self._diff_tracker.set_before_state(current_packages)

    def _handle_command_result(self, ctx: typer.Context, result: ToolResult):
        """
        Common implementation to handle command results.
        Can be called by child classes in their after() implementation.
        """
        process = result.process
        if process:
            if process.returncode == 0:
                self._perform_diff(ctx)

            emit_tool_command_executed(
                ctx.obj.event_bus,
                ctx,  # type: ignore
                tool=ToolType.PIP,
                result=result,
            )

    def before(self, ctx: typer.Context):
        self._initialize_diff_tracker(ctx)

    def after(self, ctx: typer.Context, result: ToolResult):
        self._handle_command_result(ctx, result)

    def execute(self, ctx: typer.Context):
        with self.__filelock:
            self.before(ctx)
            # TODO: Safety should redirect to the proper pip, if the user is
            # using pip3, it should be redirected to pip3, not pip to avoid any
            # issues.

            pre_args = [get_unwrapped_command(name=self._name[0])]
            args = pre_args + self.__remove_safety_args(self._args)

            started_at = time.monotonic()
            process = subprocess.run(
                args, capture_output=self.__capture_output, env=self.env(ctx)
            )

            duration_ms = int((time.monotonic() - started_at) * 1000)

            result = ToolResult(process=process, duration_ms=duration_ms)

            self.after(ctx, result)

    def env(self, ctx: typer.Context):
        return os.environ.copy()

    @classmethod
    def from_args(cls, args: List[str]):
        if "install" in args:
            return PipInstallCommand(args)
        elif "uninstall" in args:
            return PipUninstallCommand(args)
        else:
            return PipGenericCommand(args)

    def __remove_safety_args(self, args: List[str]):
        return [arg for arg in args if not arg.startswith("--safety")]

    def _get_installed_packages(self, ctx: typer.Context) -> List[Dict[str, Any]]:
        """
        Get the currently installed packages as a Python dictionary.
        """
        pre_args = [get_unwrapped_command(name=self._name[0])] + self._name[1:]
        args = pre_args + ["list", "--format=json"]
        result = subprocess.run(args, capture_output=True, env=self.env(ctx), text=True)
        # TODO: Handle error
        return json.loads(result.stdout)

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
            by_tool=ToolType.PIP,
        )


class PipGenericCommand(PipCommand):
    pass


class PipInstallCommand(PipCommand):
    def __init__(self, args: List[str]) -> None:
        super().__init__(args)
        self.package_names = []
        self.__index_url = None

    def before(self, ctx: typer.Context):
        super().before(ctx)
        args = self._args

        ranges_to_delete = []
        for ind, val in enumerate(args):
            if ind > 0 and (
                args[ind - 1].startswith("-i")
                or args[ind - 1].startswith("--index-url")
            ):
                if args[ind].startswith("https://pkgs.safetycli.com"):
                    self.__index_url = args[ind]

                ranges_to_delete.append((ind - 1, ind))
            elif ind > 0 and (
                args[ind - 1] == "-r" or args[ind - 1] == "--requirement"
            ):
                requirement_file = args[ind]

                if not Path(requirement_file).is_file():
                    continue

                with open(requirement_file, "r") as f:
                    fd, tmp_requirements_path = mkstemp(
                        suffix="safety-requirements.txt", text=True
                    )
                    with os.fdopen(fd, "w") as tf:
                        requirements = re.sub(
                            r"^(-i|--index-url).*$", "", f.read(), flags=re.MULTILINE
                        )
                        tf.write(requirements)

                    args[ind] = tmp_requirements_path
            elif (
                ind > 0
                and (
                    not args[ind - 1].startswith("-e")
                    or not args[ind - 1].startswith("--editable")
                )
                and not args[ind].startswith("-")
            ):
                if args[ind] == ".":
                    continue

                package_name = args[ind]
                (valid, candidate_package_name) = self.__check_typosquatting(
                    package_name
                )
                if not valid:
                    prompt = f"You are about to install {package_name} package. Did you mean to install {candidate_package_name}?"
                    answer = Prompt.ask(
                        prompt=prompt,
                        choices=["y", "n"],
                        default="y",
                        show_default=True,
                        console=console,
                    ).lower()
                    if answer == "y":
                        package_name = candidate_package_name
                        console.print(f"Installing {package_name} package instead.")
                        args[ind] = package_name

                self.__add_package_name(package_name)

        for start, end in ranges_to_delete:
            args = args[:start] + args[end + 1 :]

        self._args = args

    def after(self, ctx: typer.Context, result: ToolResult):
        super().after(ctx, result)

        if result.process and result.process.returncode == 0:
            self.__run_scan()
        else:
            self.__render_package_details()

    def env(self, ctx: typer.Context) -> dict:
        env = super().env(ctx)
        env["PIP_INDEX_URL"] = (
            Pip.build_index_url(ctx, self.__index_url)
            if not self.__is_check_disabled()
            else Pip.default_index_url()
        )
        return env

    def __is_check_disabled(self):
        return "--safety-disable-check" in self._args

    def __check_typosquatting(self, package_name):
        max_edit_distance = 2 if len(package_name) > 5 else 1

        if package_name in MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES:
            return (True, package_name)

        for pkg in MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES:
            if (
                abs(len(pkg) - len(package_name)) <= max_edit_distance
                and nltk.edit_distance(pkg, package_name) <= max_edit_distance
            ):
                return (False, pkg)

        return (True, package_name)

    def __run_scan(self):
        if not is_os_supported():
            return

        target = os.getcwd()
        if Path(os.path.join(target, PROJECT_CONFIG)).is_file():
            try:
                subprocess.Popen(
                    ["safety", "scan"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception:
                pass

    def __add_package_name(self, package_name):
        r = re.compile(r"^([a-zA-Z_-]+)(([~<>=]=)[a-zA-Z0-9._-]+)?")
        match = r.match(package_name)
        if match:
            self.package_names.append(match.group(1))

    def __render_package_details(self):
        for package_name in self.package_names:
            console.print(
                Padding(
                    f"Learn more: [link]https://data.safetycli.com/packages/pypi/{package_name}/[/link]",
                    (0, 0, 0, 1),
                ),
                emoji=True,
            )


class PipUninstallCommand(PipCommand):
    pass


class UVBaseCommand(PipCommand):
    def __init__(self, args: List[str]) -> None:
        super().__init__(args)
        self._name = ["uv", "pip"]


class UvInstallCommand(PipInstallCommand, UVBaseCommand):
    def before(self, ctx: typer.Context):
        pass


class UvUninstallCommand(PipUninstallCommand, UVBaseCommand):
    pass


class UvGenericCommand(PipGenericCommand, UVBaseCommand):
    pass


class UvCommand:
    @classmethod
    def from_args(cls, args: List[str]):
        if "install" in args:
            return UvInstallCommand(args)
        elif "uninstall" in args:
            return UvUninstallCommand(args)
        else:
            return UvGenericCommand(args)
