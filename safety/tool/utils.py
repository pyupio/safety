import abc
import os.path
import re
import subprocess
from abc import abstractmethod
from pathlib import Path
from sys import platform
from tempfile import mkstemp

import typer
import nltk
from filelock import FileLock
from rich.padding import Padding
from rich.prompt import Prompt

from safety.console import main_console as console
from safety.constants import PIP_LOCK
from safety.tool.constants import MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES, PROJECT_CONFIG, REPOSITORY_URL
from safety.tool.pip import Pip
from safety.tool.poetry import Poetry
from safety.tool.resolver import get_unwrapped_command

from typing_extensions import List

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from subprocess import CompletedProcess


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
    def configure(self, file: Path) -> None:
        """
        Configures specific file.
        Args:
            file (str): The file to configure.
        """
        pass


class PipRequirementsConfigurator(BuildFileConfigurator):
    __file_name_pattern = re.compile("^([a-zA-Z_-]+)?requirements([a-zA-Z_-]+)?.txt$")

    def is_supported(self, file: Path) -> bool:
        return self.__file_name_pattern.match(os.path.basename(file)) is not None

    def configure(self, file: Path) -> None:
        Pip.configure_requirements(file)


class PoetryPyprojectConfigurator(BuildFileConfigurator):
    __file_name_pattern = re.compile("^pyproject.toml$")

    def is_supported(self, file: Path) -> bool:
        return self.__file_name_pattern.match(os.path.basename(file)) is not None and Poetry.is_poetry_project_file(
            file)

    def configure(self, file: Path) -> None:
        Poetry.configure_pyproject(file)


# TODO: Review if we should move this/hook up this into interceptors.
class ToolConfigurator(abc.ABC):

    @abc.abstractmethod
    def configure(self) -> None:
        """
        Configures specific tool.
        """
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        """
        Resets specific tool.
        """
        pass

class PipConfigurator(ToolConfigurator):

    def configure(self) -> None:
        Pip.configure_system()

    def reset(self) -> None:
        Pip.reset_system()


class PipCommand(abc.ABC):

    def __init__(self, args: List[str], capture_output: bool = False) -> None:
        self._args = args
        self.__capture_output = capture_output
        self.__filelock = FileLock(PIP_LOCK, 10)

    @abstractmethod
    def before(self, ctx: typer.Context):
        pass

    @abstractmethod
    def after(self, ctx: typer.Context, result):
        pass

    def execute(self, ctx: typer.Context):
        with self.__filelock:
            self.before(ctx)
            # TODO: Safety should redirect to the proper pip, if the user is
            # using pip3, it should be redirected to pip3, not pip to avoid any
            # issues.
            args = [get_unwrapped_command(name="pip")] + self.__remove_safety_args(self._args)
            result = subprocess.run(args, capture_output=self.__capture_output, env=self.env(ctx))
            self.after(ctx, result)

    def env(self, ctx: typer.Context):
        return os.environ.copy()

    @classmethod
    def from_args(self, args):
        if "install" in args:
            return PipInstallCommand(args)
        elif "uninstall" in args:
            return PipUninstallCommand(args)
        else:
            return PipGenericCommand(args)

    def __remove_safety_args(self, args: List[str]):
        return [arg for arg in args if not arg.startswith("--safety")]


class PipGenericCommand(PipCommand):

    def __init__(self, args: List[str]) -> None:
        super().__init__(args)

    def before(self, ctx: typer.Context):
        pass

    def after(self, ctx: typer.Context, result):
        pass


class PipInstallCommand(PipCommand):

    def __init__(self, args: List[str]) -> None:
        super().__init__(args)
        self.package_names = []
        self.__index_url = None

    def before(self, ctx: typer.Context):
        args = self._args

        ranges_to_delete = []
        for ind, val in enumerate(args):
            if ind > 0 and (args[ind - 1].startswith("-i") or args[ind - 1].startswith("--index-url")):
                if args[ind].startswith("https://pkgs.safetycli.com"):
                    self.__index_url = args[ind]

                ranges_to_delete.append((ind - 1, ind))
            elif ind > 0 and (args[ind - 1] == "-r" or args[ind - 1] == "--requirement"):
                requirement_file = args[ind]

                if not Path(requirement_file).is_file():
                    continue

                with open(requirement_file, "r") as f:
                    fd, tmp_requirements_path = mkstemp(suffix="safety-requirements.txt", text=True)
                    with os.fdopen(fd, "w") as tf:
                        requirements = re.sub(r"^(-i|--index-url).*$", "", f.read(), flags=re.MULTILINE)
                        tf.write(requirements)

                    args[ind] = tmp_requirements_path
            elif ind > 0 and (not args[ind - 1].startswith("-e") or not args[ind - 1].startswith("--editable")) and not args[ind].startswith("-"):
                if args[ind] == '.':
                    continue

                package_name = args[ind]
                (valid, candidate_package_name) = self.__check_typosquatting(package_name)
                if not valid:
                    prompt = f"You are about to install {package_name} package. Did you mean to install {candidate_package_name}?"
                    answer = Prompt.ask(prompt=prompt, choices=["y", "n"],
                                        default="y", show_default=True, console=console).lower()
                    if answer == 'y':
                        package_name = candidate_package_name
                        console.print(f"Installing {package_name} package instead.")
                        args[ind] = package_name

                self.__add_package_name(package_name)

        for (start, end) in ranges_to_delete:
            args = args[:start] + args[end + 1:]

        self._args = args

    def after(self, ctx: typer.Context, result: 'CompletedProcess[str]'):
        if result and result.returncode == 0:
            self.__run_scan()
        else:
            self.__render_package_details()

    def env(self, ctx: typer.Context) -> dict:
        env = super().env(ctx)
        env["PIP_INDEX_URL"] = Pip.build_index_url(ctx, self.__index_url) if not self.__is_check_disabled() else Pip.default_index_url()
        return env

    def __is_check_disabled(self):
        return "--safety-disable-check" in self._args

    def __check_typosquatting(self, package_name):
        max_edit_distance = 2 if len(package_name) > 5 else 1

        if package_name in MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES:
            return (True, package_name)

        for pkg in MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES:
            if (abs(len(pkg) - len(package_name)) <= max_edit_distance
                and nltk.edit_distance(pkg, package_name) <= max_edit_distance):
                return (False, pkg)

        return (True, package_name)

    def __run_scan(self):
        if not is_os_supported():
            return

        target = os.getcwd()
        if Path(os.path.join(target, PROJECT_CONFIG)).is_file():
            try:
                subprocess.Popen(
                ['safety', 'scan'],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL,
                     start_new_session=True
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
                Padding(f"Learn more: [link]https://data.safetycli.com/packages/pypi/{package_name}/[/link]",
                        (0, 0, 0, 1)), emoji=True)


class PipUninstallCommand(PipCommand):

    def __init__(self, args: List[str]) -> None:
        super().__init__(args)

    def before(self, ctx: typer.Context):
        pass

    def after(self, ctx: typer.Context, result):
        pass
