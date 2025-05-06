import abc
import os.path
import re
from pathlib import Path
from sys import platform


from safety.tool.pip import Pip
from safety.tool.poetry import Poetry


from typing import Any, TYPE_CHECKING, Optional

from safety.tool.uv.main import Uv

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
    ) -> Optional[Path]:
        """
        Configures specific file.
        Args:
            file (str): The file to configure.
            org_slug (str): The organization slug.
            project_id (str): The project identifier.
        """
        pass


class PipRequirementsConfigurator(BuildFileConfigurator):
    __file_name_pattern = re.compile("^([a-zA-Z_-]+)?requirements([a-zA-Z_-]+)?.txt$")

    def is_supported(self, file: Path) -> bool:
        return self.__file_name_pattern.match(os.path.basename(file)) is not None

    def configure(
        self, file: Path, org_slug: Optional[str], project_id: Optional[str]
    ) -> None:
        Pip.configure_requirements(file, org_slug, project_id)


class PoetryPyprojectConfigurator(BuildFileConfigurator):
    __file_name_pattern = re.compile("^pyproject.toml$")

    def is_supported(self, file: Path) -> bool:
        return self.__file_name_pattern.match(
            os.path.basename(file)
        ) is not None and Poetry.is_poetry_project_file(file)

    def configure(
        self, file: Path, org_slug: Optional[str], project_id: Optional[str]
    ) -> Optional[Path]:
        if self.is_supported(file):
            return Poetry.configure_pyproject(file, org_slug, project_id)  # type: ignore
        return None


# TODO: Review if we should move this/hook up this into interceptors.
class ToolConfigurator(abc.ABC):
    @abc.abstractmethod
    def configure(self, org_slug: Optional[str]) -> Any:
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
    def configure(self, org_slug: Optional[str]) -> Optional[Path]:
        return Pip.configure_system(org_slug)

    def reset(self) -> None:
        Pip.reset_system()


class PoetryConfigurator(ToolConfigurator):
    """
    Configures poetry system is not supported.
    """

    def configure(self, org_slug: Optional[str]) -> Optional[Path]:
        return None

    def reset(self) -> None:
        return None


class UvConfigurator(ToolConfigurator):
    def configure(self, org_slug: Optional[str]) -> Optional[Path]:
        return Uv.configure_system(org_slug)

    def reset(self) -> None:
        Uv.reset_system()


class UvPyprojectConfigurator(BuildFileConfigurator):
    __file_name_pattern = re.compile("^uv.lock$")

    def is_supported(self, file: Path) -> bool:
        return (
            self.__file_name_pattern.match(os.path.basename(file)) is not None
            and Path("pyproject.toml").exists()
        )

    def configure(
        self, file: Path, org_slug: Optional[str], project_id: Optional[str]
    ) -> Optional[Path]:
        if self.is_supported(file):
            return Uv.configure_pyproject(Path("pyproject.toml"), org_slug, project_id)
        return None
