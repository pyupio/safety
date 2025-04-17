from enum import Enum
import logging
import os
from pathlib import Path
import subprocess
from typing import TYPE_CHECKING, Optional, Tuple


from safety.scan.finder.handlers import (
    FileHandler,
    PythonFileHandler,
    SafetyProjectFileHandler,
)
from safety_schemas.models import Stage

if TYPE_CHECKING:
    from safety_schemas.models import GITModel


LOG = logging.getLogger(__name__)


class Language(str, Enum):
    """
    Enum representing supported programming languages.
    """

    python = "python"
    javascript = "javascript"
    safety_project = "safety_project"

    def handler(self) -> FileHandler:
        """
        Get the appropriate file handler for the language.

        Returns:
            FileHandler: The file handler for the language.
        """
        if self is Language.python:
            return PythonFileHandler()
        if self is Language.safety_project:
            return SafetyProjectFileHandler()

        return PythonFileHandler()


class Output(Enum):
    """
    Enum representing output formats.
    """

    json = "json"


class AuthenticationType(str, Enum):
    """
    Enum representing authentication types.
    """

    token = "token"
    api_key = "api_key"
    none = "unauthenticated"

    def is_allowed_in(self, stage: Stage = Stage.development) -> bool:
        """
        Check if the authentication type is allowed in the given stage.

        Args:
            stage (Stage): The current stage.

        Returns:
            bool: True if the authentication type is allowed, otherwise False.
        """
        if self is AuthenticationType.none:
            return False

        if stage == Stage.development and self is AuthenticationType.api_key:
            return False

        if (not stage == Stage.development) and self is AuthenticationType.token:
            return False

        return True


class GIT:
    """
    Class representing Git operations.
    """

    ORIGIN_CMD: Tuple[str, ...] = ("remote", "get-url", "origin")
    BRANCH_CMD: Tuple[str, ...] = ("symbolic-ref", "--short", "-q", "HEAD")
    TAG_CMD: Tuple[str, ...] = ("describe", "--tags", "--exact-match")
    DESCRIBE_CMD: Tuple[str, ...] = (
        "describe",
        '--match=""',
        "--always",
        "--abbrev=40",
        "--dirty",
    )
    GIT_CHECK_CMD: Tuple[str, ...] = ("rev-parse", "--is-inside-work-tree")

    def __init__(self, root: Path = Path(".")) -> None:
        """
        Initialize the GIT class with the given root directory.

        Args:
            root (Path): The root directory for Git operations.
        """
        self.git = ("git", "-C", root.resolve())

    def __run__(
        self, cmd: Tuple[str, ...], env_var: Optional[str] = None
    ) -> Optional[str]:
        """
        Run a Git command.

        Args:
            cmd (Tuple[str, ...]): The Git command to run.
            env_var (Optional[str]): An optional environment variable to check for the command result.

        Returns:
            Optional[str]: The result of the Git command, or None if an error occurred.
        """
        if env_var and os.environ.get(env_var):
            return os.environ.get(env_var)

        try:
            return (
                subprocess.run(
                    self.git + cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
                )
                .stdout.decode("utf-8")
                .strip()
            )
        except Exception as e:
            LOG.exception(e)

        return None

    def origin(self) -> Optional[str]:
        """
        Get the Git origin URL.

        Returns:
            Optional[str]: The Git origin URL, or None if an error occurred.
        """
        return self.__run__(self.ORIGIN_CMD, env_var="SAFETY_GIT_ORIGIN")

    def branch(self) -> Optional[str]:
        """
        Get the current Git branch.

        Returns:
            Optional[str]: The current Git branch, or None if an error occurred.
        """
        return self.__run__(self.BRANCH_CMD, env_var="SAFETY_GIT_BRANCH")

    def tag(self) -> Optional[str]:
        """
        Get the current Git tag.

        Returns:
            Optional[str]: The current Git tag, or None if an error occurred.
        """
        return self.__run__(self.TAG_CMD, env_var="SAFETY_GIT_TAG")

    def describe(self) -> Optional[str]:
        """
        Get the Git describe output.

        Returns:
            Optional[str]: The Git describe output, or None if an error occurred.
        """
        return self.__run__(self.DESCRIBE_CMD)

    def dirty(self, raw_describe: str) -> bool:
        """
        Check if the working directory is dirty.

        Args:
            raw_describe (str): The raw describe output.

        Returns:
            bool: True if the working directory is dirty, otherwise False.
        """
        if (is_dirty := os.environ.get("SAFETY_GIT_DIRTY")) and is_dirty in ["0", "1"]:
            return bool(int(is_dirty))

        return raw_describe.endswith("-dirty")

    def commit(self, raw_describe: str) -> Optional[str]:
        """
        Get the current Git commit hash.

        Args:
            raw_describe (str): The raw describe output.

        Returns:
            Optional[str]: The current Git commit hash, or None if an error occurred.
        """
        if os.environ.get("SAFETY_GIT_COMMIT"):
            return os.environ.get("SAFETY_GIT_COMMIT")

        try:
            return raw_describe.split("-dirty")[0]
        except Exception:
            pass

    def is_git(self) -> bool:
        """
        Check if the current directory is a Git repository.

        Returns:
            bool: True if the current directory is a Git repository, otherwise False.
        """
        result = self.__run__(self.GIT_CHECK_CMD)

        if result == "true":
            return True

        return False

    def build_git_data(self) -> Optional["GITModel"]:
        """
        Build a GITModel object with Git data.

        Returns:
            Optional[GITModel]: The GITModel object with Git data, or None if the directory is not a Git repository.
        """
        from safety_schemas.models import GITModel

        if self.is_git():
            raw_describe = self.describe()
            commit = None
            dirty = False

            # TODO: describe fails when there are not commits,
            # GitModel needs to support this case too
            if raw_describe:
                commit = self.commit(raw_describe)
                dirty = self.dirty(raw_describe)
            return GITModel(
                branch=self.branch(),
                tag=self.tag(),
                commit=commit,
                dirty=dirty,
                origin=self.origin(),
            )

        return None
