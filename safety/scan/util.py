from enum import Enum
import logging
import os
from pathlib import Path
import subprocess
from typing import Optional, Tuple

import typer

from safety.scan.finder.handlers import FileHandler, PythonFileHandler, SafetyProjectFileHandler
from safety_schemas.models import Stage

LOG = logging.getLogger(__name__)

class Language(str, Enum):
    python = "python"
    javascript = "javascript"
    safety_project = "safety_project"

    def handler(self) -> FileHandler:
        if self is Language.python:
            return PythonFileHandler()
        if self is Language.safety_project:
            return SafetyProjectFileHandler()

        return PythonFileHandler()

class Output(Enum):
    json = "json"

class AuthenticationType(str, Enum):
    token = "token"
    api_key = "api_key"
    none = "unauthenticated"

    def is_allowed_in(self, stage: Stage = Stage.development) -> bool:
        if self is AuthenticationType.none:
           return False
        
        if stage == Stage.development and self is AuthenticationType.api_key:
            return False
            
        if (not stage == Stage.development) and self is AuthenticationType.token:
            return False

        return True


class GIT:
    ORIGIN_CMD: Tuple[str, ...] = ("remote", "get-url", "origin")
    BRANCH_CMD: Tuple[str, ...] = ("symbolic-ref", "--short", "-q", "HEAD")
    TAG_CMD: Tuple[str, ...] = ("describe", "--tags", "--exact-match")
    DESCRIBE_CMD: Tuple[str, ...] = ("describe", '--match=""', '--always', 
                                   '--abbrev=40', '--dirty')
    GIT_CHECK_CMD: Tuple[str, ...] = ("rev-parse", "--is-inside-work-tree")
    
    def __init__(self, root: Path = Path(".")) -> None:
        self.git = ("git", "-C", root.resolve())

    def __run__(self, cmd: Tuple[str, ...], env_var: Optional[str] = None) -> Optional[str]:
        if env_var and os.environ.get(env_var):
            return os.environ.get(env_var)

        try:
            return subprocess.run(self.git + cmd, stdout=subprocess.PIPE, 
                                    stderr=subprocess.DEVNULL).stdout.decode('utf-8').strip()
        except Exception as e:
            LOG.exception(e)
        
        return None

    def origin(self) -> Optional[str]:
        return self.__run__(self.ORIGIN_CMD, env_var="SAFETY_GIT_ORIGIN")
    
    def branch(self) -> Optional[str]:
        return self.__run__(self.BRANCH_CMD, env_var="SAFETY_GIT_BRANCH")

    def tag(self) -> Optional[str]:
        return self.__run__(self.TAG_CMD, env_var="SAFETY_GIT_TAG")
    
    def describe(self) -> Optional[str]:
        return self.__run__(self.DESCRIBE_CMD)
    
    def dirty(self, raw_describe: str) -> bool:
        if os.environ.get("SAFETY_GIT_DIRTY") in ["0", "1"]:
            return bool(int(os.environ.get("SAFETY_GIT_DIRTY")))
        
        return raw_describe.endswith('-dirty')

    def commit(self, raw_describe: str) -> Optional[str]:
        if os.environ.get("SAFETY_GIT_COMMIT"):
            return os.environ.get("SAFETY_GIT_COMMIT")

        try:        
            return raw_describe.split("-dirty")[0]
        except Exception:
            pass

    def is_git(self) -> bool:
        result = self.__run__(self.GIT_CHECK_CMD)

        if result == "true":
            return True
        
        return False

    def build_git_data(self):
        from safety_schemas.models import GITModel

        if self.is_git():
            raw_describe = self.describe()
            commit = None
            dirty = None
            if raw_describe:
                commit = self.commit(raw_describe)
                dirty = self.dirty(raw_describe)
            return GITModel(branch=self.branch(), 
                            tag=self.tag(), commit=commit, dirty=dirty, 
                            origin=self.origin())
        
        return None
