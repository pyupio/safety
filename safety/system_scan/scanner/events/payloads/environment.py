from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Union
from enum import Enum
from .links import EnvironmentRelations


class EnvironmentSubtype(Enum):
    PYTHON_VENV = "python:venv"
    PYTHON_BASE = "python:base"
    PYTHON_USER = "python:user"


@dataclass
class CreatorTool:
    name: str
    version: str | None = None


@dataclass
class PythonVenvMetadata:
    site_packages_mtime: float | None = None
    bin_mtime: float | None = None


@dataclass
class BaseEnvironment:
    canonical_path: str
    creator_tool: CreatorTool | None = None
    links: EnvironmentRelations | None = None


@dataclass
class PythonVenvEnvironment(BaseEnvironment):
    python_venv_pyvenv_cfg: dict[str, Any] | None = None
    python_venv_metadata: PythonVenvMetadata | None = None
    subtype: ClassVar[EnvironmentSubtype] = EnvironmentSubtype.PYTHON_VENV


@dataclass
class PythonBaseEnvironment(BaseEnvironment):
    site_packages_path: str | None = None
    runtime_path: str | None = None
    subtype: ClassVar[EnvironmentSubtype] = EnvironmentSubtype.PYTHON_BASE


@dataclass
class PythonUserEnvironment(BaseEnvironment):
    site_packages_path: str | None = None
    user_site_enabled: bool = True
    subtype: ClassVar[EnvironmentSubtype] = EnvironmentSubtype.PYTHON_USER


EnvironmentInfo = Union[
    PythonVenvEnvironment, PythonBaseEnvironment, PythonUserEnvironment
]
