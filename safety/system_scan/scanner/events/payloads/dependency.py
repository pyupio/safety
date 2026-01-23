from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar
from enum import Enum
from .links import DependencyRelations


class DependencySubtype(Enum):
    PYTHON = "python"


@dataclass
class BaseDependency:
    canonical_path: str
    name: str
    version: str
    links: DependencyRelations | None = None


@dataclass
class PythonDependency(BaseDependency):
    subtype: ClassVar[DependencySubtype] = DependencySubtype.PYTHON


DependencyInfo = PythonDependency
