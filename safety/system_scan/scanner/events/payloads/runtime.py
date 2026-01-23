from __future__ import annotations

from typing import ClassVar
from dataclasses import dataclass
from enum import Enum

from ...models import FileIntegrity
from ...events.payloads.links import RuntimeRelations


class RuntimeSubtype(Enum):
    PYTHON = "python"


@dataclass
class BaseRuntime:
    canonical_path: str
    aliases: list[str]
    version: str
    integrity: FileIntegrity
    links: RuntimeRelations | None = None


@dataclass
class PythonRuntime(BaseRuntime):
    subtype: ClassVar[RuntimeSubtype] = RuntimeSubtype.PYTHON


RuntimeInfo = PythonRuntime
