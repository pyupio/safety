from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Union
from enum import Enum

from ...models import FileIntegrity
from .links import ToolRelations


class ToolSubtype(Enum):
    PACKAGE_MANAGER = "package_manager"
    VCS = "vcs"
    CONTAINER = "container"
    IDE = "ide"
    AI = "ai"


@dataclass
class BaseTool:
    canonical_path: str
    name: str
    version: str | None
    integrity: FileIntegrity
    aliases: list[str]
    links: ToolRelations | None = None


@dataclass
class PackageManagerTool(BaseTool):
    subtype: ClassVar[ToolSubtype] = ToolSubtype.PACKAGE_MANAGER


@dataclass
class VcsTool(BaseTool):
    subtype: ClassVar[ToolSubtype] = ToolSubtype.VCS


@dataclass
class ContainerTool(BaseTool):
    subtype: ClassVar[ToolSubtype] = ToolSubtype.CONTAINER


@dataclass
class IdeTool(BaseTool):
    subtype: ClassVar[ToolSubtype] = ToolSubtype.IDE


@dataclass
class AiTool(BaseTool):
    subtype: ClassVar[ToolSubtype] = ToolSubtype.AI


ToolInfo = Union[PackageManagerTool, VcsTool, ContainerTool, IdeTool, AiTool]
