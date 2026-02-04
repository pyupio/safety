from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Union
from .utils import required


class ExecutionContextSubtype(Enum):
    HOST = "host"
    WSL = "wsl"


class OsFamily(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclass
class LinuxOsRelease:
    id: str | None = None  # ubuntu, alpine, debian
    id_like: tuple[str, ...] | None = None  # (debian,) for ubuntu
    version_id: str | None = None  # 22.04
    version_codename: str | None = None  # jammy
    pretty_name: str | None = None  # Ubuntu 22.04.3 LTS


@dataclass
class BaseExecutionContext:
    arch: str
    kernel_name: str
    kernel_version: str
    os_name: str
    os_family: OsFamily
    os_version: str
    hostname: str
    os_build: str | None = None
    os_username: str = field(default_factory=required("os_username"))


@dataclass
class HostExecutionContext(BaseExecutionContext):
    machine_id: str = field(default_factory=required("machine_id"))
    windows_win32_ver: tuple[str, str, str, str] | None = None
    macos_darwin_release: str | None = None
    subtype: ClassVar[ExecutionContextSubtype] = ExecutionContextSubtype.HOST


@dataclass
class WslExecutionContext(BaseExecutionContext):
    machine_id: str = field(default_factory=required("machine_id"))
    subtype: ClassVar[ExecutionContextSubtype] = ExecutionContextSubtype.WSL


ExecutionContextInfo = Union[HostExecutionContext, WslExecutionContext]
