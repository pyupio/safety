from __future__ import annotations

from typing import NamedTuple


class WindowsVersionInfo(NamedTuple):
    kernel_version: str  # "10.0" - NT version
    build: str  # "26100" - base release
    ubr: int  # 4652 - patch level
    full_version: str  # "10.0.26100.4652"
    display_version: str  # "24H2"
    product_name: str  # "Windows Server 2025 Standard"


class MacOSVersionInfo(NamedTuple):
    name: str
    version: str
    build: str | None


class LinuxVersionInfo(NamedTuple):
    name: str  # "Ubuntu", "Debian", "Alpine"
    version: str  # "22.04.3", "12.5", "3.19.1" (point release)
    version_id: str  # "22.04", "12", "3.19" (major release)
    id: str  # "ubuntu", "debian", "alpine"
    id_like: str  # "debian", "rhel fedora"
    codename: str  # "jammy", "bookworm"
    pretty_name: str  # "Ubuntu 22.04.3 LTS"
