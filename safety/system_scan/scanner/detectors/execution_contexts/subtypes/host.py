from __future__ import annotations

import platform
import getpass

from enum import Enum

from ..utils import (
    get_xnu_kernel_version,
    get_windows_version_info,
    get_macos_version_info,
    get_macos_machine_id,
    get_linux_machine_id,
    get_windows_machine_id,
    get_linux_version_info,
)

from ....events.payloads.execution_context import OsFamily


class KernelName(Enum):
    WINDOWS_NT = "Windows NT"
    LINUX = "Linux"
    XNU = "XNU"
    UNKNOWN = "Unknown"


def get_machine_id() -> str | None:
    """
    Returns the machine ID for the current platform.

    Returns:
        Machine ID
    """
    system = platform.system().lower()

    handlers = {
        "linux": lambda: get_linux_machine_id(),
        "darwin": lambda: get_macos_machine_id(),
        "windows": lambda: get_windows_machine_id(),
    }

    try:
        return handlers[system]()
    except KeyError:
        # TODO: Log this
        pass

    return None


def get_kernel_info() -> tuple[KernelName, str]:
    """
    Returns the kernel name and version for the current platform.

    Returns:
        tuple of (kernel_name, kernel_version)
    """
    system = platform.system().lower()

    handlers = {
        "linux": lambda: (KernelName.LINUX, platform.release()),
        "darwin": lambda: (KernelName.XNU, get_xnu_kernel_version()),
        "windows": lambda: (
            KernelName.WINDOWS_NT,
            get_windows_version_info().kernel_version,
        ),
    }

    try:
        return handlers[system]()
    except KeyError:
        # TODO: Log this
        return KernelName.UNKNOWN, platform.release()


def get_os_info() -> tuple[str, OsFamily, str, str, str]:
    """
    Returns the OS name, family, version, build, and username for the current platform.

    Returns:
        tuple of (os_name, os_family, os_version, os_build, os_username)
    """
    system = platform.system().lower()
    os_user = getpass.getuser()

    handlers = {
        "linux": lambda: (
            get_linux_version_info().name or get_linux_version_info().pretty_name,
            OsFamily.LINUX,
            get_linux_version_info().version,
            None,
            os_user,
        ),
        "darwin": lambda: (
            get_macos_version_info().name,
            OsFamily.MACOS,
            get_macos_version_info().version,
            get_macos_version_info().build,
            os_user,
        ),
        "windows": lambda: (
            get_windows_version_info().product_name,
            OsFamily.WINDOWS,
            get_windows_version_info().display_version,
            f"{get_windows_version_info().build}.{get_windows_version_info().ubr}",
            os_user,
        ),
    }

    try:
        return handlers[system]()
    except KeyError:
        # TODO: Log this
        return platform.system(), OsFamily.UNKNOWN, platform.release(), "", os_user
