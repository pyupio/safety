from __future__ import annotations

import subprocess
import platform
from enum import Enum

from ..main import MacOSVersionInfo


class SwVersKey(str, Enum):
    PRODUCT_NAME = "productname"
    PRODUCT_VERSION = "productversion"
    BUILD_VERSION = "buildversion"


SW_VERS_KEYS = frozenset(e.value for e in SwVersKey)


def get_xnu_kernel_version() -> str:
    """
    Extracts the XNU kernel version from platform.version() on macOS.

    Returns:
        str: The XNU kernel version or empty string if not found
    """

    FALLBACK_VERSION = ""
    XNU_MARKER = "xnu-"
    version_content = platform.version().lower()

    if XNU_MARKER not in version_content:
        return FALLBACK_VERSION

    return version_content.partition(XNU_MARKER)[2].split("/")[0]


def get_macos_version_info() -> MacOSVersionInfo:
    """
    Get macOS version information.

    Uses sw_vers command, falls back to platform.mac_ver() if unavailable.

    Returns:
        MacOSVersionInfo with fields:
            name: OS name (e.g., "macOS")
            version: OS version (e.g., "14.1.2")
            build: Build number (e.g., "23B92") or empty string
    """
    FALLBACK_NAME = "macOS"
    FALLBACK_BUILD = ""

    try:
        result = subprocess.run(
            ["sw_vers"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError):
        result = None

    sw_vers = {}

    if result and result.returncode == 0:
        for line in result.stdout.strip().splitlines():
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            key = key.strip().lower()

            if key in SW_VERS_KEYS:
                sw_vers[key] = value.strip()

    return MacOSVersionInfo(
        name=sw_vers.get(SwVersKey.PRODUCT_NAME) or FALLBACK_NAME,
        version=sw_vers.get(SwVersKey.PRODUCT_VERSION) or platform.mac_ver()[0],
        build=sw_vers.get(SwVersKey.BUILD_VERSION) or FALLBACK_BUILD,
    )
