"""
Platform-specific machine ID detection.

Shared utility for reading hardware UUIDs from Linux, macOS, and Windows.
Both ``safety.auth`` and ``safety.system_scan`` import from here.
"""

from __future__ import annotations

import os
import platform
import stat
import subprocess
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import winreg
elif platform.system().lower() == "windows":
    import winreg


def get_linux_machine_id() -> Optional[str]:
    """
    Get Linux machine ID from /etc/machine-id or /var/lib/dbus/machine-id.

    Returns:
        The machine ID or None if not found.
    """
    paths = (
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
    )

    # machine-id is 32 hex chars + newline = 33 bytes
    # set a max size to avoid reading big files
    max_size = 64

    for path in paths:
        try:
            st = os.stat(path)

            # Reject if too large or not a regular file
            if st.st_size > max_size or not stat.S_ISREG(st.st_mode):
                continue

            with open(path, "r", encoding="utf-8") as f:
                value = f.read(max_size).strip()

            if value:
                return value

        except (OSError, ValueError):
            continue

    return None


def get_macos_machine_id() -> Optional[str]:
    """
    Get macOS hardware UUID (IOPlatformUUID).

    Returns:
        The hardware UUID or None if not found.
    """
    try:
        result = subprocess.run(
            ["ioreg", "-d2", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
        )

        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            if "IOPlatformUUID" in line:
                _, _, value = line.partition("=")
                value = value.strip().strip('"').strip()

                if value:
                    return value

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return None


def get_windows_machine_id() -> Optional[str]:
    """
    Get Windows machine GUID from the registry.

    Returns:
        The machine GUID or None if not found.
    """
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            value, reg_type = winreg.QueryValueEx(key, "MachineGuid")

        if reg_type != winreg.REG_SZ or not isinstance(value, str) or not value:
            return None

        return value

    except (OSError, ValueError, TypeError):
        return None
