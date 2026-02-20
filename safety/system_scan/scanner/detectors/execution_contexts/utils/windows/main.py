from __future__ import annotations

from typing import TYPE_CHECKING
import platform


from ..main import WindowsVersionInfo

if TYPE_CHECKING or platform.system().lower() == "windows":
    import winreg


def get_windows_version_info() -> WindowsVersionInfo:
    """
    Get Windows version info mainly from registry.

    Returns:
        WindowsVersionInfo with kernel_version, build, ubr, full_version, display_version, product_name
    """
    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:

        def query(name, default=None):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return default

        major = query("CurrentMajorVersionNumber", 10)
        minor = query("CurrentMinorVersionNumber", 0)
        build = query("CurrentBuildNumber", "0")
        ubr = query("UBR", 0)
        display = query("DisplayVersion", "")  # "24H2"
        product = query("ProductName", "")  # "Windows Server 2025 Standard"

    kernel_version = f"{major}.{minor}"
    full_version = f"{kernel_version}.{build}.{ubr}"

    return WindowsVersionInfo(
        kernel_version=kernel_version,
        build=build,
        ubr=ubr,
        full_version=full_version,
        display_version=display,
        product_name=product,
    )
