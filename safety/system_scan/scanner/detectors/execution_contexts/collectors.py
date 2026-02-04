import platform
from ...events.payloads import HostExecutionContext, OsFamily
from .subtypes import host


def get_host_execution_context() -> HostExecutionContext:
    """
    Collect the host execution context data for current platform.

    This function is intended to be ran inside the host execution context.

    Returns:
        HostExecutionContext with the execution context data
    """

    machine_id = host.get_machine_id()

    if not machine_id:
        raise Exception(
            "Unsupported platform. Unable to identify the Host execution context."
        )

    arch = platform.machine()
    kernel_name, kernel_version = host.get_kernel_info()
    os_name, os_family, os_version, os_build, os_username = host.get_os_info()

    # NOTE:
    # platform.node() implementation is cached, so underlying changes in the hostname
    # won't be reflected until the process is restarted.
    hostname = platform.node().split(".")[0]

    windows_win32_ver = None
    macos_darwin_release = None

    if os_family == OsFamily.WINDOWS:
        windows_win32_ver = platform.win32_ver()
    elif os_family == OsFamily.MACOS:
        macos_darwin_release = platform.release()

    return HostExecutionContext(
        arch=arch,
        kernel_name=kernel_name.value,
        kernel_version=kernel_version,
        os_name=os_name,
        os_family=os_family,
        os_version=os_version,
        os_build=os_build,
        os_username=os_username,
        hostname=hostname or "",
        machine_id=machine_id,
        windows_win32_ver=windows_win32_ver,
        macos_darwin_release=macos_darwin_release,
    )
