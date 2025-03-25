import getpass
import os
from pathlib import Path
import site
import socket
import sys
import platform
from typing import List, Optional
from safety_schemas.models.events.context import (
    ClientInfo,
    EventContext,
    HostInfo,
    OsInfo,
    ProjectInfo,
    PythonInfo,
    RuntimeInfo,
    UserInfo,
)

from safety_schemas.models.events.types import SourceType
from safety_schemas.models import ProjectModel


def get_user_info() -> UserInfo:
    """
    Collect information about the current user.
    """
    return UserInfo(name=getpass.getuser(), home_dir=str(Path.home()))


def get_os_info() -> OsInfo:
    """
    Get basic OS information using only the platform module.
    Returns a dictionary with architecture, platform, name, version, and kernel_version.
    """
    # Initialize with required fields
    os_info = {
        "architecture": platform.machine(),
        "platform": platform.system(),
        "name": None,
        "version": None,
        "kernel_version": None,
    }

    python_version = sys.version_info

    if sys.platform == "wind32":
        os_info["version"] = platform.release()
        os_info["kernel_version"] = platform.version()
        os_info["name"] = "windows"

    elif sys.platform == "darwin":
        os_info["version"] = platform.mac_ver()[0]
        os_info["kernel_version"] = platform.release()
        os_info["name"] = "macos"

    elif sys.platform == "linux":
        os_info["kernel_version"] = platform.release()
        if python_version >= (3, 10):
            try:
                os_release = platform.freedesktop_os_release()
                # Use ID for name (more consistent for programmatic use)
                os_info["name"] = os_release.get("ID", "linux")
                os_info["version"] = os_release.get("VERSION_ID")
            except (OSError, AttributeError):
                # If freedesktop_os_release fails, keep values as is
                pass

    return OsInfo(**os_info)


def get_host_info() -> HostInfo:
    """
    Collect information about the host machine.
    """
    hostname = socket.gethostname()

    ipv4_addresses = set()
    ipv6_addresses = set()
    try:
        host_info = socket.getaddrinfo(hostname, None)
        for info in host_info:
            ip_family = info[0]
            ip = str(info[4][0])

            if ip_family == socket.AF_INET:
                if not ip.startswith("127."):
                    ipv4_addresses.add(ip)
            elif ip_family == socket.AF_INET6:
                if not ip.startswith("::1") and ip != "fe80::1":
                    ipv6_addresses.add(ip)

        # Prioritize addresses
        primary_ipv4 = next(
            (ip for ip in ipv4_addresses),
            next(iter(ipv4_addresses)) if ipv4_addresses else None,
        )

        primary_ipv6 = next(
            (ip for ip in ipv6_addresses if not ip.startswith("fe80:")),
            next(iter(ipv6_addresses)) if ipv6_addresses else None,
        )

    except socket.gaierror:
        primary_ipv4 = None
        primary_ipv6 = None

    return HostInfo(name=hostname, ipv4=primary_ipv4, ipv6=primary_ipv6, timezone=None)


def get_python_info() -> PythonInfo:
    """
    Collect detailed information about the Python environment.
    """
    # Get site-packages directories
    site_packages_dirs = site.getsitepackages()

    user_site_enabled = bool(site.ENABLE_USER_SITE)
    user_site_packages = site.getusersitepackages()

    return PythonInfo(
        version=f"{sys.version_info.major}.{sys.version_info.minor}",
        path=sys.executable,
        sys_path=sys.path,
        implementation=platform.python_implementation(),
        implementation_version=platform.python_version(),
        sys_prefix=sys.prefix,
        site_packages=site_packages_dirs,
        user_site_enabled=user_site_enabled,
        user_site_packages=user_site_packages,
        encoding=sys.getdefaultencoding(),
        filesystem_encoding=sys.getfilesystemencoding(),
    )


def create_event_context(
    client_identifier: SourceType,
    client_version: str,
    client_path: str,
    project: Optional[ProjectModel] = None,
    tags: Optional[List[str]] = None,
) -> EventContext:
    client = ClientInfo(
        identifier=client_identifier, version=client_version, path=client_path
    )

    project_info = None

    if project:
        project_info = ProjectInfo(
            id=project.id,
            url=project.url_path,
        )

    runtime = RuntimeInfo(
        workdir=os.getcwd(),
        user=get_user_info(),
        os=get_os_info(),
        host=get_host_info(),
        python=get_python_info(),
    )

    return EventContext(client=client, runtime=runtime, project=project_info, tags=tags)
