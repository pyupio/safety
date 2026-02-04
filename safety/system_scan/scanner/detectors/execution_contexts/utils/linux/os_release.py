import re

from ..main import LinuxVersionInfo


_OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")
_DEBIAN_VERSION_PATH = "/etc/debian_version"
_REDHAT_RELEASE_PATH = "/etc/redhat-release"

_RHEL_FAMILY = frozenset({"rhel", "centos", "rocky", "almalinux", "fedora", "ol"})


def get_linux_version_info(
    root: str = "",
    kernel_version: str = "",
) -> LinuxVersionInfo:
    """
    Get Linux distribution and kernel information.

    Args:
        root: Optional filesystem root prefix (e.g., "/mnt/target")
        kernel_version: Optional kernel version (if not running on target)

    Returns:
        LinuxVersionInfo with distribution and kernel details
    """
    os_release = _parse_os_release(root)

    distro_id = os_release.get("ID", "linux")
    version_id = os_release.get("VERSION_ID", "")
    version = _get_point_release(root, distro_id, version_id, os_release)

    return LinuxVersionInfo(
        name=os_release.get("NAME", "Linux"),
        version=version,
        version_id=version_id,
        id=distro_id,
        id_like=os_release.get("ID_LIKE", ""),
        codename=os_release.get("VERSION_CODENAME", ""),
        pretty_name=os_release.get("PRETTY_NAME", "Linux"),
    )


def _parse_os_release(root: str = "") -> dict[str, str]:
    """
    Parse os-release from standard locations.
    """
    for path in _OS_RELEASE_PATHS:
        full_path = f"{root}{path}" if root else path
        result = _parse_kv_file(full_path)

        if result:
            return result

    return {}


def _is_debian_family(distro_id: str, id_like: str) -> bool:
    return distro_id == "debian" or "debian" in id_like.split()


def _is_rhel_family(distro_id: str, id_like: str) -> bool:
    id_like_set = set(id_like.split())
    return distro_id in _RHEL_FAMILY or bool(id_like_set & _RHEL_FAMILY)


def _get_point_release(
    root: str,
    distro_id: str,
    version_id: str,
    os_release: dict[str, str],
) -> str:
    """
    Get specific point release for known distros.

    Falls back to version_id if point release unavailable.
    """

    id_like = os_release.get("ID_LIKE", "")

    # Ubuntu: VERSION contains point release (e.g., "22.04.3 LTS")
    if distro_id == "ubuntu":
        version = os_release.get("VERSION", "")
        match = re.match(r"([\d.]+)", version)
        if match:
            return match.group(1)

    if _is_debian_family(distro_id, id_like):
        path = f"{root}{_DEBIAN_VERSION_PATH}" if root else _DEBIAN_VERSION_PATH
        content = _read_file(path)
        if content and content[0].isdigit():
            return content

    # RHEL family: /etc/redhat-release (e.g., "Rocky Linux release 8.9 (Green Obsidian)")
    if _is_rhel_family(distro_id, id_like):
        path = f"{root}{_REDHAT_RELEASE_PATH}" if root else _REDHAT_RELEASE_PATH
        content = _read_file(path)
        if content:
            match = re.search(r"release\s+([\d.]+)", content)
            if match:
                return match.group(1)

    return version_id


def _read_file(path: str) -> str:
    """
    Read file content, return empty string on failure.
    """
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _parse_kv_file(path: str) -> dict[str, str]:
    """
    Parse KEY=value or KEY="value" file.
    """
    content = _read_file(path)
    if not content:
        return {}

    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        result[key] = value.strip("\"'")

    return result
