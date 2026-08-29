from importlib.metadata import distributions
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

import socket
import sys
from urllib.parse import urlparse

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import pytest

import safety.meta

# Store the original version function
original_version = safety.meta.get_version


def mock_version():
    return "1.2.3"


# Apply the patch immediately at import time
safety.meta.get_version = mock_version


# You can still keep the fixture to ensure cleanup
@pytest.fixture(autouse=True, scope="session")
def cleanup_importlib_patch():
    yield
    safety.meta.get_version = original_version


def get_project_dependencies():
    try:
        with open("pyproject.toml", "rb") as f:
            pyproject = tomllib.load(f)
            deps = pyproject.get("project", {}).get("dependencies", [])
            return {
                canonicalize_name(Requirement(dep).name): dep
                for dep in deps
                if isinstance(dep, str)
            }
    except Exception as e:
        print(f"Error reading dependencies: {e}")
        return {}


_PLATFORM_MARKERS = {
    "unix_only": sys.platform != "win32",
    "windows_only": sys.platform == "win32",
    "linux": sys.platform in ("linux", "linux2"),
    "darwin": sys.platform == "darwin",
}


def _can_resolve(url: str, timeout: float = 2.0) -> bool:
    host = urlparse(url).hostname
    if not host:
        return False
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def _has_platform_network() -> bool:
    from safety.auth.constants import SAFETY_PLATFORM_URL

    return _can_resolve(SAFETY_PLATFORM_URL)


_NETWORK_MARKERS = {
    "requires_network": _has_platform_network(),
}


def pytest_collection_modifyitems(config, items):
    for marker_name, condition_met in {**_PLATFORM_MARKERS, **_NETWORK_MARKERS}.items():
        if condition_met:
            continue
        reason = (
            f"requires {marker_name} (platform={sys.platform})"
            if marker_name in _PLATFORM_MARKERS
            else "requires network access to the Safety Platform"
        )
        skip = pytest.mark.skip(reason=reason)
        for item in items:
            if marker_name in item.keywords:
                item.add_marker(skip)


def pytest_configure(config):
    main_deps_specs = get_project_dependencies()
    all_dists = {
        canonicalize_name(dist.metadata["Name"]): (dist.metadata["Name"], dist.version)
        for dist in distributions()
    }

    # Main dependencies table
    print(f"\n[{len(main_deps_specs)}] Main Dependencies:")
    print("-" * 60)
    print("%-20s %-25s %-15s" % ("Package", "Specification", "Installed"))
    print("-" * 60)

    for pkg_norm, spec in sorted(main_deps_specs.items()):
        if pkg_norm in all_dists:
            name, version = all_dists[pkg_norm]
            print("%-20s %-25s %-15s" % (name, spec, version))

    other_pkgs = [
        f"{name} {ver}"
        for pkg_norm, (name, ver) in sorted(all_dists.items())
        if pkg_norm not in main_deps_specs
    ]

    # Other dependencies in wrapped format
    print(f"\n[{len(other_pkgs)}] Other Dependencies:")
    print("-" * 80)

    # Print other dependencies with wrapping
    line = ""
    for pkg in other_pkgs:
        if len(line) + len(pkg) + 2 > 78:
            print(line.rstrip(", "))
            line = pkg + ", "
        else:
            line += pkg + ", "
    if line:
        print(line.rstrip(", "))
