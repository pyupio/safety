from __future__ import annotations

import platform
from pathlib import Path
from typing import Any
from ...filesystem import FsRuntime
from ...events.payloads.environment import (
    PythonVenvEnvironment,
    PythonBaseEnvironment,
    PythonUserEnvironment,
    PythonVenvMetadata,
    CreatorTool,
)


def collect_venv_environment_info(
    venv_root: Path, fs: FsRuntime
) -> PythonVenvEnvironment | None:
    """
    Collect virtual environment information.

    Args:
        venv_root: Path to the virtual environment root
        fs: Filesystem runtime

    Returns:
        PythonVenvEnvironment if successfully collected, None otherwise
    """
    pyvenv_cfg = venv_root / "pyvenv.cfg"

    try:
        # Parse pyvenv.cfg
        cfg_content = fs.read_text(pyvenv_cfg, max_bytes=4096)
        if not cfg_content:
            return None

        pyvenv_cfg_data = _parse_pyvenv_cfg(cfg_content)
        creator_tool = _detect_venv_creator(venv_root, fs)

        # Collect metadata
        site_packages = _find_venv_site_packages(venv_root, fs)
        bin_dir = venv_root / ("Scripts" if platform.system() == "Windows" else "bin")

        metadata = PythonVenvMetadata()
        if site_packages and fs.is_dir(site_packages):
            try:
                stat = fs.stat(site_packages)
                metadata.site_packages_mtime = stat.st_mtime
            except Exception:
                pass

        if fs.is_dir(bin_dir):
            try:
                stat = fs.stat(bin_dir)
                metadata.bin_mtime = stat.st_mtime
            except Exception:
                pass

        return PythonVenvEnvironment(
            canonical_path=str(fs.realpath(venv_root)),
            creator_tool=creator_tool,
            python_venv_pyvenv_cfg=pyvenv_cfg_data,
            python_venv_metadata=metadata,
        )

    except Exception:
        return None


def collect_base_environment_info(
    runtime_path: Path, fs: FsRuntime
) -> PythonBaseEnvironment | None:
    """
    Collect base Python environment information.

    Args:
        runtime_path: Path to the Python runtime
        fs: Filesystem runtime

    Returns:
        PythonBaseEnvironment if successfully collected, None otherwise
    """
    try:
        site_packages = _find_base_site_packages(runtime_path, fs)
        if not site_packages:
            return None

        return PythonBaseEnvironment(
            canonical_path=str(site_packages),
            site_packages_path=str(site_packages),
            runtime_path=str(runtime_path),
        )

    except Exception:
        return None


def collect_user_environment_info(fs: FsRuntime) -> PythonUserEnvironment | None:
    """
    Collect user Python environment information.

    Args:
        fs: Filesystem runtime

    Returns:
        PythonUserEnvironment if successfully collected, None otherwise
    """
    try:
        site_packages = _find_user_site_packages(fs)
        if not site_packages:
            return None

        return PythonUserEnvironment(
            canonical_path=str(site_packages),
            site_packages_path=str(site_packages),
            user_site_enabled=True,
        )

    except Exception:
        return None


def _parse_pyvenv_cfg(content: str) -> dict[str, Any]:
    """Parse pyvenv.cfg content into a dictionary."""
    config = {}

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" in line:
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()

    return config


def _detect_venv_creator(venv_root: Path, fs: FsRuntime) -> CreatorTool | None:
    """
    Detect which tool created the virtual environment.
    """
    # Check for tool-specific markers
    if fs.is_file(venv_root / "uv.lock"):
        return CreatorTool(name="uv")

    if fs.is_file(venv_root.parent / "poetry.lock"):
        return CreatorTool(name="poetry")

    if fs.is_file(venv_root.parent / "Pipfile.lock"):
        return CreatorTool(name="pipenv")

    if fs.is_file(venv_root.parent / "pdm.lock"):
        return CreatorTool(name="pdm")

    return CreatorTool(name="venv")  # Default


def _find_venv_site_packages(venv_root: Path, fs: FsRuntime) -> Path | None:
    """
    Find site-packages directory in a virtual environment.
    """
    # Try common patterns
    patterns = [
        "lib/python*/site-packages",
        "Lib/site-packages",  # Windows
        "lib/python3.*/site-packages",
    ]

    for pattern in patterns:
        matches = list(venv_root.glob(pattern))
        if matches and fs.is_dir(matches[0]):
            return matches[0]

    return None


def _find_base_site_packages(runtime_path: Path, fs: FsRuntime) -> Path | None:
    """
    Find base site-packages for a Python runtime.
    """
    base = runtime_path.parent.parent  # Go up from bin/python

    patterns = [
        "lib/python*/site-packages",
        "lib/python3.*/site-packages",
        "lib64/python*/site-packages",
        "Lib/site-packages",  # Windows
    ]

    for pattern in patterns:
        matches = list(base.glob(pattern))
        if matches and fs.is_dir(matches[0]):
            return matches[0]

    return None


def _find_user_site_packages(fs: FsRuntime) -> Path | None:
    """
    Find user site-packages directory.
    """
    if platform.system() == "Windows":
        base = Path.home() / "AppData" / "Roaming" / "Python"
    else:
        base = Path.home() / ".local"

    # Try common patterns
    patterns = [
        "lib/python*/site-packages",
        "lib/python3.*/site-packages",
        "Python*/site-packages",  # Windows
    ]

    for pattern in patterns:
        matches = list(base.glob(pattern))
        if matches and fs.is_dir(matches[0]):
            return matches[0]

    return None
