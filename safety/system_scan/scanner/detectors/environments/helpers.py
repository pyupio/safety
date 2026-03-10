from __future__ import annotations

import os
import platform
from pathlib import Path


def _to_major_minor(version: str | None) -> str | None:
    """
    Extract major.minor from a version string.

    Args:
        version: Full version string, e.g. '3.11.6'.

    Returns:
        The 'major.minor' portion (e.g. '3.11'), or None if version
        is falsy or has fewer than two dot-separated parts.
    """
    if not version:
        return None
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return None


def _get_prefix(path: Path) -> Path:
    """
    Return the install prefix for a Python binary path.

    On Unix binaries live under {prefix}/bin/, so the prefix is two
    levels up. On Windows the binary sits directly in the prefix dir.

    Args:
        path: Path to a Python binary (resolved or unresolved).

    Returns:
        The install prefix directory.
        Unix:    /usr/bin/python3.11   -> /usr
        Windows: C:\\Python312\\python.exe -> C:\\Python312
    """
    if platform.system() == "Windows":
        return path.parent

    return path.parent.parent


def _extract_cellar_prefix(resolved: Path) -> Path | None:
    """
    Extract the Homebrew prefix from a Cellar path.

    Args:
        resolved: Resolved (symlink-followed) path to a Python binary.

    Returns:
        The Homebrew prefix (e.g. /opt/homebrew) if the path contains
        '/Cellar/', otherwise None.
    """
    s = str(resolved)
    idx = s.find("/Cellar/")
    if idx > 0:
        return Path(s[:idx])
    return None


def _collect_prefixes(candidate_path: Path, resolved_path: Path) -> list[Path]:
    """
    Collect all possible install prefixes for a Python runtime.

    Builds a deduplicated list by deriving prefixes in this exact order
    1. Resolved (real) binary prefix — the authoritative install location.
    2. Candidate (symlink / PATH) binary prefix — covers Homebrew links, etc.
    3. Homebrew Cellar prefix extracted from the resolved path.

    Args:
        candidate_path: The Python binary path as found on PATH (may be a symlink).
        resolved_path: The fully resolved (symlink-followed) binary path.

    Returns:
        Ordered, deduplicated list of prefix Paths to probe for package
        directories. The first prefix that yields existing package dirs
        wins environment registration in the scan registry.
    """
    seen: set[str] = set()
    prefixes: list[Path] = []

    def _add(p: Path) -> None:
        key = str(p)
        if key not in seen:
            seen.add(key)
            prefixes.append(p)

    _add(_get_prefix(resolved_path))
    _add(_get_prefix(candidate_path))

    cellar_prefix = _extract_cellar_prefix(resolved_path)

    if cellar_prefix:
        _add(cellar_prefix)

    return prefixes


def _base_env_canonical_path(prefix: Path, major_minor: str) -> Path:
    """
    Build the canonical directory path for a python:base environment.

    Args:
        prefix: The Python install prefix (e.g. /usr, /opt/homebrew).
        major_minor: Python version as 'major.minor' (e.g. '3.11').

    Returns:
        The base environment directory.
        Unix:    {prefix}/lib/python{ver}  e.g. /usr/lib/python3.11
        Windows: {prefix}\\Lib              e.g. C:\\Python312\\Lib
    """
    if platform.system() == "Windows":
        return prefix / "Lib"

    return prefix / "lib" / f"python{major_minor}"


def _get_base_package_dirs(prefix: Path, ver: str) -> list[Path]:
    """
    Enumerate all candidate package directories for a base environment.

    Covers platform-specific layouts: standard site-packages,
    Debian/Ubuntu dist-packages, Fedora/RHEL lib64, and /usr/local
    fallbacks.

    Args:
        prefix: The Python install prefix (e.g. /usr, /opt/homebrew).
        ver: Python version as 'major.minor' (e.g. '3.11').

    Returns:
        List of Path candidates. Caller must filter for existence.
    """
    system = platform.system()
    dirs: list[Path] = []

    if system == "Windows":
        dirs.append(prefix / "Lib" / "site-packages")
    else:
        # Standard layout (all Unix)
        dirs.append(prefix / "lib" / f"python{ver}" / "site-packages")

        # Debian/Ubuntu: dist-packages
        dirs.append(prefix / "lib" / f"python{ver}" / "dist-packages")
        dirs.append(prefix / "lib" / "python3" / "dist-packages")

        # Debian: pip system-wide -> /usr/local when prefix is /usr
        if str(prefix).rstrip("/") == "/usr":
            dirs.append(Path("/usr/local/lib") / f"python{ver}" / "dist-packages")
            dirs.append(Path("/usr/local/lib") / f"python{ver}" / "site-packages")

        # Fedora/RHEL/Amazon Linux: lib64 for 64-bit native packages
        dirs.append(prefix / "lib64" / f"python{ver}" / "site-packages")

        # RHEL/Amazon Linux: pip system-wide -> /usr/local/lib64 when prefix is /usr
        if str(prefix).rstrip("/") == "/usr":
            dirs.append(Path("/usr/local/lib64") / f"python{ver}" / "site-packages")

    return dirs


def _get_user_site_packages(ver: str) -> Path | None:
    """
    Compute the per-user site-packages path for a Python version.

    Args:
        ver: Python version as 'major.minor' (e.g. '3.12').

    Returns:
        The user site-packages Path, or None if the required env var
        (APPDATA on Windows) is not set. Platform paths:
        Windows: %APPDATA%\\Python\\Python{ver_nodot}\\site-packages
        macOS:   ~/Library/Python/{ver}/lib/python/site-packages
        Linux:   ~/.local/lib/python{ver}/site-packages
    """
    system = platform.system()

    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            return None
        ver_nodot = ver.replace(".", "")  # "3.12" -> "312"

        return Path(appdata) / "Python" / f"Python{ver_nodot}" / "site-packages"

    if system == "Darwin":
        # macOS framework builds use ~/Library/Python/{ver}/lib/python/site-packages

        return (
            Path.home()
            / "Library"
            / "Python"
            / ver
            / "lib"
            / "python"
            / "site-packages"
        )

    # Linux and other Unix
    return Path.home() / ".local" / "lib" / f"python{ver}" / "site-packages"
