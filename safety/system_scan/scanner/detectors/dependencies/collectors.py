from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from ...models import FileIntegrity
from ...filesystem import FsRuntime
from ...events.payloads.dependency import PythonDependency


def parse_dist_info_dirname(dirname: str, suffix: str) -> tuple[str | None, str | None]:
    """Parse name and version from dist-info directory name.

    Args:
        dirname: Directory name to parse
        suffix: Expected suffix (e.g., '.dist-info')

    Returns:
        tuple of (name, version) if parsed successfully, (None, None) otherwise

    Example:
        requests-2.31.0.dist-info -> (requests, 2.31.0)
    """
    if not dirname.endswith(suffix):
        return None, None

    base = dirname[: -len(suffix)]
    if "-" not in base:
        return base, None  # Name only, no version

    # Split on last hyphen (name can contain hyphens)
    name, version = base.rsplit("-", 1)
    # Validate version looks reasonable
    if re.match(r"^\d+", version):
        return name, version

    return base, None


def parse_egg_info_dirname(dirname: str, suffix: str) -> tuple[str | None, str | None]:
    """Parse name and version from egg-info directory name.

    Args:
        dirname: Directory name to parse
        suffix: Expected suffix (e.g., '.egg-info')

    Returns:
        tuple of (name, version) if parsed successfully, (None, None) otherwise
    """
    if not dirname.endswith(suffix):
        return None, None

    base = dirname[: -len(suffix)]
    if "-" not in base:
        return base, None

    name, version = base.rsplit("-", 1)
    if re.match(r"^\d+", version):
        return name, version

    return base, None


def extract_metadata_field(content: str, field: str) -> str | None:
    """Extract a field from METADATA or PKG-INFO content.

    Args:
        content: File content to search
        field: Field name to extract

    Returns:
        Field value if found, None otherwise
    """
    pattern = rf"^{re.escape(field)}:\s*(.+)$"
    if match := re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
        return match.group(1).strip()
    return None


def enrich_package_meta(
    meta: dict[str, Any], dist_info_path: Path, fs: FsRuntime
) -> None:
    """Add additional metadata if cheaply available.

    Args:
        meta: Dictionary to enrich with additional metadata
        dist_info_path: Path to the dist-info directory
        fs: Filesystem runtime
    """
    # Check for direct_url.json (indicates editable install or direct URL)
    direct_url_path = dist_info_path / "direct_url.json"
    if fs.is_file(direct_url_path):
        content = fs.read_text(direct_url_path, max_bytes=32_000)
        if content:
            try:
                import json

                direct_url = json.loads(content)
                meta["direct_url"] = direct_url
                if direct_url.get("dir_info", {}).get("editable"):
                    meta["editable"] = True
                if "url" in direct_url:
                    meta["source_type"] = "url"
                    meta["source_ref"] = direct_url["url"]
                elif "dir_info" in direct_url:
                    meta["source_type"] = "directory"
            except Exception:
                pass

    # Check for INSTALLER
    installer_path = dist_info_path / "INSTALLER"
    if fs.is_file(installer_path):
        installer = fs.read_text(installer_path, max_bytes=4096)
        if installer:
            meta["installer"] = installer.strip()

    # Build purl if we have name and version
    if meta.get("name") and meta.get("version"):
        # Normalize name for purl
        normalized_name = re.sub(r"[-_.]+", "-", meta["name"]).lower()
        meta["purl"] = f"pkg:pypi/{normalized_name}@{meta['version']}"


def collect_file_integrity(path: Path, fs: FsRuntime) -> FileIntegrity:
    """
    Calculate file integrity for the given path.

    Args:
        path: Path to calculate integrity for
        fs: Filesystem runtime

    Returns:
        FileIntegrity object with hash and metadata
    """
    return FileIntegrity.from_path(path, fs)


def collect_python_dependency_info(
    dist_info_path: Path, name: str, version: str | None, fs: FsRuntime
) -> PythonDependency:
    """
    Collect Python dependency data

    Args:
        dist_info_path: Path to the dist-info directory
        name: Dependency name
        version: Dependency version
        fs: Filesystem runtime

    Returns:
        PythonDependency payload object
    """
    return PythonDependency(
        canonical_path=str(dist_info_path), name=name, version=version or "unknown"
    )
