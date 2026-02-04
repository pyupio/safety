from __future__ import annotations

import re
import subprocess
from pathlib import Path
from ...models import FileIntegrity
from ...events.payloads.runtime import PythonRuntime
from ...filesystem import FsRuntime


VERSION_PATTERNS = (
    # Explicit python + X.Y.Z (highest confidence)
    (re.compile(r"python[_-]?(\d+\.\d+\.\d+)", re.IGNORECASE), None),
    # pyenv/asdf versions directory style
    (re.compile(r"versions[/\\](\d+\.\d+\.\d+)", re.IGNORECASE), None),
    # Standalone X.Y.Z with word boundaries
    (re.compile(r"(?<![.\d])(\d+\.\d+\.\d+)(?![.\d])", re.IGNORECASE), None),
    # Explicit python + X.Y
    (re.compile(r"python[_-]?(\d+\.\d+)", re.IGNORECASE), None),
    # Windows PythonXYZ style (e.g., Python312 -> 3.12)
    (
        re.compile(r"python(\d)(\d+)", re.IGNORECASE),
        lambda m: f"{m.group(1)}.{m.group(2)}",
    ),
    # Standalone X.Y fallback
    (re.compile(r"(?<![.\d])(\d+\.\d+)(?![.\d])", re.IGNORECASE), None),
)


def extract_version_from_path(path: Path) -> str | None:
    """
    Extract Python version from the file path by analyzing path components.

    Attempts multiple patterns in order of specificity.

    Args:
        path: Path to the Python executable

    Returns:
        Version string in X.Y or X.Y.Z format if found, None otherwise

    Examples:
        /usr/bin/python3.11 -> "3.11"
        /Users/me/.pyenv/versions/3.11.5/bin/python -> "3.11.5"
        C:\\Python311\\python.exe -> "3.11"
    """
    path_str = str(path)

    for pattern, transform in VERSION_PATTERNS:
        match = pattern.search(path_str)
        if match:
            return transform(match) if transform else match.group(1)

    return None


def extract_version_from_execution(path: Path) -> str | None:
    """
    Extract Python version by executing the binary to get the real executable path.

    Used when path-based extraction fails (e.g., stub binaries like /usr/bin/python).

    Args:
        path: Path to the Python executable

    Returns:
        Version string if successfully extracted, None otherwise
    """
    try:
        stdout = subprocess.check_output(
            [str(path), "-c", "import sys; print(sys.executable)"], text=True
        ).strip()

        runtime_path = Path(stdout)
        return extract_version_from_path(runtime_path)
    except Exception:
        return None


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


def collect_python_runtime_info(raw_path: Path, fs: FsRuntime) -> PythonRuntime | None:
    """
    Collect Python runtime information without executing unless necessary.

    This function orchestrates different collection strategies:
    1. Path-based version extraction (fastest)
    2. Execution-based extraction (fallback for stub binaries)

    Args:
        raw_path: Original path to the Python executable
        fs: Filesystem runtime

    Returns:
        PythonRuntime if successfully collected, None otherwise
    """
    try:
        symlink_origin = None
        path = fs.realpath(raw_path)

        # Track if this was a symlink
        if raw_path.is_symlink():
            symlink_origin = raw_path

        # Try path-based version extraction first
        version = extract_version_from_path(path)

        # Calculate file integrity
        integrity = collect_file_integrity(path, fs)

        return PythonRuntime(
            canonical_path=str(path),
            aliases=[str(symlink_origin)] if symlink_origin else [],
            version=version or "",
            integrity=integrity,
        )

    except Exception:
        return None
