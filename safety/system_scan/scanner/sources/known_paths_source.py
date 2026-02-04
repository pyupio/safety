import os
import platform
from pathlib import Path
from typing import Iterator
from .base import Source
from ..models import Candidate


class KnownPathsSource(Source):
    """
    Discovers Python installations at known system locations.
    """

    def __init__(self):
        self.system = platform.system()

    def _get_known_paths(self) -> list[Path]:
        """
        Get list of known Python paths for current OS.
        """
        paths = []

        if self.system == "Linux":
            paths.extend(
                [
                    Path("/usr/bin"),
                    Path("/usr/local/bin"),
                    Path("/opt/python"),
                    Path("/usr/lib/python3"),
                    Path("/usr/local/lib/python3"),
                ]
            )
        elif self.system == "Darwin":  # macOS
            paths.extend(
                [
                    Path("/usr/bin"),
                    Path("/usr/local/bin"),
                    Path("/opt/homebrew/bin"),
                    Path("/opt/homebrew/opt/python"),
                    Path("/Library/Developer/CommandLineTools/usr/bin"),
                    Path("/Library/Frameworks/Python.framework/Versions"),
                    Path(
                        "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions"
                    ),
                    Path("~/.local/share/uv/python").expanduser(),
                ]
            )
        elif self.system == "Windows":
            paths.extend(
                [
                    Path("C:/Python"),
                    Path("C:/Python3"),
                    Path("C:/Program Files/Python"),
                    Path("C:/Program Files (x86)/Python"),
                ]
            )
            # Add user local paths
            try:
                user_path = Path.home() / "AppData/Local/Programs/Python"
                if user_path.exists():
                    paths.append(user_path)
            except Exception:
                pass

        return paths

    def iter_candidates(self) -> Iterator[Candidate]:
        """
        Generate candidates from known paths.
        """
        for base_path in self._get_known_paths():
            if not base_path.exists():
                continue

            try:
                # Direct check for python executables
                for name in ["python", "python3"]:
                    exe_path = base_path / name
                    if exe_path.is_file():
                        yield Candidate(
                            path=exe_path,
                            source="KNOWN_PATHS",
                            hint="python:runtime",
                            depth=0,
                        )

                # Check subdirectories for Python installations
                if base_path.is_dir():
                    with os.scandir(base_path) as entries:
                        for entry in entries:
                            if entry.is_dir():
                                subdir = Path(entry.path)
                                bin_dir = (
                                    subdir / "bin"
                                    if self.system != "Windows"
                                    else subdir
                                )

                                for exe_name in [
                                    "python",
                                    "python3",
                                    "python.exe",
                                    "python3.exe",
                                ]:
                                    exe_path = bin_dir / exe_name
                                    if exe_path.is_file():
                                        yield Candidate(
                                            path=exe_path,
                                            source="KNOWN_PATHS",
                                            hint="python:runtime",
                                            depth=1,
                                        )

            except (OSError, PermissionError):
                continue
