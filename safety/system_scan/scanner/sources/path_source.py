import os
from pathlib import Path
from typing import Iterator
from .base import Source
from ..models import Candidate


class PathSource(Source):
    """
    Discovers executables from PATH directories.
    """

    def iter_candidates(self) -> Iterator[Candidate]:
        """
        Scan PATH directories for executables.
        """
        path_env = os.environ.get("PATH", "")
        if not path_env:
            return

        path_dirs = [Path(p) for p in path_env.split(os.pathsep) if p]
        seen_dirs = set()

        for dir_path in path_dirs:
            try:
                real_path = dir_path.resolve()
                if real_path in seen_dirs:
                    continue
                seen_dirs.add(real_path)

                if not dir_path.exists() or not dir_path.is_dir():
                    continue

                with os.scandir(dir_path) as entries:
                    for entry in entries:
                        if entry.is_file():
                            # Check if executable
                            if os.access(entry.path, os.X_OK):
                                yield Candidate(
                                    path=Path(entry.path),
                                    source="PATH",
                                    hint=entry.name,
                                    depth=0,
                                )
            except (OSError, PermissionError):
                continue
