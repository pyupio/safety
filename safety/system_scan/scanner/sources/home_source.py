from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator
from .base import Source
from ..models import Candidate


class HomeSource(Source):
    """
    Discovers Python environments in home directory using markers.
    """

    DIR_MARKERS = {
        "pyvenv.cfg": "python:venv_root",
        "conda-meta": "python:conda_root",
        "pyproject.toml": "python:project_root",
        "requirements.txt": "python:project_root",
        "setup.py": "python:project_root",
        "setup.cfg": "python:project_root",
    }

    VENV_DIRNAMES = {".venv", "venv", ".tox", "env", ".virtualenv"}

    def __init__(
        self,
        home_dir: Path | None = None,
        max_depth: int = 5,
        prune_dirs: set[str] | None = None,
    ):
        self.home_dir = home_dir or Path.home()
        self.max_depth = max_depth
        self.prune_dirs = prune_dirs or {
            ".git",
            "node_modules",
            ".cache",
            "__pycache__",
            ".npm",
            ".yarn",
            ".cargo",
            ".rustup",
            ".docker",
            "Library",
            "Pictures",
            "Movies",
            "Music",
            "Downloads",
        }

    def iter_candidates(self) -> Iterator[Candidate]:
        """
        Scan home directory with marker-driven approach.
        """
        if not self.home_dir.exists():
            return

        stack = [(self.home_dir, 0)]

        while stack:
            current, depth = stack.pop()

            if depth > self.max_depth:
                continue

            try:
                with os.scandir(current) as entries:
                    names = set()
                    subdirs = []

                    for entry in entries:
                        names.add(entry.name)

                        if entry.is_dir(follow_symlinks=False):
                            if entry.name in self.prune_dirs:
                                continue

                            # Targeted venv discovery
                            if entry.name in self.VENV_DIRNAMES:
                                env_root = Path(entry.path)
                                if (env_root / "pyvenv.cfg").is_file():
                                    yield Candidate(
                                        path=env_root,
                                        source="HOME",
                                        hint="python:venv_root",
                                        depth=depth + 1,
                                    )
                                continue  # Don't descend into venv

                            subdirs.append(Path(entry.path))

                    # Check for markers in current directory
                    for marker, hint in self.DIR_MARKERS.items():
                        if marker in names:
                            yield Candidate(
                                path=current, source="HOME", hint=hint, depth=depth
                            )
                            break  # One marker is enough per dir

                    # Add subdirs to stack for deeper scanning
                    if depth < self.max_depth:
                        for subdir in subdirs:
                            stack.append((subdir, depth + 1))

            except (OSError, PermissionError):
                continue
