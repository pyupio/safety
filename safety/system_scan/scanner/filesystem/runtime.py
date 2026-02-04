from __future__ import annotations

import os
import hashlib
from pathlib import Path


class FsRuntime:
    """
    Wrapper for filesystem operations with security constraints.

    # TODO: Refactor and enforce usage of this class.
    """

    def __init__(self, follow_symlinks: bool = False):
        self.follow_symlinks = follow_symlinks

    def realpath(self, path: Path) -> Path:
        try:
            return path.resolve()
        except (OSError, RuntimeError):
            return path

    def stat(self, path: Path) -> os.stat_result:
        return os.stat(path, follow_symlinks=self.follow_symlinks)

    def exists(self, path: Path) -> bool:
        try:
            return path.exists()
        except (OSError, PermissionError):
            return False

    def is_file(self, path: Path) -> bool:
        try:
            return path.is_file()
        except (OSError, PermissionError):
            return False

    def is_dir(self, path: Path) -> bool:
        try:
            return path.is_dir()
        except (OSError, PermissionError):
            return False

    def is_executable(self, path: Path) -> bool:
        try:
            if not self.is_file(path):
                return False
            return os.access(path, os.X_OK)
        except (OSError, PermissionError):
            return False

    def read_text(self, path: Path, max_bytes: int = 64_000) -> str | None:
        """
        Read text file with size limit.
        """
        try:
            stat = self.stat(path)
            if stat.st_size > max_bytes:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(max_bytes)
            else:
                return path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError, UnicodeDecodeError):
            return None

    def scandir(self, path: Path):
        try:
            return os.scandir(path)
        except (OSError, PermissionError):
            return []

    def sha256(self, path: Path) -> str | None:
        """
        Calculate SHA256 hash of a file.
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (OSError, PermissionError, IOError):
            return None
