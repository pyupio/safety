from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator
from ...models import Candidate, Detection, DetectionKind
from ...filesystem import FsRuntime
from ...events.payloads.links import (
    ExecutionContextRelation,
    RuntimeRef,
    RuntimeRelations,
)
from .collectors import collect_python_runtime_info
import platform
import os

from ...context import DetectContext
from ...registry import ScanRefRegistry


class PythonRuntimeDetector:
    """
    Detects Python runtime installations.
    """

    # Pattern to match Python executables across platforms:
    # - python.exe (Windows)
    # - python, python3, python2 (Unix-like)
    # - pythonX.Y (e.g., python3.9, python3.10, etc.)
    PYTHON_PATTERN = re.compile(r"^python(?:\d+(?:\.\d+)?)?(?:\.exe)?$", re.IGNORECASE)

    def __init__(self):
        self.system = platform.system().lower()

        if self.system == "windows":
            self._exact_matches = frozenset(("python.exe", "python3.exe"))
            self._versioned_pattern = re.compile(r"^python3?\.\d+\.exe$", re.IGNORECASE)
        else:
            self._exact_matches = frozenset(("python", "python3"))
            self._versioned_pattern = re.compile(r"^python3?\.\d+$")

    def _is_python_executable_name(self, name: str) -> bool:
        """
        Check if filename looks like a Python executable.
        """
        return (
            name in self._exact_matches
            or self._versioned_pattern.match(name) is not None
        )

    def _validate_python_executable(self, path: Path, fs: FsRuntime) -> Path | None:
        """
        Validate path is a Python executable.
        Returns resolved real path or None.
        """
        if not self._is_python_executable_name(path.name):
            return None

        if not fs.is_file(path):
            return None

        if not fs.is_executable(path):
            return None

        resolved_path = fs.realpath(path)

        parent_dir = resolved_path.parent.parent
        if fs.is_file(parent_dir / "pyvenv.cfg"):
            return None

        return resolved_path

    def _find_python_in_directory(self, bin_dir: Path, fs: FsRuntime) -> Path | None:
        """
        Find first valid Python executable in a directory.
        """
        try:
            with os.scandir(bin_dir) as entries:
                for entry in entries:
                    resolved = self._validate_python_executable(Path(entry.path), fs)
                    if resolved is not None:
                        return resolved
        except (OSError, PermissionError):
            pass

        return None

    def build_entity_reference(
        self, path: Path, fs: FsRuntime, *, search_directory: bool = False
    ) -> RuntimeRef | None:
        """
        Build RuntimeRef if this is a valid Python runtime, None otherwise.
        """
        if search_directory:
            resolved = self._find_python_in_directory(path, fs)
        else:
            resolved = self._validate_python_executable(path, fs)

        if resolved is None:
            return None

        return RuntimeRef(canonical_path=str(resolved))

    def get_stable_id(self, entity_ref: RuntimeRef) -> str:
        """
        Generate a stable ID for the runtime.
        """
        return f"runtime:{entity_ref.canonical_path}"

    def detect(
        self,
        candidate: Candidate,
        ctx: DetectContext,
    ) -> Iterator[Detection]:
        """
        Detect Python runtime from candidate.
        """
        fs: FsRuntime = ctx.fs
        exec_context_ref: ExecutionContextRelation = ctx.exec_ctx_rel
        scan_registry: ScanRefRegistry = ctx.registry

        search_directory = False

        if "venv_bin" in candidate.hint:
            search_directory = True

        runtime_ref = self.build_entity_reference(
            candidate.path, fs, search_directory=search_directory
        )

        if not runtime_ref:
            return

        yield from self.detect_from_ref(
            runtime_ref, fs, exec_context_ref, scan_registry, source=candidate.source
        )

    def detect_from_ref(
        self,
        ref: RuntimeRef,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry: ScanRefRegistry,
        source: str = "DIRECT",
    ) -> Iterator[Detection]:
        """
        Detect Python runtime from RuntimeRef.
        """
        stable_id = self.get_stable_id(ref)

        # Already processed this runtime in this scan
        if scan_registry.is_seen(stable_id):
            return

        path = Path(ref.canonical_path)

        # Collect runtime information
        runtime_info = collect_python_runtime_info(path, fs)

        if not runtime_info:
            # There was an error collecting the runtime info
            # TODO: Log error
            return

        # Register in scan registry
        scan_registry.register_runtime(stable_id, ref)

        # Relations
        relations = RuntimeRelations(execution_context=exec_context_ref)
        runtime_info.links = relations

        # Build and yield detection with the stable ID we generated
        detection = Detection(
            kind=DetectionKind.RUNTIME,
            subtype="python",
            stable_id=stable_id,
            primary_path=str(path),
            scope="system" if self._is_system_python(path) else "user",
            found_via=[source],
            meta=runtime_info,
        )

        yield detection

    def _is_system_python(self, path: Path) -> bool:
        """
        Check if this is a system Python.
        TODO: Improve this logic
        """
        path_str = str(path)
        return (
            "/usr/bin" in path_str
            or "/usr/local/bin" in path_str
            or "System" in path_str
        )
