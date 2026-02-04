from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, TYPE_CHECKING
import platform
from ...models import Candidate, Detection, DetectionKind
from ...filesystem import FsRuntime
from ...events.payloads.environment import (
    EnvironmentInfo,
    PythonBaseEnvironment,
    PythonUserEnvironment,
    PythonVenvEnvironment,
)
from ...events.payloads.links import (
    EnvironmentRelations,
    ExecutionContextRelation,
    RuntimeRelation,
    EnvironmentRelation,
    EnvironmentRef,
    RuntimeRef,
    DependencyRelations,
    ToolRelations,
)
from .collectors import (
    collect_venv_environment_info,
)
from ...registry import ScanRefRegistry
from ...context import DetectContext

if TYPE_CHECKING:
    from ..dependencies.main import PythonDependencyDetector
    from ..tools.main import ToolDetector
    from ..runtimes.main import PythonRuntimeDetector
    from ...context import DetectContext


class PythonEnvironmentDetector:
    """
    Detects Python environments (venv, base, user).
    """

    def __init__(
        self,
        dependency_detector: PythonDependencyDetector,
        tool_detector: ToolDetector,
        runtime_detector: PythonRuntimeDetector,
    ):
        self.dependency_detector = dependency_detector
        self.tool_detector = tool_detector
        self.runtime_detector = runtime_detector

    def build_entity_reference(
        self,
        path: Path,
        fs: FsRuntime,
    ) -> EnvironmentRef | None:
        """
        Build EnvironmentRef if this is a valid venv, None otherwise
        """
        # Validation happens here
        if not fs.is_file(path / "pyvenv.cfg"):
            return None

        canonical_path = str(fs.realpath(path))

        return EnvironmentRef(canonical_path=canonical_path)

    def get_stable_id(self, entity_ref: EnvironmentRef) -> str:
        """
        Generate a stable ID for the environment.
        """
        return f"env:{entity_ref.canonical_path}"

    def detect(self, candidate: Candidate, ctx: DetectContext) -> Iterator[Detection]:
        """
        Detect Python environments from candidate.
        """
        fs = ctx.fs
        exec_context_ref = ctx.exec_ctx_rel
        scan_registry = ctx.registry

        # Check for venv
        if "venv_root" in candidate.hint:
            yield from self._detect_from_venv_root(
                candidate, fs, exec_context_ref, scan_registry
            )

        # Check for Python project that might have environments
        elif "project_root" in candidate.hint:
            yield from self._detect_project_envs(
                candidate, fs, exec_context_ref, scan_registry
            )

    def _detect_from_venv_root(
        self,
        candidate: Candidate,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry: ScanRefRegistry,
    ) -> Iterator[Detection]:
        """
        Detect Python virtual environment from venv root

        Args:
            candidate: Candidate to check
            fs: Filesystem runtime

        Yields:
            Detection objects for runtimes, packages, tools, and the environment
        """

        environment_ref = self.build_entity_reference(candidate.path, fs)

        # If not a valid venv, return
        if not environment_ref:
            return

        env_stable_id = self.get_stable_id(environment_ref)

        # Already processed this environment in this scan
        if scan_registry.is_seen(env_stable_id):
            return

        venv_root = Path(environment_ref.canonical_path)

        venv_info = collect_venv_environment_info(venv_root, fs)

        if not venv_info:
            # There was an error collecting the venv info
            # TODO: Log error
            return

        scan_registry.register_environment(env_stable_id, environment_ref)

        bin_path, site_packages_path = self._get_paths(venv_root, fs)

        runtime_ref = self._get_runtime_ref(venv_info, bin_path, fs)

        runtime_relation = None

        if runtime_ref:
            runtime_relation = RuntimeRelation(ref=runtime_ref)
            yield from self.runtime_detector.detect_from_ref(
                runtime_ref,
                fs,
                exec_context_ref,
                scan_registry,
                source=candidate.source,
            )

        # Cascade: detect packages and tools using PEP 405 standard layout
        # Relations
        environment_relation = EnvironmentRelation(ref=environment_ref)

        yield from self._detect_dependencies(
            site_packages_path, venv_root, fs, exec_context_ref, environment_relation
        )

        yield from self._detect_tools(
            bin_path, fs, scan_registry, exec_context_ref, environment_relation
        )

        env_relations = EnvironmentRelations(
            execution_context=exec_context_ref, runtime=runtime_relation
        )

        # Yield environment with relations
        venv_info.links = env_relations
        yield self._create_detection(environment_ref, venv_info, [candidate.source])

    def _get_paths(self, venv_root: Path, fs: FsRuntime) -> tuple[Path, Path | None]:
        # Determine paths based on OS (PEP 405)
        if platform.system().lower() == "windows":
            site_packages_path = venv_root / "Lib" / "site-packages"
            bin_path = venv_root / "Scripts"
        else:
            # Unix/Linux/macOS - find python directory in lib/
            lib_dir = venv_root / "lib"
            site_packages_path = None
            if fs.is_dir(lib_dir):
                # Find python directory (e.g., python3.11)
                try:
                    with os.scandir(lib_dir) as entries:
                        for entry in entries:
                            if entry.is_dir() and entry.name.startswith("python"):
                                site_packages_path = (
                                    lib_dir / entry.name / "site-packages"
                                )
                                break
                except (OSError, PermissionError):
                    pass
            bin_path = venv_root / "bin"

        return bin_path, site_packages_path

    def _get_runtime_ref(
        self, venv: PythonVenvEnvironment, bin_path: Path, fs: FsRuntime
    ) -> RuntimeRef | None:
        """
        Get runtime reference for the venv.
        """

        if venv.python_venv_pyvenv_cfg and (
            home := venv.python_venv_pyvenv_cfg.get("home")
        ):
            ref = self.runtime_detector.build_entity_reference(
                Path(home), fs, search_directory=True
            )
            if ref:
                return ref

        return self.runtime_detector.build_entity_reference(
            bin_path, fs, search_directory=True
        )

    def _detect_tools(
        self,
        bin_path: Path | None,
        fs: FsRuntime,
        scan_registry: ScanRefRegistry,
        exec_context_ref: ExecutionContextRelation,
        environment_relation: EnvironmentRelation,
    ) -> Iterator[Detection]:
        """
        Detect tools in bin directory.
        """
        if not bin_path:
            return

        relations = ToolRelations(
            execution_context=exec_context_ref, environment=environment_relation
        )

        for detection in self.tool_detector.scan_directory(
            bin_path, fs, exec_context_ref, scan_registry, "ENV_BIN_SCAN"
        ):
            detection.meta.links = relations
            yield detection

    def _detect_dependencies(
        self,
        site_packages_path: Path | None,
        venv_root: Path,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        environment_relation: EnvironmentRelation,
    ) -> Iterator[Detection]:
        """
        Detect dependencies in site-packages.
        """
        if not site_packages_path:
            return

        relations = DependencyRelations(
            execution_context=exec_context_ref, environment=environment_relation
        )

        for detection in self.dependency_detector.detect_packages(
            site_packages_path, venv_root, fs
        ):
            detection.meta.links = relations
            yield detection

    def _detect_project_envs(
        self,
        candidate: Candidate,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry,
    ) -> Iterator[Detection]:
        """
        Look for environments in a Python project.

        Args:
            candidate: Candidate to check
            fs: Filesystem runtime

        Yields:
            Detection objects for found environments
        """
        project_root = candidate.path

        # Check for common venv directories
        for venv_name in [".venv", "venv", "env", ".virtualenv"]:
            venv_path = project_root / venv_name
            if fs.is_dir(venv_path) and fs.is_file(venv_path / "pyvenv.cfg"):
                yield from self._detect_from_venv_root(
                    Candidate(
                        venv_path,
                        "PROJECT_SCAN",
                        "python:venv_root",
                        candidate.depth + 1,
                    ),
                    fs,
                    exec_context_ref,
                    scan_registry,
                )

    def _create_detection(
        self,
        environment_ref: EnvironmentRef,
        env_info: EnvironmentInfo,
        found_via: list[str],
    ) -> Detection:
        """
        Create Detection object from environment information.

        Args:
            env_info: Environment information dataclass
            found_via: list of sources that found this environment

        Returns:
            Detection object
        """
        primary_path = env_info.canonical_path

        # Determine scope based on environment type
        if isinstance(env_info, PythonBaseEnvironment):
            scope = "system"
        elif isinstance(env_info, PythonUserEnvironment):
            scope = "user"
        else:  # PythonVenvEnvironment
            scope = "project"

        return Detection(
            kind=DetectionKind.ENVIRONMENT,
            subtype=env_info.subtype.value,
            stable_id=self.get_stable_id(environment_ref),
            primary_path=primary_path,
            scope=scope,
            found_via=found_via,
            meta=env_info,
        )
