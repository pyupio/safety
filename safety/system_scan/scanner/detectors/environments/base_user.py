from __future__ import annotations

from pathlib import Path
from typing import Iterator, TYPE_CHECKING

from ...models import Detection, DetectionKind
from ...filesystem import FsRuntime
from ...events.payloads.environment import (
    EnvironmentInfo,
    PythonBaseEnvironment,
    PythonUserEnvironment,
)
from ...events.payloads.links import (
    EnvironmentRelations,
    ExecutionContextRelation,
    RuntimeRelation,
    EnvironmentRelation,
    EnvironmentRef,
    RuntimeRef,
    DependencyRelations,
)
from .helpers import (
    _to_major_minor,
    _collect_prefixes,
    _base_env_canonical_path,
    _get_base_package_dirs,
    _get_user_site_packages,
)
from ...registry import ScanRefRegistry

if TYPE_CHECKING:
    from ..dependencies.main import PythonDependencyDetector


class BaseUserEnvDetector:
    """
    Detects base (system-wide) and user-site Python environments
    for a given Python runtime.
    """

    def __init__(self, dependency_detector: PythonDependencyDetector):
        self.dependency_detector = dependency_detector

    @staticmethod
    def get_stable_id(env_ref: EnvironmentRef) -> str:
        return f"env:{env_ref.canonical_path}"

    def detect_for_runtime(
        self,
        candidate_path: Path,
        runtime_ref: RuntimeRef,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry: ScanRefRegistry,
        runtime_version: str | None = None,
    ) -> Iterator[Detection]:
        """
        Detect base and user environments for a successfully detected runtime.

        Called by RuntimeDetector.detect() after a runtime is registered.

        Args:
            candidate_path: Original (possibly symlinked) path to the Python binary.
            runtime_ref: The RuntimeRef for the detected runtime.
            fs: Filesystem runtime.
            exec_context_ref: Execution context relation.
            scan_registry: Scan-wide dedup registry.
            runtime_version: Python version string from the runtime detector
                (e.g. '3.11.6' or '3.11'), used to determine package directories.
        """
        resolved = Path(runtime_ref.canonical_path)

        major_minor = _to_major_minor(runtime_version)

        if not major_minor:
            return  # can't enumerate package dirs without version

        prefixes = _collect_prefixes(candidate_path, resolved)

        for prefix in prefixes:
            yield from self._detect_base_environment(
                prefix,
                major_minor,
                resolved,
                runtime_ref,
                fs,
                exec_context_ref,
                scan_registry,
            )

        yield from self._detect_user_environment(
            major_minor, runtime_ref, fs, exec_context_ref, scan_registry
        )

    def _detect_base_environment(
        self,
        prefix: Path,
        major_minor: str,
        runtime_path: Path,
        runtime_ref: RuntimeRef,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry: ScanRefRegistry,
    ) -> Iterator[Detection]:
        """
        Detect python:base environment at the given prefix.
        """
        # Canonical path for base env
        canonical = _base_env_canonical_path(prefix, major_minor)
        env_ref = EnvironmentRef(canonical_path=str(canonical))
        env_stable_id = self.get_stable_id(env_ref)

        if scan_registry.is_seen(env_stable_id):
            return

        # Enumerate package directories for this base environment
        pkg_dirs = _get_base_package_dirs(prefix, major_minor)

        # Check if at least one package directory exists
        existing_pkg_dirs = [d for d in pkg_dirs if fs.is_dir(d)]
        if not existing_pkg_dirs:
            return  # no package directories found -- skip this base env

        scan_registry.register_environment(env_stable_id, env_ref)

        # Build environment info
        base_info = PythonBaseEnvironment(
            canonical_path=str(canonical),
            site_packages_path=str(existing_pkg_dirs[0]),
            runtime_path=str(runtime_path),
        )

        # Relations: base env links to its runtime
        runtime_relation = RuntimeRelation(ref=runtime_ref)
        environment_relation = EnvironmentRelation(ref=env_ref)

        # Cascade: detect packages in all package directories
        yield from self._detect_dependencies_multi_dir(
            existing_pkg_dirs,
            canonical,
            fs,
            exec_context_ref,
            environment_relation,
            scan_registry,
            found_via=["BASE_SITE_PACKAGES"],
        )

        # Set environment relations and yield environment detection
        base_info.links = EnvironmentRelations(
            execution_context=exec_context_ref,
            runtime=runtime_relation,
        )
        yield self._create_detection(env_ref, base_info, ["RUNTIME_ENV_DISCOVERY"])

    def _detect_user_environment(
        self,
        major_minor: str,
        runtime_ref: RuntimeRef,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry: ScanRefRegistry,
    ) -> Iterator[Detection]:
        """
        Detect python:user environment for the given Python version.

        Deduped by versioned user-site path -- if multiple runtimes share the
        same major.minor (e.g., system 3.12.3 + uv 3.12.7), only the first
        triggers detection. The user env links to that first runtime.
        """
        user_site = _get_user_site_packages(major_minor)
        if not user_site or not fs.is_dir(user_site):
            return

        canonical = str(user_site)
        env_ref = EnvironmentRef(canonical_path=canonical)
        env_stable_id = self.get_stable_id(env_ref)

        if scan_registry.is_seen(env_stable_id):
            return  # already detected by another runtime of the same version

        scan_registry.register_environment(env_stable_id, env_ref)

        user_info = PythonUserEnvironment(
            canonical_path=canonical,
            site_packages_path=canonical,
            user_site_enabled=True,
        )

        environment_relation = EnvironmentRelation(ref=env_ref)

        # Cascade: detect packages in user site-packages
        yield from self._detect_dependencies_multi_dir(
            [user_site],
            Path(canonical),
            fs,
            exec_context_ref,
            environment_relation,
            scan_registry,
            found_via=["USER_SITE_PACKAGES"],
        )

        # Link to the runtime that triggered detection (first wins on dedup)
        runtime_relation = RuntimeRelation(ref=runtime_ref)
        user_info.links = EnvironmentRelations(
            execution_context=exec_context_ref,
            runtime=runtime_relation,
        )
        yield self._create_detection(env_ref, user_info, ["RUNTIME_ENV_DISCOVERY"])

    def _detect_dependencies_multi_dir(
        self,
        package_dirs: list[Path],
        env_canonical_path: Path,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        environment_relation: EnvironmentRelation,
        scan_registry: ScanRefRegistry,
        found_via: list[str],
    ) -> Iterator[Detection]:
        """
        Detect dependencies across multiple package directories for one environment.

        Deduplicates at the directory level -- if two environments share a physical
        directory, only the first one scans it.
        """
        relations = DependencyRelations(
            execution_context=exec_context_ref,
            environment=environment_relation,
        )

        for pkg_dir in package_dirs:
            dir_key = f"pkgdir:{pkg_dir}"

            if scan_registry.is_seen(dir_key):
                continue

            scan_registry.register_other(dir_key)

            for detection in self.dependency_detector.detect_packages(
                pkg_dir, env_canonical_path, fs
            ):
                detection.meta.links = relations
                detection.found_via = found_via
                yield detection

    @staticmethod
    def _create_detection(
        environment_ref: EnvironmentRef,
        env_info: EnvironmentInfo,
        found_via: list[str],
    ) -> Detection:
        """
        Create Detection object from environment information.
        """
        primary_path = env_info.canonical_path

        if isinstance(env_info, PythonBaseEnvironment):
            scope = "system"
        elif isinstance(env_info, PythonUserEnvironment):
            scope = "user"
        else:
            scope = "project"

        return Detection(
            kind=DetectionKind.ENVIRONMENT,
            subtype=env_info.subtype.value,
            stable_id=BaseUserEnvDetector.get_stable_id(environment_ref),
            primary_path=primary_path,
            scope=scope,
            found_via=found_via,
            meta=env_info,
        )
