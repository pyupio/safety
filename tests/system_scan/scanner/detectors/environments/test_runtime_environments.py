from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from safety.system_scan.scanner.detectors.environments.base_user import (
    BaseUserEnvDetector,
)
from safety.system_scan.scanner.models import (
    Detection,
    DetectionKind,
)
from safety.system_scan.scanner.filesystem import FsRuntime
from safety.system_scan.scanner.events.payloads.links import (
    EnvironmentRef,
    RuntimeRef,
    ExecutionContextRelation,
    HostRef,
)
from safety.system_scan.scanner.registry import ScanRefRegistry

# Patch targets for helpers (they import platform directly)
HELPERS_PLATFORM = "safety.system_scan.scanner.detectors.environments.helpers.platform"


def _make_mock_detection(stable_id: str = "pkg:mock") -> Detection:
    """
    Create a mock Detection with mutable meta.links and found_via.
    """
    meta = MagicMock()
    meta.links = None
    return Detection(
        kind=DetectionKind.DEPENDENCY,
        subtype="python",
        stable_id=stable_id,
        primary_path="/mock",
        scope="environment",
        found_via=["MOCK"],
        meta=meta,
    )


def _make_exec_ctx_rel() -> ExecutionContextRelation:
    return ExecutionContextRelation(
        ref=HostRef(machine_id="test-machine", hostname="test-host")
    )


def _make_fs(
    existing_dirs: set[Path],
    realpath_map: dict[Path, Path] | None = None,
) -> Mock:
    """
    Build a mock FsRuntime.
    - is_dir returns True for paths in existing_dirs (Path equality)
    - realpath returns mapped value or identity
    """
    fs = Mock(spec=FsRuntime)
    fs.is_dir.side_effect = lambda p: p in existing_dirs

    if realpath_map:
        fs.realpath.side_effect = lambda p: realpath_map.get(p, p)
    else:
        fs.realpath.side_effect = lambda p: p

    return fs


def _make_detector(
    dep_packages_side_effect=None,
) -> BaseUserEnvDetector:
    """
    Build a BaseUserEnvDetector with mocked dependency detector.
    """
    dep_detector = Mock()

    if dep_packages_side_effect is not None:
        dep_detector.detect_packages.side_effect = dep_packages_side_effect
    else:
        dep_detector.detect_packages.return_value = iter([])

    return BaseUserEnvDetector(dep_detector)


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario1HomebrewMacOS:
    """
    macOS Homebrew Python with base and user environments.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Darwin")
    def test_homebrew_base_and_user_envs(self, _mock_platform):
        resolved = Path(
            "/opt/homebrew/Cellar/python@3.11/3.11.6/Frameworks/"
            "Python.framework/Versions/3.11/bin/python3.11"
        )
        framework_prefix = Path(
            "/opt/homebrew/Cellar/python@3.11/3.11.6/Frameworks/"
            "Python.framework/Versions/3.11"
        )
        framework_sp = framework_prefix / "lib" / "python3.11" / "site-packages"
        user_sp = Path.home() / "Library/Python/3.11/lib/python/site-packages"

        existing_dirs = {framework_sp, user_sp}

        fs = _make_fs(existing_dirs)

        registry = ScanRefRegistry()
        runtime_ref = RuntimeRef(canonical_path=str(resolved))

        # Packages: 2 in base, 1 in user
        packages_by_dir = {
            framework_sp: [
                _make_mock_detection("pkg:setuptools"),
                _make_mock_detection("pkg:pip"),
            ],
            user_sp: [_make_mock_detection("pkg:httpx")],
        }

        def detect_packages_side_effect(site_packages, env_path, fs_arg):
            assert site_packages in packages_by_dir, f"Unexpected path: {site_packages}"
            return iter(packages_by_dir[site_packages])

        detector = _make_detector(dep_packages_side_effect=detect_packages_side_effect)
        exec_ctx_rel = _make_exec_ctx_rel()

        candidate_path = Path("/opt/homebrew/bin/python3.11")

        detections = list(
            detector.detect_for_runtime(
                candidate_path=candidate_path,
                runtime_ref=runtime_ref,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11.6",
            )
        )

        # Count by kind
        env_dets = [d for d in detections if d.kind == DetectionKind.ENVIRONMENT]
        dep_dets = [d for d in detections if d.kind == DetectionKind.DEPENDENCY]

        # 2 base deps + 1 base env + 1 user dep + 1 user env = 5
        assert len(env_dets) == 2
        assert len(dep_dets) == 3
        assert len(detections) == 5

        # Base env
        base_env = [d for d in env_dets if d.subtype == "python:base"][0]
        assert base_env.scope == "system"
        assert base_env.found_via == ["RUNTIME_ENV_DISCOVERY"]
        assert base_env.meta.runtime_path == str(resolved)
        assert base_env.meta.links.runtime is not None
        assert base_env.meta.links.runtime.ref.canonical_path == str(resolved)

        # User env
        user_env = [d for d in env_dets if d.subtype == "python:user"][0]
        assert user_env.scope == "user"
        assert user_env.found_via == ["RUNTIME_ENV_DISCOVERY"]
        assert user_env.meta.links.runtime is not None
        assert user_env.meta.links.runtime.ref.canonical_path == str(resolved)
        assert user_env.meta.user_site_enabled is True

        # Dependency found_via
        base_deps = [d for d in dep_dets if d.found_via == ["BASE_SITE_PACKAGES"]]
        user_deps = [d for d in dep_dets if d.found_via == ["USER_SITE_PACKAGES"]]
        assert len(base_deps) == 2
        assert len(user_deps) == 1

        # All deps have environment links
        for dep in dep_dets:
            assert dep.meta.links is not None
            assert dep.meta.links.environment is not None


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario2UbuntuDebian:
    """
    Debian-specific package directory layout with dist-packages.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_debian_dist_packages_multi_dir(self, _mock_platform):
        resolved = Path("/usr/bin/python3.11")
        versioned_dist = Path("/usr/lib/python3.11/dist-packages")
        shared_dist = Path("/usr/lib/python3/dist-packages")
        local_dist = Path("/usr/local/lib/python3.11/dist-packages")

        existing_dirs = {versioned_dist, shared_dist, local_dist}
        # user site does NOT exist
        user_sp = Path.home() / ".local/lib/python3.11/site-packages"
        assert user_sp not in existing_dirs

        fs = _make_fs(existing_dirs)
        registry = ScanRefRegistry()
        runtime_ref = RuntimeRef(canonical_path=str(resolved))

        packages_by_dir = {
            versioned_dist: [_make_mock_detection("pkg:apt_pkg")],
            shared_dist: [_make_mock_detection("pkg:python_apt")],
            local_dist: [_make_mock_detection("pkg:requests")],
        }

        def detect_packages_side_effect(site_packages, env_path, fs_arg):
            assert site_packages in packages_by_dir, f"Unexpected path: {site_packages}"
            return iter(packages_by_dir[site_packages])

        detector = _make_detector(dep_packages_side_effect=detect_packages_side_effect)
        exec_ctx_rel = _make_exec_ctx_rel()

        candidate_path = Path("/usr/bin/python3.11")

        detections = list(
            detector.detect_for_runtime(
                candidate_path=candidate_path,
                runtime_ref=runtime_ref,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11",
            )
        )

        env_dets = [d for d in detections if d.kind == DetectionKind.ENVIRONMENT]
        dep_dets = [d for d in detections if d.kind == DetectionKind.DEPENDENCY]

        # 3 deps (from 3 dirs) + 1 base env + 0 user env = 4
        assert len(dep_dets) == 3
        assert len(env_dets) == 1
        assert len(detections) == 4

        base_env = env_dets[0]
        assert base_env.subtype == "python:base"
        assert base_env.stable_id == "env:/usr/lib/python3.11"
        assert base_env.scope == "system"

        # All deps reference same env
        for dep in dep_dets:
            assert dep.found_via == ["BASE_SITE_PACKAGES"]
            assert (
                dep.meta.links.environment.ref.canonical_path == "/usr/lib/python3.11"
            )


@pytest.mark.windows_only
@pytest.mark.unit
class TestScenario3Windows:
    """
    Windows-specific path layout.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    @patch.dict("os.environ", {"APPDATA": "/C/Users/alice/AppData/Roaming"})
    def test_windows_base_and_user_envs(self, _mock_platform):
        resolved = Path("/C/Python311/python.exe")
        base_sp = Path("/C/Python311/Lib/site-packages")
        user_sp = Path("/C/Users/alice/AppData/Roaming/Python/Python311/site-packages")

        existing_dirs = {base_sp, user_sp}
        fs = _make_fs(existing_dirs)

        registry = ScanRefRegistry()
        runtime_ref = RuntimeRef(canonical_path=str(resolved))

        packages_by_dir = {
            base_sp: [
                _make_mock_detection("pkg:pip"),
                _make_mock_detection("pkg:setuptools"),
            ],
            user_sp: [_make_mock_detection("pkg:black")],
        }

        def detect_packages_side_effect(site_packages, env_path, fs_arg):
            assert site_packages in packages_by_dir, f"Unexpected path: {site_packages}"
            return iter(packages_by_dir[site_packages])

        detector = _make_detector(dep_packages_side_effect=detect_packages_side_effect)
        exec_ctx_rel = _make_exec_ctx_rel()

        candidate_path = Path("/C/Python311/python.exe")

        detections = list(
            detector.detect_for_runtime(
                candidate_path=candidate_path,
                runtime_ref=runtime_ref,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11",
            )
        )

        env_dets = [d for d in detections if d.kind == DetectionKind.ENVIRONMENT]
        dep_dets = [d for d in detections if d.kind == DetectionKind.DEPENDENCY]

        # 2 base deps + 1 base env + 1 user dep + 1 user env = 5
        assert len(dep_dets) == 3
        assert len(env_dets) == 2
        assert len(detections) == 5

        # Windows canonical path uses Lib (no version in dir)
        base_env = [d for d in env_dets if d.subtype == "python:base"][0]
        assert "Lib" in base_env.stable_id
        assert base_env.scope == "system"

        user_env = [d for d in env_dets if d.subtype == "python:user"][0]
        assert user_env.scope == "user"
        assert user_env.meta.links.runtime is not None
        assert user_env.meta.links.runtime.ref.canonical_path == str(resolved)


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario4Fedora:
    """
    Fedora uses lib64 for 64-bit packages.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_fedora_lib64(self, _mock_platform):
        resolved = Path("/usr/bin/python3.12")
        lib64_sp = Path("/usr/lib64/python3.12/site-packages")
        lib_sp = Path("/usr/lib/python3.12/site-packages")
        user_sp = Path.home() / ".local/lib/python3.12/site-packages"

        existing_dirs = {lib64_sp, lib_sp, user_sp}

        fs = _make_fs(existing_dirs)
        registry = ScanRefRegistry()
        runtime_ref = RuntimeRef(canonical_path=str(resolved))

        packages_by_dir = {
            lib_sp: [],  # exists but empty
            lib64_sp: [
                _make_mock_detection("pkg:dnf"),
                _make_mock_detection("pkg:rpm"),
            ],
            user_sp: [_make_mock_detection("pkg:poetry")],
        }

        def detect_packages_side_effect(site_packages, env_path, fs_arg):
            assert site_packages in packages_by_dir, f"Unexpected path: {site_packages}"
            return iter(packages_by_dir[site_packages])

        detector = _make_detector(dep_packages_side_effect=detect_packages_side_effect)
        exec_ctx_rel = _make_exec_ctx_rel()

        candidate_path = Path("/usr/bin/python3.12")

        detections = list(
            detector.detect_for_runtime(
                candidate_path=candidate_path,
                runtime_ref=runtime_ref,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.12",
            )
        )

        env_dets = [d for d in detections if d.kind == DetectionKind.ENVIRONMENT]
        dep_dets = [d for d in detections if d.kind == DetectionKind.DEPENDENCY]

        # 2 lib64 deps + 0 stdlib deps + 1 base env + 1 user dep + 1 user env = 5
        assert len(dep_dets) == 3
        assert len(env_dets) == 2
        assert len(detections) == 5

        base_env = [d for d in env_dets if d.subtype == "python:base"][0]
        # canonical_path is /usr/lib/python3.12 (not lib64)
        assert base_env.stable_id == "env:/usr/lib/python3.12"
        # site_packages_path is the first existing dir (standard site-packages)
        assert base_env.meta.site_packages_path == str(lib_sp)


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario5PyenvMultiRuntime:
    """
    Two Python 3.11 runtimes: system + pyenv. User env deduped.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_user_env_dedup(self, _mock_platform):
        resolved_a = Path("/usr/bin/python3.11")
        resolved_b = Path("/home/alice/.pyenv/versions/3.11.6/bin/python3.11")

        system_sp = Path("/usr/lib/python3.11/site-packages")
        pyenv_sp = Path(
            "/home/alice/.pyenv/versions/3.11.6/lib/python3.11/site-packages"
        )
        user_sp = Path.home() / ".local/lib/python3.11/site-packages"

        existing_dirs = {system_sp, pyenv_sp, user_sp}

        fs = _make_fs(existing_dirs)

        registry = ScanRefRegistry()
        runtime_ref_a = RuntimeRef(canonical_path=str(resolved_a))
        runtime_ref_b = RuntimeRef(canonical_path=str(resolved_b))

        packages_by_dir = {
            system_sp: [_make_mock_detection("pkg:setuptools")],
            pyenv_sp: [_make_mock_detection("pkg:numpy")],
            user_sp: [_make_mock_detection("pkg:httpx")],
        }

        def detect_packages_side_effect(site_packages, env_path, fs_arg):
            assert site_packages in packages_by_dir, f"Unexpected path: {site_packages}"
            return iter(packages_by_dir[site_packages])

        detector = _make_detector(dep_packages_side_effect=detect_packages_side_effect)
        exec_ctx_rel = _make_exec_ctx_rel()

        # --- Process Runtime A (system Python) ---
        detections_a = list(
            detector.detect_for_runtime(
                candidate_path=Path("/usr/bin/python3.11"),
                runtime_ref=runtime_ref_a,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11",
            )
        )

        # --- Process Runtime B (pyenv Python) ---
        detections_b = list(
            detector.detect_for_runtime(
                candidate_path=Path("/home/alice/.pyenv/shims/python3.11"),
                runtime_ref=runtime_ref_b,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11.6",
            )
        )

        # Runtime A: 1 base dep + 1 base env + 1 user dep + 1 user env = 4
        env_dets_a = [d for d in detections_a if d.kind == DetectionKind.ENVIRONMENT]
        dep_dets_a = [d for d in detections_a if d.kind == DetectionKind.DEPENDENCY]
        assert len(env_dets_a) == 2  # base + user
        assert len(dep_dets_a) == 2  # 1 base + 1 user

        # Runtime B: 1 base dep + 1 base env + 0 user = 2 (user deduped!)
        env_dets_b = [d for d in detections_b if d.kind == DetectionKind.ENVIRONMENT]
        dep_dets_b = [d for d in detections_b if d.kind == DetectionKind.DEPENDENCY]
        assert len(env_dets_b) == 1  # only base (user deduped)
        assert len(dep_dets_b) == 1  # only base dep

        # Verify only one user env across both, linked to FIRST runtime (A)
        all_user_envs = [
            d
            for d in detections_a + detections_b
            if d.kind == DetectionKind.ENVIRONMENT and d.subtype == "python:user"
        ]
        assert len(all_user_envs) == 1
        assert all_user_envs[0].meta.links.runtime is not None
        assert all_user_envs[0].meta.links.runtime.ref.canonical_path == str(resolved_a)

        # Total: 6
        assert len(detections_a) + len(detections_b) == 6


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario6UbuntuMultiVersion:
    """
    Two Python versions sharing /usr/lib/python3/dist-packages. Directory-level dedup.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_pkgdir_dedup(self, _mock_platform):
        resolved_a = Path("/usr/bin/python3.11")
        resolved_b = Path("/usr/bin/python3.12")

        dist_311 = Path("/usr/lib/python3.11/dist-packages")
        dist_312 = Path("/usr/lib/python3.12/dist-packages")
        shared_dist = Path("/usr/lib/python3/dist-packages")
        user_311 = Path.home() / ".local/lib/python3.11/site-packages"
        user_312 = Path.home() / ".local/lib/python3.12/site-packages"

        existing_dirs = {dist_311, dist_312, shared_dist, user_311, user_312}

        fs = _make_fs(existing_dirs)
        registry = ScanRefRegistry()
        runtime_ref_a = RuntimeRef(canonical_path=str(resolved_a))
        runtime_ref_b = RuntimeRef(canonical_path=str(resolved_b))

        packages_by_dir = {
            dist_311: [_make_mock_detection("pkg:apt_pkg-2.6")],
            dist_312: [_make_mock_detection("pkg:apt_pkg-2.7")],
            shared_dist: [_make_mock_detection("pkg:python_apt")],
            user_311: [_make_mock_detection("pkg:black")],
            user_312: [_make_mock_detection("pkg:ruff")],
        }

        def detect_packages_side_effect(site_packages, env_path, fs_arg):
            assert site_packages in packages_by_dir, f"Unexpected path: {site_packages}"
            return iter(packages_by_dir[site_packages])

        detector = _make_detector(dep_packages_side_effect=detect_packages_side_effect)
        exec_ctx_rel = _make_exec_ctx_rel()

        # --- Process Runtime A (python3.11) ---
        detections_a = list(
            detector.detect_for_runtime(
                candidate_path=Path("/usr/bin/python3.11"),
                runtime_ref=runtime_ref_a,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11",
            )
        )

        # --- Process Runtime B (python3.12) ---
        detections_b = list(
            detector.detect_for_runtime(
                candidate_path=Path("/usr/bin/python3.12"),
                runtime_ref=runtime_ref_b,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.12",
            )
        )

        # Runtime A: 1 versioned + 1 shared + 1 base env + 1 user dep + 1 user env = 5
        assert len(detections_a) == 5

        # Runtime B: 1 versioned + 0 shared (deduped!) + 1 base env + 1 user dep + 1 user env = 4
        assert len(detections_b) == 4

        # Verify shared dir was claimed by 3.11
        python_apt_dets = [d for d in detections_a if d.stable_id == "pkg:python_apt"]
        assert len(python_apt_dets) == 1
        assert (
            python_apt_dets[0].meta.links.environment.ref.canonical_path
            == "/usr/lib/python3.11"
        )

        # Verify NOT in runtime B
        python_apt_in_b = [d for d in detections_b if d.stable_id == "pkg:python_apt"]
        assert len(python_apt_in_b) == 0

        # Total: 9
        assert len(detections_a) + len(detections_b) == 9

        # Verify pkgdir dedup: the shared dir key was registered
        assert registry.is_seen(f"pkgdir:{Path('/usr/lib/python3/dist-packages')}")


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario7NoVersion:
    """
    Runtime detected but version can't be extracted from path.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_no_version_skipped(self, _mock_platform):
        resolved = Path("/usr/bin/python3")
        detector = _make_detector()
        fs = _make_fs(set())

        registry = ScanRefRegistry()
        runtime_ref = RuntimeRef(canonical_path=str(resolved))
        exec_ctx_rel = _make_exec_ctx_rel()

        detections = list(
            detector.detect_for_runtime(
                candidate_path=Path("/usr/bin/python3"),
                runtime_ref=runtime_ref,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version=None,
            )
        )

        assert detections == []
        detector.dependency_detector.detect_packages.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario8NoPkgDirs:
    """
    Runtime exists, version known, but no package dirs on disk.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_no_dirs_skipped(self, _mock_platform):
        resolved = Path("/usr/bin/python3.13")
        detector = _make_detector()
        # No dirs exist at all
        fs = _make_fs(set())

        registry = ScanRefRegistry()
        runtime_ref = RuntimeRef(canonical_path=str(resolved))
        exec_ctx_rel = _make_exec_ctx_rel()

        detections = list(
            detector.detect_for_runtime(
                candidate_path=Path("/usr/bin/python3.13"),
                runtime_ref=runtime_ref,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.13",
            )
        )

        assert detections == []
        # No register_environment calls
        assert not registry.is_seen("env:/usr/lib/python3.13")
        detector.dependency_detector.detect_packages.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario9EnvAlreadySeen:
    """
    Both base and user env already registered -> no new detections.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_already_seen_dedup(self, _mock_platform):
        resolved = Path("/usr/bin/python3.11")
        base_sp = Path("/usr/lib/python3.11/site-packages")
        user_sp = Path.home() / ".local/lib/python3.11/site-packages"

        existing_dirs = {base_sp, user_sp}
        fs = _make_fs(existing_dirs)

        registry = ScanRefRegistry()
        runtime_ref = RuntimeRef(canonical_path=str(resolved))

        # Pre-register BOTH environments (as if a prior runtime already handled them)
        base_ref = EnvironmentRef(canonical_path="/usr/lib/python3.11")
        registry.register_environment("env:/usr/lib/python3.11", base_ref)
        user_ref = EnvironmentRef(canonical_path=str(user_sp))
        registry.register_environment(f"env:{user_sp}", user_ref)

        detector = _make_detector()
        exec_ctx_rel = _make_exec_ctx_rel()

        detections = list(
            detector.detect_for_runtime(
                candidate_path=Path("/usr/bin/python3"),
                runtime_ref=runtime_ref,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11",
            )
        )

        assert detections == []
        detector.dependency_detector.detect_packages.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.unix_only
@pytest.mark.unit
class TestScenario10RuntimeDetectorCascade:
    """
    RuntimeDetector cascades to BaseUserEnvDetector from detect() only.
    """

    def test_detect_cascades(self):
        """
        RuntimeDetector.detect() cascades to base_user_env_detector.
        """
        from safety.system_scan.scanner.detectors.runtimes.main import (
            PythonRuntimeDetector,
        )
        from safety.system_scan.scanner.models import Candidate
        from safety.system_scan.scanner.context import DetectContext, Config
        from safety.system_scan.scanner.callbacks import Callbacks

        base_user = Mock(spec=BaseUserEnvDetector)
        base_user.detect_for_runtime.return_value = iter([])

        runtime_detector = PythonRuntimeDetector(base_user_env_detector=base_user)

        fs = Mock(spec=FsRuntime)
        fs.is_file.return_value = True
        fs.is_executable.return_value = True
        resolved = Path("/usr/bin/python3.11")
        fs.realpath.return_value = resolved
        # pyvenv.cfg check -> False (not inside a venv)
        fs.is_file.side_effect = lambda p: "pyvenv.cfg" not in str(p)

        registry = ScanRefRegistry()
        exec_ctx_rel = _make_exec_ctx_rel()

        ctx = DetectContext(
            exec_ctx_rel=exec_ctx_rel,
            registry=registry,
            callbacks=Mock(spec=Callbacks),
            config=Config(),
            fs=fs,
        )

        candidate = Candidate(
            path=Path("/usr/bin/python3.11"),
            source="PATH",
            hint="python3.11",
        )

        with patch(
            "safety.system_scan.scanner.detectors.runtimes.main.collect_python_runtime_info"
        ) as mock_collect:
            mock_info = MagicMock()
            mock_info.links = None
            mock_collect.return_value = mock_info

            list(runtime_detector.detect(candidate, ctx))

        # Cascade was called with version from runtime_info
        base_user.detect_for_runtime.assert_called_once()
        call_kwargs = base_user.detect_for_runtime.call_args
        assert call_kwargs.kwargs["candidate_path"] == candidate.path
        assert call_kwargs.kwargs["runtime_version"] == mock_info.version

    def test_detect_from_ref_does_not_cascade(self):
        """
        RuntimeDetector.detect_from_ref() does NOT cascade.
        """
        from safety.system_scan.scanner.detectors.runtimes.main import (
            PythonRuntimeDetector,
        )

        base_user = Mock(spec=BaseUserEnvDetector)
        base_user.detect_for_runtime.return_value = iter([])

        runtime_detector = PythonRuntimeDetector(base_user_env_detector=base_user)

        fs = Mock(spec=FsRuntime)
        registry = ScanRefRegistry()
        exec_ctx_rel = _make_exec_ctx_rel()

        runtime_ref = RuntimeRef(canonical_path="/usr/bin/python3.11")

        with patch(
            "safety.system_scan.scanner.detectors.runtimes.main.collect_python_runtime_info"
        ) as mock_collect:
            mock_info = MagicMock()
            mock_info.links = None
            mock_collect.return_value = mock_info

            list(
                runtime_detector.detect_from_ref(
                    runtime_ref, fs, exec_ctx_rel, registry, source="VENV"
                )
            )

        # Cascade was NOT called
        base_user.detect_for_runtime.assert_not_called()


@pytest.mark.windows_only
@pytest.mark.unit
class TestScenario11WindowsMultiRuntime:
    """
    Windows multi-runtime: official installer + pyenv-win. User env deduped.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    @patch.dict("os.environ", {"APPDATA": "/C/Users/alice/AppData/Roaming"})
    def test_windows_multi_runtime_dedup(self, _mock_platform):
        resolved_a = Path("/C/Python311/python.exe")
        resolved_b = Path("/C/Users/alice/.pyenv/pyenv-win/versions/3.11.6/python.exe")

        base_sp_a = Path("/C/Python311/Lib/site-packages")
        base_sp_b = Path(
            "/C/Users/alice/.pyenv/pyenv-win/versions/3.11.6/Lib/site-packages"
        )
        user_sp = Path("/C/Users/alice/AppData/Roaming/Python/Python311/site-packages")

        # shim's Lib/site-packages deliberately omitted (doesn't exist on disk)
        existing_dirs = {base_sp_a, base_sp_b, user_sp}

        fs = _make_fs(existing_dirs)

        registry = ScanRefRegistry()
        runtime_ref_a = RuntimeRef(canonical_path=str(resolved_a))
        runtime_ref_b = RuntimeRef(canonical_path=str(resolved_b))

        packages_by_dir = {
            base_sp_a: [
                _make_mock_detection("pkg:pip"),
                _make_mock_detection("pkg:setuptools"),
            ],
            base_sp_b: [_make_mock_detection("pkg:numpy")],
            user_sp: [_make_mock_detection("pkg:black")],
        }

        def detect_packages_side_effect(site_packages, env_path, fs_arg):
            assert site_packages in packages_by_dir, f"Unexpected path: {site_packages}"
            return iter(packages_by_dir[site_packages])

        detector = _make_detector(dep_packages_side_effect=detect_packages_side_effect)
        exec_ctx_rel = _make_exec_ctx_rel()

        # --- Runtime A (official installer) ---
        detections_a = list(
            detector.detect_for_runtime(
                candidate_path=Path("/C/Python311/python.exe"),
                runtime_ref=runtime_ref_a,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11",
            )
        )

        # --- Runtime B (pyenv-win) ---
        detections_b = list(
            detector.detect_for_runtime(
                candidate_path=Path("/C/Users/alice/.pyenv/pyenv-win/shims/python.exe"),
                runtime_ref=runtime_ref_b,
                fs=fs,
                exec_context_ref=exec_ctx_rel,
                scan_registry=registry,
                runtime_version="3.11.6",
            )
        )

        # Runtime A: 2 base deps + 1 base env + 1 user dep + 1 user env = 5
        env_a = [d for d in detections_a if d.kind == DetectionKind.ENVIRONMENT]
        dep_a = [d for d in detections_a if d.kind == DetectionKind.DEPENDENCY]
        assert len(env_a) == 2  # base + user
        assert len(dep_a) == 3  # 2 base + 1 user
        assert len(detections_a) == 5

        # Runtime B: 1 base dep + 1 base env + 0 user = 2 (user deduped!)
        env_b = [d for d in detections_b if d.kind == DetectionKind.ENVIRONMENT]
        dep_b = [d for d in detections_b if d.kind == DetectionKind.DEPENDENCY]
        assert len(env_b) == 1  # only base
        assert len(dep_b) == 1  # only base dep
        assert len(detections_b) == 2

        # Verify user env only in A, linked to FIRST runtime (A)
        all_user = [
            d
            for d in detections_a + detections_b
            if d.kind == DetectionKind.ENVIRONMENT and d.subtype == "python:user"
        ]
        assert len(all_user) == 1
        assert all_user[0].meta.links.runtime is not None
        assert all_user[0].meta.links.runtime.ref.canonical_path == str(resolved_a)

        # Total: 7
        assert len(detections_a) + len(detections_b) == 7

        # Verify shim prefix produced no base env (Lib/site-packages doesn't exist there)
        base_envs = [
            d
            for d in detections_a + detections_b
            if d.kind == DetectionKind.ENVIRONMENT and d.subtype == "python:base"
        ]
        assert len(base_envs) == 2
        stable_ids = {d.stable_id for d in base_envs}
        # No shim-derived base env
        assert not any("shims" in sid for sid in stable_ids)
