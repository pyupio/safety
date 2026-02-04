from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch
import pytest
from typing import cast

from safety.system_scan.scanner.detectors.environments.main import (
    PythonEnvironmentDetector,
)
from safety.system_scan.scanner.models import (
    Candidate,
    Detection,
    DetectionKind,
)
from safety.system_scan.scanner.filesystem import FsRuntime
from safety.system_scan.scanner.events.payloads.environment import (
    PythonVenvEnvironment,
    PythonBaseEnvironment,
    PythonUserEnvironment,
)
from safety.system_scan.scanner.events.payloads.links import (
    EnvironmentRef,
    RuntimeRef,
)
from safety.system_scan.scanner.registry import ScanRefRegistry
from safety.system_scan.scanner.context import DetectContext


@pytest.mark.unit
class TestPythonEnvironmentDetector:
    """
    Test PythonEnvironmentDetector implementation.
    """

    @pytest.fixture
    def mock_dependency_detector(self) -> Mock:
        """
        Mock dependency detector.
        """
        return Mock()

    @pytest.fixture
    def mock_tool_detector(self) -> Mock:
        """
        Mock tool detector.
        """
        return Mock()

    @pytest.fixture
    def mock_runtime_detector(self) -> Mock:
        """
        Mock runtime detector.
        """
        return Mock()

    @pytest.fixture
    def environment_detector(
        self,
        mock_dependency_detector: Mock,
        mock_tool_detector: Mock,
        mock_runtime_detector: Mock,
    ) -> PythonEnvironmentDetector:
        """
        Create PythonEnvironmentDetector instance for testing.
        """
        return PythonEnvironmentDetector(
            mock_dependency_detector, mock_tool_detector, mock_runtime_detector
        )

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def mock_context(self, mock_fs: Mock) -> Mock:
        """
        Mock detect context.
        """
        context = Mock(spec=DetectContext)
        context.fs = mock_fs
        context.exec_ctx_rel = Mock()
        context.registry = Mock(spec=ScanRefRegistry)
        return context

    def test_init(
        self,
        mock_dependency_detector: Mock,
        mock_tool_detector: Mock,
        mock_runtime_detector: Mock,
    ) -> None:
        """
        Test PythonEnvironmentDetector initialization.
        """
        detector = PythonEnvironmentDetector(
            mock_dependency_detector, mock_tool_detector, mock_runtime_detector
        )

        assert detector.dependency_detector == mock_dependency_detector
        assert detector.tool_detector == mock_tool_detector
        assert detector.runtime_detector == mock_runtime_detector

    def test_build_entity_reference_valid_venv(
        self, environment_detector: PythonEnvironmentDetector, mock_fs: Mock
    ) -> None:
        """
        Test building entity reference for valid venv.
        """
        venv_path = Path("/project/.venv")
        cast(Mock, mock_fs.is_file).return_value = True
        cast(Mock, mock_fs.realpath).return_value = venv_path

        result = environment_detector.build_entity_reference(venv_path, mock_fs)

        assert result is not None
        assert isinstance(result, EnvironmentRef)
        assert result.canonical_path == str(venv_path)

    def test_build_entity_reference_invalid_venv(
        self, environment_detector: PythonEnvironmentDetector, mock_fs: Mock
    ) -> None:
        """
        Test building entity reference for invalid venv (no pyvenv.cfg).
        """
        venv_path = Path("/project/.venv")
        cast(Mock, mock_fs.is_file).return_value = False

        result = environment_detector.build_entity_reference(venv_path, mock_fs)

        assert result is None

    def test_get_stable_id(
        self, environment_detector: PythonEnvironmentDetector
    ) -> None:
        """
        Test generating stable ID for environment.
        """
        env_ref = EnvironmentRef(canonical_path="/path/to/env")

        result = environment_detector.get_stable_id(env_ref)

        assert result == "env:/path/to/env"

    def test_detect_with_venv_root_hint(
        self, environment_detector: PythonEnvironmentDetector, mock_context: Mock
    ) -> None:
        """
        Test detect with venv_root hint.
        """
        candidate = Candidate(
            path=Path("/project/.venv"),
            source="TEST",
            hint="python:venv_root",
            depth=1,
        )

        with patch.object(
            environment_detector, "_detect_from_venv_root"
        ) as mock_detect_venv:
            mock_detect_venv.return_value = iter([])

            list(environment_detector.detect(candidate, mock_context))

            mock_detect_venv.assert_called_once_with(
                candidate,
                mock_context.fs,
                mock_context.exec_ctx_rel,
                mock_context.registry,
            )

    def test_detect_with_project_root_hint(
        self, environment_detector: PythonEnvironmentDetector, mock_context: Mock
    ) -> None:
        """
        Test detect with project_root hint.
        """
        candidate = Candidate(
            path=Path("/project"),
            source="TEST",
            hint="python:project_root",
            depth=1,
        )

        with patch.object(
            environment_detector, "_detect_project_envs"
        ) as mock_detect_project:
            mock_detect_project.return_value = iter([])

            list(environment_detector.detect(candidate, mock_context))

            mock_detect_project.assert_called_once_with(
                candidate,
                mock_context.fs,
                mock_context.exec_ctx_rel,
                mock_context.registry,
            )

    def test_detect_with_no_relevant_hint(
        self, environment_detector: PythonEnvironmentDetector, mock_context: Mock
    ) -> None:
        """
        Test detect with irrelevant hint.
        """
        candidate = Candidate(
            path=Path("/project"),
            source="TEST",
            hint="other:irrelevant",
            depth=1,
        )

        result = list(environment_detector.detect(candidate, mock_context))

        assert result == []

    @patch(
        "safety.system_scan.scanner.detectors.environments.main.collect_venv_environment_info"
    )
    def test_detect_from_venv_root_success(
        self,
        mock_collect_info: Mock,
        environment_detector: PythonEnvironmentDetector,
        mock_context: Mock,
    ) -> None:
        """
        Test successful venv detection from venv root.
        """
        candidate = Candidate(
            path=Path("/project/.venv"),
            source="TEST",
            hint="python:venv_root",
            depth=1,
        )

        # Mock filesystem
        cast(Mock, mock_context.fs.is_file).return_value = True
        cast(Mock, mock_context.fs.realpath).return_value = candidate.path
        cast(Mock, mock_context.registry.is_seen).return_value = False

        # Mock venv info collection
        mock_venv_info = Mock(spec=PythonVenvEnvironment)
        mock_venv_info.canonical_path = str(candidate.path)
        mock_venv_info.python_venv_pyvenv_cfg = {"home": "/usr/bin"}
        mock_venv_info.subtype.value = "venv"
        mock_collect_info.return_value = mock_venv_info

        # Mock path discovery
        with patch.object(environment_detector, "_get_paths") as mock_get_paths:
            bin_path = Path("/project/.venv/bin")
            site_packages_path = Path("/project/.venv/lib/python3.11/site-packages")
            mock_get_paths.return_value = (bin_path, site_packages_path)

            # Mock runtime reference
            with patch.object(
                environment_detector, "_get_runtime_ref"
            ) as mock_get_runtime_ref:
                runtime_ref = RuntimeRef(canonical_path="/usr/bin/python3")
                mock_get_runtime_ref.return_value = runtime_ref

                # Mock detector methods
                cast(
                    Mock, environment_detector.runtime_detector.detect_from_ref
                ).return_value = iter([])
                cast(
                    Mock, environment_detector.dependency_detector.detect_packages
                ).return_value = iter([])
                cast(
                    Mock, environment_detector.tool_detector.scan_directory
                ).return_value = iter([])

                result = list(
                    environment_detector._detect_from_venv_root(
                        candidate,
                        mock_context.fs,
                        mock_context.exec_ctx_rel,
                        mock_context.registry,
                    )
                )

                # Should have one detection for the environment
                assert len(result) >= 1
                env_detection = result[-1]  # Last item should be the environment
                assert env_detection.kind == DetectionKind.ENVIRONMENT

    def test_detect_from_venv_root_invalid_venv(
        self,
        environment_detector: PythonEnvironmentDetector,
        mock_context: Mock,
    ) -> None:
        """
        Test venv detection with invalid venv (no pyvenv.cfg).
        """
        candidate = Candidate(
            path=Path("/project/.venv"),
            source="TEST",
            hint="python:venv_root",
            depth=1,
        )

        cast(Mock, mock_context.fs.is_file).return_value = False

        result = list(
            environment_detector._detect_from_venv_root(
                candidate,
                mock_context.fs,
                mock_context.exec_ctx_rel,
                mock_context.registry,
            )
        )

        assert result == []

    def test_detect_from_venv_root_already_seen(
        self,
        environment_detector: PythonEnvironmentDetector,
        mock_context: Mock,
    ) -> None:
        """
        Test venv detection when environment already seen.
        """
        candidate = Candidate(
            path=Path("/project/.venv"),
            source="TEST",
            hint="python:venv_root",
            depth=1,
        )

        cast(Mock, mock_context.fs.is_file).return_value = True
        cast(Mock, mock_context.fs.realpath).return_value = candidate.path
        cast(Mock, mock_context.registry.is_seen).return_value = True

        result = list(
            environment_detector._detect_from_venv_root(
                candidate,
                mock_context.fs,
                mock_context.exec_ctx_rel,
                mock_context.registry,
            )
        )

        assert result == []

    @patch(
        "safety.system_scan.scanner.detectors.environments.main.collect_venv_environment_info"
    )
    def test_detect_from_venv_root_collection_failed(
        self,
        mock_collect_info: Mock,
        environment_detector: PythonEnvironmentDetector,
        mock_context: Mock,
    ) -> None:
        """
        Test venv detection when info collection fails.
        """
        candidate = Candidate(
            path=Path("/project/.venv"),
            source="TEST",
            hint="python:venv_root",
            depth=1,
        )

        cast(Mock, mock_context.fs.is_file).return_value = True
        cast(Mock, mock_context.fs.realpath).return_value = candidate.path
        cast(Mock, mock_context.registry.is_seen).return_value = False
        mock_collect_info.return_value = None

        result = list(
            environment_detector._detect_from_venv_root(
                candidate,
                mock_context.fs,
                mock_context.exec_ctx_rel,
                mock_context.registry,
            )
        )

        assert result == []

    @patch("platform.system")
    def test_get_paths_windows(
        self,
        mock_platform: Mock,
        environment_detector: PythonEnvironmentDetector,
        mock_fs: Mock,
    ) -> None:
        """
        Test path discovery on Windows.
        """
        mock_platform.return_value = "Windows"
        venv_root = Path("C:/project/.venv")

        bin_path, site_packages_path = environment_detector._get_paths(
            venv_root, mock_fs
        )

        assert bin_path == venv_root / "Scripts"
        assert site_packages_path == venv_root / "Lib" / "site-packages"

    @patch("platform.system")
    @patch("os.scandir")
    def test_get_paths_unix_success(
        self,
        mock_scandir: Mock,
        mock_platform: Mock,
        environment_detector: PythonEnvironmentDetector,
        mock_fs: Mock,
    ) -> None:
        """
        Test path discovery on Unix with successful python directory find.
        """
        mock_platform.return_value = "Linux"
        venv_root = Path("/project/.venv")
        lib_dir = venv_root / "lib"

        cast(Mock, mock_fs.is_dir).return_value = True

        # Mock directory entry
        mock_entry = Mock()
        mock_entry.is_dir.return_value = True
        mock_entry.name = "python3.11"
        mock_scandir.return_value.__enter__.return_value = [mock_entry]

        bin_path, site_packages_path = environment_detector._get_paths(
            venv_root, mock_fs
        )

        assert bin_path == venv_root / "bin"
        assert site_packages_path == lib_dir / "python3.11" / "site-packages"

    @patch("platform.system")
    @patch("os.scandir")
    def test_get_paths_unix_scandir_failure(
        self,
        mock_scandir: Mock,
        mock_platform: Mock,
        environment_detector: PythonEnvironmentDetector,
        mock_fs: Mock,
    ) -> None:
        """
        Test path discovery on Unix with scandir failure.
        """
        mock_platform.return_value = "Linux"
        venv_root = Path("/project/.venv")

        cast(Mock, mock_fs.is_dir).return_value = True
        mock_scandir.side_effect = OSError("Cannot scan")

        bin_path, site_packages_path = environment_detector._get_paths(
            venv_root, mock_fs
        )

        assert bin_path == venv_root / "bin"
        assert site_packages_path is None

    def test_get_runtime_ref_from_home(
        self, environment_detector: PythonEnvironmentDetector, mock_fs: Mock
    ) -> None:
        """
        Test getting runtime reference from pyvenv.cfg home.
        """
        venv_info = Mock(spec=PythonVenvEnvironment)
        venv_info.python_venv_pyvenv_cfg = {"home": "/usr/bin"}
        bin_path = Path("/project/.venv/bin")

        runtime_ref = RuntimeRef(canonical_path="/usr/bin/python3")
        cast(
            Mock, environment_detector.runtime_detector.build_entity_reference
        ).return_value = runtime_ref

        result = environment_detector._get_runtime_ref(venv_info, bin_path, mock_fs)

        assert result == runtime_ref
        # Should try home path first
        cast(
            Mock, environment_detector.runtime_detector.build_entity_reference
        ).assert_called_with(Path("/usr/bin"), mock_fs, search_directory=True)

    def test_get_runtime_ref_fallback_to_bin(
        self, environment_detector: PythonEnvironmentDetector, mock_fs: Mock
    ) -> None:
        """
        Test getting runtime reference fallback to bin path.
        """
        venv_info = Mock(spec=PythonVenvEnvironment)
        venv_info.python_venv_pyvenv_cfg = {"home": "/usr/bin"}
        bin_path = Path("/project/.venv/bin")

        # First call (home) returns None, second call (bin) returns runtime_ref
        runtime_ref = RuntimeRef(canonical_path="/project/.venv/bin/python3")
        cast(
            Mock, environment_detector.runtime_detector.build_entity_reference
        ).side_effect = [
            None,
            runtime_ref,
        ]

        result = environment_detector._get_runtime_ref(venv_info, bin_path, mock_fs)

        assert result == runtime_ref

    def test_get_runtime_ref_no_home(
        self, environment_detector: PythonEnvironmentDetector, mock_fs: Mock
    ) -> None:
        """
        Test getting runtime reference when no home in pyvenv.cfg.
        """
        venv_info = Mock(spec=PythonVenvEnvironment)
        venv_info.python_venv_pyvenv_cfg = {}
        bin_path = Path("/project/.venv/bin")

        runtime_ref = RuntimeRef(canonical_path="/project/.venv/bin/python3")
        cast(
            Mock, environment_detector.runtime_detector.build_entity_reference
        ).return_value = runtime_ref

        result = environment_detector._get_runtime_ref(venv_info, bin_path, mock_fs)

        assert result == runtime_ref

    def test_detect_project_envs_success(
        self, environment_detector: PythonEnvironmentDetector, mock_context: Mock
    ) -> None:
        """
        Test detecting project environments successfully.
        """
        candidate = Candidate(
            path=Path("/project"),
            source="TEST",
            hint="python:project_root",
            depth=1,
        )

        # Mock filesystem to find .venv directory
        cast(Mock, mock_context.fs.is_dir).side_effect = lambda p: ".venv" in str(p)
        cast(Mock, mock_context.fs.is_file).side_effect = lambda p: (
            "pyvenv.cfg" in str(p)
        )

        with patch.object(
            environment_detector, "_detect_from_venv_root"
        ) as mock_detect_venv:
            mock_detect_venv.return_value = iter([Mock(spec=Detection)])

            result = list(
                environment_detector._detect_project_envs(
                    candidate,
                    mock_context.fs,
                    mock_context.exec_ctx_rel,
                    mock_context.registry,
                )
            )

            assert len(result) == 1
            mock_detect_venv.assert_called_once()

    def test_detect_project_envs_no_venv_found(
        self, environment_detector: PythonEnvironmentDetector, mock_context: Mock
    ) -> None:
        """
        Test detecting project environments when no venv found.
        """
        candidate = Candidate(
            path=Path("/project"),
            source="TEST",
            hint="python:project_root",
            depth=1,
        )

        cast(Mock, mock_context.fs.is_dir).return_value = False
        cast(Mock, mock_context.fs.is_file).return_value = False

        result = list(
            environment_detector._detect_project_envs(
                candidate,
                mock_context.fs,
                mock_context.exec_ctx_rel,
                mock_context.registry,
            )
        )

        assert result == []

    def test_create_detection_venv_environment(
        self, environment_detector: PythonEnvironmentDetector
    ) -> None:
        """
        Test creating detection for venv environment.
        """
        env_ref = EnvironmentRef(canonical_path="/project/.venv")
        env_info = Mock(spec=PythonVenvEnvironment)
        env_info.canonical_path = "/project/.venv"
        env_info.subtype.value = "venv"
        found_via = ["PROJECT_SCAN"]

        result = environment_detector._create_detection(env_ref, env_info, found_via)

        assert result.kind == DetectionKind.ENVIRONMENT
        assert result.subtype == "venv"
        assert result.stable_id == "env:/project/.venv"
        assert result.primary_path == "/project/.venv"
        assert result.scope == "project"
        assert result.found_via == found_via
        assert result.meta == env_info

    def test_create_detection_base_environment(
        self, environment_detector: PythonEnvironmentDetector
    ) -> None:
        """
        Test creating detection for base environment.
        """
        env_ref = EnvironmentRef(canonical_path="/usr/lib/python3.11/site-packages")
        env_info = Mock(spec=PythonBaseEnvironment)
        env_info.canonical_path = "/usr/lib/python3.11/site-packages"
        env_info.subtype.value = "base"
        found_via = ["SYSTEM_SCAN"]

        result = environment_detector._create_detection(env_ref, env_info, found_via)

        assert result.kind == DetectionKind.ENVIRONMENT
        assert result.subtype == "base"
        assert result.stable_id == "env:/usr/lib/python3.11/site-packages"
        assert result.scope == "system"

    def test_create_detection_user_environment(
        self, environment_detector: PythonEnvironmentDetector
    ) -> None:
        """
        Test creating detection for user environment.
        """
        env_ref = EnvironmentRef(
            canonical_path="/home/user/.local/lib/python3.11/site-packages"
        )
        env_info = Mock(spec=PythonUserEnvironment)
        env_info.canonical_path = "/home/user/.local/lib/python3.11/site-packages"
        env_info.subtype.value = "user"
        found_via = ["USER_SCAN"]

        result = environment_detector._create_detection(env_ref, env_info, found_via)

        assert result.kind == DetectionKind.ENVIRONMENT
        assert result.subtype == "user"
        assert result.scope == "user"

    def test_detect_tools_no_bin_path(
        self, environment_detector: PythonEnvironmentDetector, mock_context: Mock
    ) -> None:
        """
        Test detecting tools when bin path is None.
        """
        result = list(
            environment_detector._detect_tools(
                None,  # No bin path
                mock_context.fs,
                mock_context.registry,
                mock_context.exec_ctx_rel,
                Mock(),  # environment_relation
            )
        )

        assert result == []

    def test_detect_dependencies_no_site_packages(
        self, environment_detector: PythonEnvironmentDetector, mock_context: Mock
    ) -> None:
        """
        Test detecting dependencies when site_packages path is None.
        """
        result = list(
            environment_detector._detect_dependencies(
                None,  # No site_packages path
                Path("/project/.venv"),
                mock_context.fs,
                mock_context.exec_ctx_rel,
                Mock(),  # environment_relation
            )
        )

        assert result == []
