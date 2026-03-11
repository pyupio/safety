from __future__ import annotations

import pytest
from unittest.mock import Mock, patch
from pathlib import Path

from safety.system_scan.scanner.detectors.dependencies.main import (
    PythonDependencyDetector,
)
from safety.system_scan.scanner.models import DetectionKind
from safety.system_scan.scanner.filesystem import FsRuntime


@pytest.mark.unit
class TestPythonDependencyDetector:
    """
    Orchestration tests for detect_packages: scandir dispatch and error handling.
    """

    @pytest.fixture
    def detector(self) -> PythonDependencyDetector:
        return PythonDependencyDetector()

    @pytest.fixture
    def mock_fs(self) -> Mock:
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def site_packages_path(self) -> Path:
        return Path("/test/env/lib/python3.9/site-packages")

    @pytest.fixture
    def env_path(self) -> Path:
        return Path("/test/env")

    def test_detect_packages_nonexistent_directory(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        site_packages_path: Path,
        env_path: Path,
    ) -> None:
        """
        Non-existent site-packages directory yields nothing.
        """
        mock_fs.is_dir.return_value = False

        detections = list(
            detector.detect_packages(site_packages_path, env_path, mock_fs)
        )

        assert detections == []
        mock_fs.is_dir.assert_called_once_with(site_packages_path)

    @pytest.mark.parametrize("exception_type", [OSError, PermissionError])
    def test_detect_packages_handles_filesystem_errors(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        site_packages_path: Path,
        env_path: Path,
        exception_type: type,
    ) -> None:
        """
        Filesystem errors during scandir are caught gracefully.
        """
        mock_fs.is_dir.return_value = True

        with patch("os.scandir", side_effect=exception_type("Access denied")):
            detections = list(
                detector.detect_packages(site_packages_path, env_path, mock_fs)
            )

        assert detections == []

    @patch(
        "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info"
    )
    @patch("os.scandir")
    def test_detect_packages_with_dist_info(
        self,
        mock_scandir: Mock,
        mock_collect_info: Mock,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        site_packages_path: Path,
        env_path: Path,
    ) -> None:
        """
        A .dist-info entry dispatches to _process_dist_info and yields a detection.
        """
        mock_fs.is_dir.return_value = True

        mock_entry = Mock()
        mock_entry.name = "requests-2.28.0.dist-info"
        mock_entry.path = str(site_packages_path / "requests-2.28.0.dist-info")
        mock_entry.is_dir.return_value = True

        mock_scandir.return_value.__enter__.return_value = [mock_entry]
        mock_scandir.return_value.__exit__.return_value = None

        mock_dep_info = Mock()
        mock_collect_info.return_value = mock_dep_info

        detections = list(
            detector.detect_packages(site_packages_path, env_path, mock_fs)
        )

        assert len(detections) == 1
        detection = detections[0]
        assert detection.kind == DetectionKind.DEPENDENCY
        assert detection.subtype == "python"
        assert detection.meta == mock_dep_info
        assert "requests-2.28.0.dist-info" in detection.primary_path
        assert detection.scope == "environment"
        assert detection.found_via == ["ENV_SITE_PACKAGES"]

    @patch(
        "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info"
    )
    @patch("os.scandir")
    def test_detect_packages_with_egg_info(
        self,
        mock_scandir: Mock,
        mock_collect_info: Mock,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        site_packages_path: Path,
        env_path: Path,
    ) -> None:
        """
        An .egg-info entry dispatches to _process_egg_info and yields a detection.
        """
        mock_fs.is_dir.return_value = True

        mock_entry = Mock()
        mock_entry.name = "old_package-1.0.egg-info"
        mock_entry.path = str(site_packages_path / "old_package-1.0.egg-info")
        mock_entry.is_dir.return_value = True

        mock_scandir.return_value.__enter__.return_value = [mock_entry]
        mock_scandir.return_value.__exit__.return_value = None

        mock_dep_info = Mock()
        mock_collect_info.return_value = mock_dep_info

        detections = list(
            detector.detect_packages(site_packages_path, env_path, mock_fs)
        )

        assert len(detections) == 1
        detection = detections[0]
        assert detection.kind == DetectionKind.DEPENDENCY
        assert detection.subtype == "python"
        assert detection.meta == mock_dep_info


@pytest.mark.unit
class TestProcessDistInfo:
    """
    Tests for _process_dist_info: does it take the right branch, read the
    right file, and pass the correct args to collect_python_dependency_info?
    """

    @pytest.fixture
    def detector(self) -> PythonDependencyDetector:
        return PythonDependencyDetector()

    @pytest.fixture
    def mock_fs(self) -> Mock:
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def env_path(self) -> Path:
        return Path("/test/env")

    @pytest.fixture
    def site_packages_path(self) -> Path:
        return Path("/test/site-packages")

    # ── A: Both name and version come from dirname ───────────────────────

    def test_both_from_dirname(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname provides both name and version → METADATA is not read.
        """
        dist_info_path = Path("/test/site-packages/requests-2.28.0.dist-info")

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ) as mock_collect:
            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        detection = detections[0]
        assert detection.kind == DetectionKind.DEPENDENCY
        assert detection.subtype == "python"
        assert detection.meta == mock_dep_info
        assert "requests-2.28.0.dist-info" in detection.primary_path
        # METADATA should NOT be read when dirname gives both fields
        mock_fs.read_text.assert_not_called()
        mock_collect.assert_called_once_with(
            dist_info_path, "requests", "2.28.0", mock_fs
        )

    # ── B: Both name and version come from METADATA ──────────────────────

    def test_both_from_metadata(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname parsing fails completely → falls back to METADATA for both fields.
        """
        dist_info_path = Path("/test/site-packages/invalid.dist-info")

        metadata_content = "Name: requests\nVersion: 2.28.0\n"
        mock_fs.read_text.return_value = metadata_content

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ) as mock_collect:
            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        mock_fs.read_text.assert_called_once_with(
            dist_info_path / "METADATA", max_bytes=64_000
        )
        mock_collect.assert_called_once_with(
            dist_info_path, "requests", "2.28.0", mock_fs
        )

    # ── C: Name from dirname, version from METADATA ──────────────────────

    def test_name_from_dirname_version_from_metadata(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname gives name but no version → METADATA supplies version.
        """
        dist_info_path = Path("/test/site-packages/mypackage.dist-info")

        mock_fs.read_text.return_value = "Name: mypackage\nVersion: 3.0.0\n"

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ) as mock_collect:
            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        mock_fs.read_text.assert_called_once_with(
            dist_info_path / "METADATA", max_bytes=64_000
        )
        mock_collect.assert_called_once_with(
            dist_info_path, "mypackage", "3.0.0", mock_fs
        )

    # ── D: Name corrected by METADATA ────────────────────────────────────

    def test_name_corrected_by_metadata(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname gives a garbled name with no version → METADATA corrects the name.

        parse_dist_info_dirname("garbled-name.dist-info", ...) returns
        ("garbled-name", None) — name present but no version triggers METADATA read,
        and METADATA's Name field overrides the dirname-derived name.
        """
        dist_info_path = Path("/test/site-packages/garbled-name.dist-info")

        mock_fs.read_text.return_value = "Name: real-package\nVersion: 1.0.0\n"

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ) as mock_collect:
            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        # METADATA Name should override the dirname-derived name
        mock_collect.assert_called_once_with(
            dist_info_path, "real-package", "1.0.0", mock_fs
        )

    # ── E: No name anywhere ──────────────────────────────────────────────

    def test_no_name_anywhere(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Neither dirname nor METADATA provide a name → no detection yielded.
        """
        dist_info_path = Path("/test/site-packages/invalid.dist-info")

        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_dist_info_dirname",
            return_value=(None, None),
        ):
            mock_fs.read_text.return_value = "Summary: Some package\n"

            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert detections == []

    # ── F: METADATA file empty ───────────────────────────────────────────

    def test_metadata_file_empty(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname parse fails and METADATA is empty → no detection yielded.
        """
        dist_info_path = Path("/test/site-packages/invalid.dist-info")

        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_dist_info_dirname",
            return_value=(None, None),
        ):
            mock_fs.read_text.return_value = ""

            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert detections == []
        mock_fs.read_text.assert_called_once_with(
            dist_info_path / "METADATA", max_bytes=64_000
        )


@pytest.mark.unit
class TestProcessEggInfo:
    """
    Tests for _process_egg_info: does it take the right branch, read the
    right file, and pass the correct args to collect_python_dependency_info?
    """

    @pytest.fixture
    def detector(self) -> PythonDependencyDetector:
        return PythonDependencyDetector()

    @pytest.fixture
    def mock_fs(self) -> Mock:
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def env_path(self) -> Path:
        return Path("/test/env")

    @pytest.fixture
    def site_packages_path(self) -> Path:
        return Path("/test/site-packages")

    # ── A: Both name and version come from dirname ───────────────────────

    def test_both_from_dirname(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname provides both name and version → PKG-INFO is not read.
        """
        egg_info_path = Path("/test/site-packages/requests-2.28.0.egg-info")

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ) as mock_collect:
            detections = list(
                detector._process_egg_info(
                    egg_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        detection = detections[0]
        assert detection.kind == DetectionKind.DEPENDENCY
        assert detection.subtype == "python"
        assert detection.meta == mock_dep_info
        # PKG-INFO should NOT be read when dirname gives both fields
        mock_fs.read_text.assert_not_called()
        mock_collect.assert_called_once_with(
            egg_info_path, "requests", "2.28.0", mock_fs
        )

    # ── B: Both name and version come from PKG-INFO ──────────────────────

    def test_both_from_pkg_info(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname parsing fails completely → falls back to PKG-INFO for both fields.
        """
        egg_info_path = Path("/test/site-packages/weird_dir.egg-info")

        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_egg_info_dirname",
            return_value=(None, None),
        ):
            pkg_info_content = "Name: requests\nVersion: 2.28.0\n"
            mock_fs.read_text.return_value = pkg_info_content

            mock_dep_info = Mock()
            with patch(
                "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
                return_value=mock_dep_info,
            ) as mock_collect:
                detections = list(
                    detector._process_egg_info(
                        egg_info_path, env_path, site_packages_path, mock_fs
                    )
                )

        assert len(detections) == 1
        mock_fs.read_text.assert_called_once_with(
            egg_info_path / "PKG-INFO", max_bytes=32_000
        )
        mock_collect.assert_called_once_with(
            egg_info_path, "requests", "2.28.0", mock_fs
        )

    # ── C: Name from dirname, version from PKG-INFO ──────────────────────

    def test_name_from_dirname_version_from_pkg_info(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname gives name but no version → PKG-INFO supplies version.
        """
        egg_info_path = Path("/test/site-packages/mypackage.egg-info")

        mock_fs.read_text.return_value = "Name: mypackage\nVersion: 2.0.0\n"

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ) as mock_collect:
            detections = list(
                detector._process_egg_info(
                    egg_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        mock_fs.read_text.assert_called_once_with(
            egg_info_path / "PKG-INFO", max_bytes=32_000
        )
        mock_collect.assert_called_once_with(
            egg_info_path, "mypackage", "2.0.0", mock_fs
        )

    # ── D: Name corrected by PKG-INFO ────────────────────────────────────

    def test_name_corrected_by_pkg_info(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname with platform tag gives wrong name → PKG-INFO corrects it.

        "package-1.0-linux-x86_64.egg-info" → parse_egg_info_dirname returns
        ("package-1.0-linux-x86_64", None). Since version is None, PKG-INFO
        is read. PKG-INFO's Name overrides the garbled dirname-derived name.
        No parser mock needed — the real parser returns the expected fallback.
        """
        egg_info_path = Path("/test/site-packages/package-1.0-linux-x86_64.egg-info")

        mock_fs.read_text.return_value = "Name: package\nVersion: 1.0\n"

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ) as mock_collect:
            detections = list(
                detector._process_egg_info(
                    egg_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        # PKG-INFO Name should override the dirname-derived name
        mock_collect.assert_called_once_with(egg_info_path, "package", "1.0", mock_fs)

    # ── E: No name anywhere ──────────────────────────────────────────────

    def test_no_name_anywhere(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Neither dirname nor PKG-INFO provide a name → no detection yielded.
        """
        egg_info_path = Path("/test/site-packages/invalid.egg-info")

        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_egg_info_dirname",
            return_value=(None, None),
        ):
            mock_fs.read_text.return_value = "Summary: Some package\n"

            detections = list(
                detector._process_egg_info(
                    egg_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert detections == []

    # ── F: PKG-INFO file empty ───────────────────────────────────────────

    def test_pkg_info_file_empty(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        env_path: Path,
        site_packages_path: Path,
    ) -> None:
        """
        Dirname parse fails and PKG-INFO is empty → no detection yielded.
        """
        egg_info_path = Path("/test/site-packages/invalid.egg-info")

        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_egg_info_dirname",
            return_value=(None, None),
        ):
            mock_fs.read_text.return_value = ""

            detections = list(
                detector._process_egg_info(
                    egg_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert detections == []
        mock_fs.read_text.assert_called_once_with(
            egg_info_path / "PKG-INFO", max_bytes=32_000
        )
