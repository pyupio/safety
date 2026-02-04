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
    Test Python dependency detection functionality.
    """

    @pytest.fixture
    def detector(self) -> PythonDependencyDetector:
        """
        Fresh detector instance.
        """
        return PythonDependencyDetector()

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def site_packages_path(self) -> Path:
        """
        Mock site-packages path.
        """
        return Path("/test/env/lib/python3.9/site-packages")

    @pytest.fixture
    def env_path(self) -> Path:
        """
        Mock environment path.
        """
        return Path("/test/env")

    def test_detect_packages_nonexistent_directory(
        self,
        detector: PythonDependencyDetector,
        mock_fs: Mock,
        site_packages_path: Path,
        env_path: Path,
    ) -> None:
        """
        Test detection handles non-existent site-packages directory.
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
        Test detection handles filesystem errors gracefully.
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
        Test detection of packages with dist-info directories.
        """
        mock_fs.is_dir.return_value = True

        # Mock directory entry
        mock_entry = Mock()
        mock_entry.name = "requests-2.28.0.dist-info"
        mock_entry.path = str(site_packages_path / "requests-2.28.0.dist-info")
        mock_entry.is_dir.return_value = True

        mock_scandir.return_value.__enter__.return_value = [mock_entry]
        mock_scandir.return_value.__exit__.return_value = None

        # Mock dependency info
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
        Test detection of packages with egg-info directories.
        """
        mock_fs.is_dir.return_value = True

        # Mock directory entry
        mock_entry = Mock()
        mock_entry.name = "old_package-1.0.egg-info"
        mock_entry.path = str(site_packages_path / "old_package-1.0.egg-info")
        mock_entry.is_dir.return_value = True

        mock_scandir.return_value.__enter__.return_value = [mock_entry]
        mock_scandir.return_value.__exit__.return_value = None

        # Mock dependency info
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

    def test_process_dist_info_with_valid_dirname(
        self, detector: PythonDependencyDetector, mock_fs: Mock, env_path: Path
    ) -> None:
        """
        Test processing dist-info with valid directory name.
        """
        dist_info_path = Path("/test/site-packages/requests-2.28.0.dist-info")
        site_packages_path = Path("/test/site-packages")

        # Mock collect_python_dependency_info
        mock_dep_info = Mock()

        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ):
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

    def test_process_dist_info_fallback_to_metadata(
        self, detector: PythonDependencyDetector, mock_fs: Mock, env_path: Path
    ) -> None:
        """
        Test fallback to METADATA file when dirname parsing fails.
        """
        dist_info_path = Path("/test/site-packages/invalid.dist-info")
        site_packages_path = Path("/test/site-packages")

        # Mock METADATA content
        metadata_content = "Name: requests\nVersion: 2.28.0\n"
        mock_fs.read_text.return_value = metadata_content

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ):
            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

        assert len(detections) == 1
        mock_fs.read_text.assert_called_once_with(
            dist_info_path / "METADATA", max_bytes=64_000
        )

    def test_process_dist_info_no_name_no_detection(
        self, detector: PythonDependencyDetector, mock_fs: Mock, env_path: Path
    ) -> None:
        """
        Test that no detection is created when package name cannot be determined.
        """
        dist_info_path = Path("/test/site-packages/invalid.dist-info")
        site_packages_path = Path("/test/site-packages")

        # Mock directory parsing to fail and METADATA reading to also fail to provide name
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_dist_info_dirname",
            return_value=(None, None),
        ):
            # Mock METADATA content that doesn't contain Name field
            mock_fs.read_text.return_value = "Summary: Some package\n"

            detections = list(
                detector._process_dist_info(
                    dist_info_path, env_path, site_packages_path, mock_fs
                )
            )

            assert detections == []

    def test_process_egg_info_with_valid_dirname(
        self, detector: PythonDependencyDetector, mock_fs: Mock, env_path: Path
    ) -> None:
        """
        Test processing egg-info with valid directory name.
        """
        egg_info_path = Path("/test/site-packages/requests-2.28.0.egg-info")
        site_packages_path = Path("/test/site-packages")

        mock_dep_info = Mock()
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
            return_value=mock_dep_info,
        ):
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

    def test_process_egg_info_fallback_to_pkg_info(
        self, detector: PythonDependencyDetector, mock_fs: Mock, env_path: Path
    ) -> None:
        """
        Test fallback to PKG-INFO file when dirname parsing fails completely.
        """
        # Use a path that doesn't end with .egg-info to make dirname parsing return (None, None)
        egg_info_path = Path("/test/site-packages/weird_dir.egg-info")
        site_packages_path = Path("/test/site-packages")

        # Mock the directory name parsing to fail
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_egg_info_dirname",
            return_value=(None, None),
        ):
            # Mock PKG-INFO content
            pkg_info_content = "Name: requests\nVersion: 2.28.0\n"
            mock_fs.read_text.return_value = pkg_info_content

            mock_dep_info = Mock()
            with patch(
                "safety.system_scan.scanner.detectors.dependencies.main.collect_python_dependency_info",
                return_value=mock_dep_info,
            ):
                detections = list(
                    detector._process_egg_info(
                        egg_info_path, env_path, site_packages_path, mock_fs
                    )
                )

            assert len(detections) == 1
            mock_fs.read_text.assert_called_once_with(
                egg_info_path / "PKG-INFO", max_bytes=32_000
            )

    def test_process_egg_info_no_name_no_detection(
        self, detector: PythonDependencyDetector, mock_fs: Mock, env_path: Path
    ) -> None:
        """
        Test that no detection is created when package name cannot be determined from egg-info.
        """
        egg_info_path = Path("/test/site-packages/invalid.egg-info")
        site_packages_path = Path("/test/site-packages")

        # Mock directory parsing to fail and PKG-INFO reading to also fail to provide name
        with patch(
            "safety.system_scan.scanner.detectors.dependencies.main.parse_egg_info_dirname",
            return_value=(None, None),
        ):
            # Mock PKG-INFO content that doesn't contain Name field
            mock_fs.read_text.return_value = "Summary: Some package\n"

            detections = list(
                detector._process_egg_info(
                    egg_info_path, env_path, site_packages_path, mock_fs
                )
            )

            assert detections == []


@pytest.mark.unit
class TestCollectorFunctions:
    """
    Test utility functions for dependency collection.
    """

    @pytest.mark.parametrize(
        "dirname,expected",
        [
            ("requests-2.28.0.dist-info", ("requests", "2.28.0")),
            ("Django-4.1.0.dist-info", ("Django", "4.1.0")),
            ("setuptools-65.6.3.dist-info", ("setuptools", "65.6.3")),
            ("invalid-name.dist-info", ("invalid-name", None)),
            ("no-version.dist-info", ("no-version", None)),
        ],
    )
    def test_parse_dist_info_dirname(
        self, dirname: str, expected: tuple[str | None, str | None]
    ) -> None:
        """
        Test parsing package name and version from dist-info dirname.
        """
        from safety.system_scan.scanner.detectors.dependencies.collectors import (
            parse_dist_info_dirname,
        )

        result = parse_dist_info_dirname(dirname, ".dist-info")
        assert result == expected

    @pytest.mark.parametrize(
        "dirname,expected",
        [
            ("requests-2.28.0.egg-info", ("requests", "2.28.0")),
            ("Django-4.1.0.egg-info", ("Django", "4.1.0")),
            ("invalid-name.egg-info", ("invalid-name", None)),
        ],
    )
    def test_parse_egg_info_dirname(
        self, dirname: str, expected: tuple[str | None, str | None]
    ) -> None:
        """
        Test parsing package name and version from egg-info dirname.
        """
        from safety.system_scan.scanner.detectors.dependencies.collectors import (
            parse_egg_info_dirname,
        )

        result = parse_egg_info_dirname(dirname, ".egg-info")
        assert result == expected

    def test_extract_metadata_field(self) -> None:
        """
        Test extracting fields from metadata content.
        """
        from safety.system_scan.scanner.detectors.dependencies.collectors import (
            extract_metadata_field,
        )

        metadata = "Name: requests\nVersion: 2.28.0\nSummary: HTTP library\nAuthor: Kenneth Reitz\n"

        assert extract_metadata_field(metadata, "Name") == "requests"
        assert extract_metadata_field(metadata, "Version") == "2.28.0"
        assert extract_metadata_field(metadata, "Summary") == "HTTP library"
        assert extract_metadata_field(metadata, "Author") == "Kenneth Reitz"
        assert extract_metadata_field(metadata, "NonExistent") is None

    def test_extract_metadata_field_multiline_values(self) -> None:
        """
        Test extracting metadata field that handles multiline values correctly.
        """
        from safety.system_scan.scanner.detectors.dependencies.collectors import (
            extract_metadata_field,
        )

        metadata = """Name: requests
Version: 2.28.0
Description: A simple HTTP library
    that supports multiple features
    including authentication
Author: Kenneth Reitz
"""

        assert extract_metadata_field(metadata, "Name") == "requests"
        # Should only get first line of multiline description
        description = extract_metadata_field(metadata, "Description")
        assert description == "A simple HTTP library"

    def test_collect_python_dependency_info(self) -> None:
        """
        Test collecting comprehensive dependency information.
        """
        from safety.system_scan.scanner.detectors.dependencies.collectors import (
            collect_python_dependency_info,
        )

        package_path = Path("/test/requests-2.28.0.dist-info")
        name = "requests"
        version = "2.28.0"

        mock_fs = Mock()

        info = collect_python_dependency_info(package_path, name, version, mock_fs)

        assert info.name == name
        assert info.version == version
        assert info.canonical_path == str(package_path)
