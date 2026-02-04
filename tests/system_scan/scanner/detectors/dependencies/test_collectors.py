from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import Mock

from safety.system_scan.scanner.detectors.dependencies.collectors import (
    parse_dist_info_dirname,
    parse_egg_info_dirname,
    extract_metadata_field,
    enrich_package_meta,
    collect_file_integrity,
    collect_python_dependency_info,
)
from safety.system_scan.scanner.filesystem.runtime import FsRuntime


@pytest.mark.unit
class TestParseDistInfoDirname:
    """
    Test parse_dist_info_dirname function.
    """

    def test_parse_valid_dist_info_with_version(self) -> None:
        """
        Test parsing valid dist-info directory with version.
        """
        name, version = parse_dist_info_dirname(
            "requests-2.31.0.dist-info", ".dist-info"
        )

        assert name == "requests"
        assert version == "2.31.0"

    def test_parse_valid_dist_info_name_only(self) -> None:
        """
        Test parsing dist-info directory with name only.
        """
        name, version = parse_dist_info_dirname("mypackage.dist-info", ".dist-info")

        assert name == "mypackage"
        assert version is None

    def test_parse_dist_info_with_hyphens_in_name(self) -> None:
        """
        Test parsing dist-info with hyphens in package name.
        """
        name, version = parse_dist_info_dirname(
            "package-with-hyphens-1.0.0.dist-info", ".dist-info"
        )

        assert name == "package-with-hyphens"
        assert version == "1.0.0"

    def test_parse_dist_info_invalid_version_format(self) -> None:
        """
        Test parsing dist-info with invalid version format.
        """
        name, version = parse_dist_info_dirname(
            "package-invalidversion.dist-info", ".dist-info"
        )

        assert name == "package-invalidversion"
        assert version is None

    def test_parse_dist_info_wrong_suffix(self) -> None:
        """
        Test parsing with wrong suffix.
        """
        name, version = parse_dist_info_dirname(
            "requests-2.31.0.egg-info", ".dist-info"
        )

        assert name is None
        assert version is None

    def test_parse_dist_info_complex_version(self) -> None:
        """
        Test parsing with complex version numbers.
        """
        name, version = parse_dist_info_dirname(
            "numpy-1.24.0rc1.dist-info", ".dist-info"
        )

        assert name == "numpy"
        assert version == "1.24.0rc1"

    def test_parse_dist_info_empty_string(self) -> None:
        """
        Test parsing empty string.
        """
        name, version = parse_dist_info_dirname("", ".dist-info")

        assert name is None
        assert version is None

    def test_parse_dist_info_edge_case_split_failure(self) -> None:
        """
        Test parsing edge case where split fails unexpectedly.
        """
        # This tests the fallback return for unexpected parse results
        name, version = parse_dist_info_dirname("package-.dist-info", ".dist-info")

        assert name == "package-"
        assert version is None


@pytest.mark.unit
class TestParseEggInfoDirname:
    """
    Test parse_egg_info_dirname function.
    """

    def test_parse_valid_egg_info_with_version(self) -> None:
        """
        Test parsing valid egg-info directory with version.
        """
        name, version = parse_egg_info_dirname(
            "setuptools-65.0.0.egg-info", ".egg-info"
        )

        assert name == "setuptools"
        assert version == "65.0.0"

    def test_parse_egg_info_name_only(self) -> None:
        """
        Test parsing egg-info directory with name only.
        """
        name, version = parse_egg_info_dirname("mypackage.egg-info", ".egg-info")

        assert name == "mypackage"
        assert version is None

    def test_parse_egg_info_with_hyphens_in_name(self) -> None:
        """
        Test parsing egg-info with hyphens in package name.
        """
        name, version = parse_egg_info_dirname("my-package-2.0.0.egg-info", ".egg-info")

        assert name == "my-package"
        assert version == "2.0.0"

    def test_parse_egg_info_invalid_version(self) -> None:
        """
        Test parsing egg-info with invalid version.
        """
        name, version = parse_egg_info_dirname(
            "package-notversion.egg-info", ".egg-info"
        )

        assert name == "package-notversion"
        assert version is None

    def test_parse_egg_info_wrong_suffix(self) -> None:
        """
        Test parsing with wrong suffix.
        """
        name, version = parse_egg_info_dirname("package-1.0.0.dist-info", ".egg-info")

        assert name is None
        assert version is None

    def test_parse_egg_info_edge_case_split_failure(self) -> None:
        """
        Test parsing edge case where split returns unexpected results.
        """
        # This tests the fallback return for unexpected parse results
        name, version = parse_egg_info_dirname("package-.egg-info", ".egg-info")

        assert name == "package-"
        assert version is None

    def test_parse_egg_info_version_starts_with_letter(self) -> None:
        """
        Test parsing egg-info where version starts with a letter (not digit).
        """
        name, version = parse_egg_info_dirname("package-abc123.egg-info", ".egg-info")

        assert name == "package-abc123"
        assert version is None


@pytest.mark.unit
class TestExtractMetadataField:
    """
    Test extract_metadata_field function.
    """

    def test_extract_existing_field(self) -> None:
        """
        Test extracting existing field from metadata.
        """
        content = """Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
"""
        result = extract_metadata_field(content, "Name")

        assert result == "requests"

    def test_extract_field_case_insensitive(self) -> None:
        """
        Test extracting field with case insensitive matching.
        """
        content = """name: requests
version: 2.31.0"""
        result = extract_metadata_field(content, "Name")

        assert result == "requests"

    def test_extract_field_with_whitespace(self) -> None:
        """
        Test extracting field with extra whitespace.
        """
        content = """Name:   requests   
Version: 2.31.0"""
        result = extract_metadata_field(content, "Name")

        assert result == "requests"

    def test_extract_nonexistent_field(self) -> None:
        """
        Test extracting field that doesn't exist.
        """
        content = """Name: requests
Version: 2.31.0"""
        result = extract_metadata_field(content, "Nonexistent")

        assert result is None

    def test_extract_field_multiline_content(self) -> None:
        """
        Test extracting field from multiline content.
        """
        content = """Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
Home-page: https://requests.readthedocs.io"""
        result = extract_metadata_field(content, "Version")

        assert result == "2.31.0"

    def test_extract_field_with_colon_in_value(self) -> None:
        """
        Test extracting field where value contains colons.
        """
        content = """Name: requests
Home-page: https://example.com:8080/path"""
        result = extract_metadata_field(content, "Home-page")

        assert result == "https://example.com:8080/path"


@pytest.mark.unit
class TestEnrichPackageMeta:
    """
    Test enrich_package_meta function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def dist_info_path(self) -> Path:
        """
        Mock dist-info path.
        """
        return Path("/test/requests-2.31.0.dist-info")

    def test_enrich_with_direct_url_editable(
        self, mock_fs: Mock, dist_info_path: Path
    ) -> None:
        """
        Test enriching with direct_url.json for editable install.
        """
        direct_url_data = {
            "url": "file:///home/user/myproject",
            "dir_info": {"editable": True},
        }
        mock_fs.is_file.return_value = True
        mock_fs.read_text.return_value = json.dumps(direct_url_data)

        meta = {"name": "myproject", "version": "1.0.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        assert meta["direct_url"] == direct_url_data
        assert meta["editable"] is True
        assert meta["source_type"] == "url"
        assert meta["source_ref"] == "file:///home/user/myproject"

    def test_enrich_with_direct_url_from_url(
        self, mock_fs: Mock, dist_info_path: Path
    ) -> None:
        """
        Test enriching with direct_url.json from URL.
        """
        direct_url_data = {
            "url": "https://github.com/user/repo/archive/main.zip",
        }
        mock_fs.is_file.return_value = True
        mock_fs.read_text.return_value = json.dumps(direct_url_data)

        meta = {"name": "myproject", "version": "1.0.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        assert meta["source_type"] == "url"
        assert meta["source_ref"] == "https://github.com/user/repo/archive/main.zip"

    def test_enrich_with_direct_url_directory_only(
        self, mock_fs: Mock, dist_info_path: Path
    ) -> None:
        """
        Test enriching with direct_url.json directory info without URL.
        """
        direct_url_data = {"dir_info": {"editable": True}}
        mock_fs.is_file.return_value = True
        mock_fs.read_text.return_value = json.dumps(direct_url_data)

        meta = {"name": "myproject", "version": "1.0.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        assert meta["direct_url"] == direct_url_data
        assert meta["editable"] is True
        assert meta["source_type"] == "directory"

    def test_enrich_with_installer(self, mock_fs: Mock, dist_info_path: Path) -> None:
        """
        Test enriching with INSTALLER file.
        """

        def mock_is_file(path: Path) -> bool:
            return str(path).endswith("INSTALLER")

        def mock_read_text(path: Path, max_bytes: int) -> str:
            if str(path).endswith("INSTALLER"):
                return "pip"
            return ""

        mock_fs.is_file.side_effect = mock_is_file
        mock_fs.read_text.side_effect = mock_read_text

        meta = {"name": "requests", "version": "2.31.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        assert meta["installer"] == "pip"

    def test_enrich_generates_purl(self, mock_fs: Mock, dist_info_path: Path) -> None:
        """
        Test enriching generates package URL.
        """
        mock_fs.is_file.return_value = False

        meta = {"name": "My_Package-Name", "version": "1.0.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        assert meta["purl"] == "pkg:pypi/my-package-name@1.0.0"

    def test_enrich_no_purl_without_version(
        self, mock_fs: Mock, dist_info_path: Path
    ) -> None:
        """
        Test enriching doesn't generate purl without version.
        """
        mock_fs.is_file.return_value = False

        meta = {"name": "mypackage"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        assert "purl" not in meta

    def test_enrich_handles_malformed_json(
        self, mock_fs: Mock, dist_info_path: Path
    ) -> None:
        """
        Test enriching handles malformed JSON gracefully.
        """
        mock_fs.is_file.return_value = True
        mock_fs.read_text.return_value = "invalid json{"

        meta = {"name": "myproject", "version": "1.0.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        # Should not crash and should not add direct_url
        assert "direct_url" not in meta

    def test_enrich_handles_empty_files(
        self, mock_fs: Mock, dist_info_path: Path
    ) -> None:
        """
        Test enriching handles empty files gracefully.
        """
        mock_fs.is_file.return_value = True
        mock_fs.read_text.return_value = ""

        meta = {"name": "myproject", "version": "1.0.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        # Should not crash
        assert len(meta) >= 2  # At least name and version

    def test_enrich_with_direct_url_dir_info_only(
        self, mock_fs: Mock, dist_info_path: Path
    ) -> None:
        """
        Test enriching with direct_url.json containing only dir_info (no url).
        """
        # This should hit the elif "dir_info" in direct_url branch (lines 111-117)
        direct_url_data = {"dir_info": {"some": "data"}}
        mock_fs.is_file.return_value = True
        mock_fs.read_text.return_value = json.dumps(direct_url_data)

        meta = {"name": "myproject", "version": "1.0.0"}
        enrich_package_meta(meta, dist_info_path, mock_fs)

        assert meta["direct_url"] == direct_url_data
        assert meta["source_type"] == "directory"
        assert "editable" not in meta  # Should not be set unless explicitly True


@pytest.mark.unit
class TestCollectFileIntegrity:
    """
    Test collect_file_integrity function.
    """

    def test_collect_file_integrity_calls_from_path(self) -> None:
        """
        Test collect_file_integrity delegates to FileIntegrity.from_path.
        """
        mock_fs = Mock(spec=FsRuntime)
        test_path = Path("/test/file.txt")

        # Mock the FileIntegrity.from_path method
        with pytest.MonkeyPatch.context() as monkeypatch:
            mock_from_path = Mock()
            monkeypatch.setattr(
                "safety.system_scan.scanner.detectors.dependencies.collectors.FileIntegrity.from_path",
                mock_from_path,
            )

            collect_file_integrity(test_path, mock_fs)

            mock_from_path.assert_called_once_with(test_path, mock_fs)


@pytest.mark.unit
class TestCollectPythonDependencyInfo:
    """
    Test collect_python_dependency_info function.
    """

    def test_collect_dependency_info_with_version(self) -> None:
        """
        Test collecting dependency info with version.
        """
        mock_fs = Mock(spec=FsRuntime)
        dist_info_path = Path("/test/requests-2.31.0.dist-info")

        result = collect_python_dependency_info(
            dist_info_path, "requests", "2.31.0", mock_fs
        )

        assert result.canonical_path == str(Path("/test/requests-2.31.0.dist-info"))
        assert result.name == "requests"
        assert result.version == "2.31.0"

    def test_collect_dependency_info_without_version(self) -> None:
        """
        Test collecting dependency info without version.
        """
        mock_fs = Mock(spec=FsRuntime)
        dist_info_path = Path("/test/mypackage.dist-info")

        result = collect_python_dependency_info(
            dist_info_path, "mypackage", None, mock_fs
        )

        assert result.canonical_path == str(Path("/test/mypackage.dist-info"))
        assert result.name == "mypackage"
        assert result.version == "unknown"
