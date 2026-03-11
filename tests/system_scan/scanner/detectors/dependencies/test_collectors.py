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

    @pytest.mark.parametrize(
        "dirname, expected",
        [
            pytest.param(
                "requests-2.31.0.dist-info",
                ("requests", "2.31.0"),
                id="valid_with_version",
            ),
            pytest.param("mypackage.dist-info", ("mypackage", None), id="name_only"),
            pytest.param(
                "package-with-hyphens-1.0.0.dist-info",
                ("package-with-hyphens", "1.0.0"),
                id="hyphens_in_name",
            ),
            pytest.param(
                "package-invalidversion.dist-info",
                ("package-invalidversion", None),
                id="invalid_version_format",
            ),
            pytest.param("requests-2.31.0.egg-info", (None, None), id="wrong_suffix"),
            pytest.param(
                "Django-4.1.0.dist-info", ("Django", "4.1.0"), id="case_preservation"
            ),
            pytest.param(
                "numpy-1.24.0rc1.dist-info",
                ("numpy", "1.24.0rc1"),
                id="complex_version",
            ),
            pytest.param("", (None, None), id="empty_string"),
            pytest.param(
                "package-.dist-info", ("package-", None), id="trailing_hyphen"
            ),
        ],
    )
    def test_parse_dist_info_dirname(
        self, dirname: str, expected: tuple[str | None, str | None]
    ) -> None:
        result = parse_dist_info_dirname(dirname, ".dist-info")
        assert result == expected


@pytest.mark.unit
class TestParseEggInfoDirname:
    """
    Test parse_egg_info_dirname function.
    """

    @pytest.mark.parametrize(
        "dirname, expected",
        [
            # ── Basic parsing ────────────────────────────────────────
            pytest.param(
                "setuptools-65.0.0.egg-info",
                ("setuptools", "65.0.0"),
                id="valid_with_version",
            ),
            pytest.param("mypackage.egg-info", ("mypackage", None), id="name_only"),
            pytest.param(
                "my-package-2.0.0.egg-info",
                ("my-package", "2.0.0"),
                id="hyphens_in_name",
            ),
            pytest.param(
                "Django-4.1.0.egg-info", ("Django", "4.1.0"), id="case_preservation"
            ),
            pytest.param(
                "package-notversion.egg-info",
                ("package-notversion", None),
                id="invalid_version",
            ),
            pytest.param("package-1.0.0.dist-info", (None, None), id="wrong_suffix"),
            pytest.param("package-.egg-info", ("package-", None), id="trailing_hyphen"),
            pytest.param(
                "package-abc123.egg-info",
                ("package-abc123", None),
                id="version_starts_with_letter",
            ),
            # ── -pyX.Y python version tags ───────────────────────────
            pytest.param(
                "cryptography-36.0.1-py3.9.egg-info",
                ("cryptography", "36.0.1"),
                id="py_tag",
            ),
            pytest.param(
                "systemd_python-235-py3.9.egg-info",
                ("systemd_python", "235"),
                id="py_tag_single_segment_version",
            ),
            pytest.param(
                "ruamel.yaml-0.16.6-py3.9.egg-info",
                ("ruamel.yaml", "0.16.6"),
                id="py_tag_dotted_name",
            ),
            pytest.param(
                "package-1.0.0rc1-py3.12.egg-info",
                ("package", "1.0.0rc1"),
                id="py_tag_prerelease",
            ),
            pytest.param(
                "package-1.0.0-py3.9.1.egg-info",
                ("package", "1.0.0"),
                id="py_tag_xyz_micro",
            ),
            pytest.param(
                "attrs-23.1.0-py3.13.egg-info",
                ("attrs", "23.1.0"),
                id="py_tag_two_digit_minor",
            ),
            # ── Non-pyX.Y tags → parser falls back to full stem ──────
            pytest.param(
                "package-1.0-linux-x86_64.egg-info",
                ("package-1.0-linux-x86_64", None),
                id="platform_tag_fallback",
            ),
            pytest.param(
                "package-2.0-cp39.egg-info",
                ("package-2.0-cp39", None),
                id="abi_tag_fallback",
            ),
            pytest.param(
                "package-1.0-py3.9-linux-x86_64.egg-info",
                ("package-1.0-py3.9-linux-x86_64", None),
                id="py_plus_platform_tag_fallback",
            ),
        ],
    )
    def test_parse_egg_info_dirname(
        self, dirname: str, expected: tuple[str | None, str | None]
    ) -> None:
        result = parse_egg_info_dirname(dirname, ".egg-info")
        assert result == expected


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
