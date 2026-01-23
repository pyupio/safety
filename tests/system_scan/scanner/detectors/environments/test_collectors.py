from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import pytest
from typing import cast

from safety.system_scan.scanner.detectors.environments.collectors import (
    collect_venv_environment_info,
    collect_base_environment_info,
    collect_user_environment_info,
    _parse_pyvenv_cfg,
    _detect_venv_creator,
    _find_venv_site_packages,
    _find_base_site_packages,
    _find_user_site_packages,
)
from safety.system_scan.scanner.filesystem import FsRuntime
from safety.system_scan.scanner.events.payloads.environment import (
    PythonVenvEnvironment,
    PythonBaseEnvironment,
    PythonUserEnvironment,
    CreatorTool,
)


@pytest.mark.unit
class TestCollectVenvEnvironmentInfo:
    """
    Test collect_venv_environment_info function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    @pytest.fixture
    def temp_venv_root(self):
        """
        Temporary virtual environment root.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            yield Path(tmp_dir)

    def test_collect_venv_info_success(
        self, mock_fs: Mock, temp_venv_root: Path
    ) -> None:
        """
        Test successful venv info collection.
        """
        pyvenv_cfg_content = (
            "home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.11.0\n"
        )

        cast(Mock, mock_fs.read_text).return_value = pyvenv_cfg_content
        cast(Mock, mock_fs.realpath).return_value = temp_venv_root
        cast(Mock, mock_fs.is_dir).side_effect = lambda p: (
            "site-packages" in str(p) or "bin" in str(p)
        )

        # Mock stat for timestamps
        stat_mock = Mock()
        stat_mock.st_mtime = 1640995200.0
        cast(Mock, mock_fs.stat).return_value = stat_mock

        result = collect_venv_environment_info(temp_venv_root, mock_fs)

        assert result is not None
        assert isinstance(result, PythonVenvEnvironment)
        assert result.canonical_path == str(temp_venv_root)
        if result.python_venv_pyvenv_cfg:
            assert result.python_venv_pyvenv_cfg["home"] == "/usr/bin"
            assert result.python_venv_pyvenv_cfg["version"] == "3.11.0"
        assert result.python_venv_metadata is not None

    def test_collect_venv_info_no_cfg_content(
        self, mock_fs: Mock, temp_venv_root: Path
    ) -> None:
        """
        Test venv collection with empty pyvenv.cfg.
        """
        cast(Mock, mock_fs.read_text).return_value = ""

        result = collect_venv_environment_info(temp_venv_root, mock_fs)

        assert result is None

    def test_collect_venv_info_read_exception(
        self, mock_fs: Mock, temp_venv_root: Path
    ) -> None:
        """
        Test venv collection with read exception.
        """
        cast(Mock, mock_fs.read_text).side_effect = OSError("Cannot read file")

        result = collect_venv_environment_info(temp_venv_root, mock_fs)

        assert result is None

    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._find_venv_site_packages"
    )
    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._detect_venv_creator"
    )
    def test_collect_venv_info_stat_exception(
        self,
        mock_detect_creator: Mock,
        mock_find_site_packages: Mock,
        mock_fs: Mock,
        temp_venv_root: Path,
    ) -> None:
        """
        Test venv collection with stat exception.
        """
        pyvenv_cfg_content = "home = /usr/bin\n"

        cast(Mock, mock_fs.read_text).return_value = pyvenv_cfg_content
        cast(Mock, mock_fs.realpath).return_value = temp_venv_root
        cast(Mock, mock_fs.is_dir).return_value = True
        cast(Mock, mock_fs.stat).side_effect = OSError("Cannot stat")

        mock_detect_creator.return_value = CreatorTool(name="test")
        mock_find_site_packages.return_value = temp_venv_root / "site-packages"

        result = collect_venv_environment_info(temp_venv_root, mock_fs)

        assert result is not None
        assert result.python_venv_metadata is not None
        assert result.python_venv_metadata.site_packages_mtime is None
        assert result.python_venv_metadata.bin_mtime is None


@pytest.mark.unit
class TestCollectBaseEnvironmentInfo:
    """
    Test collect_base_environment_info function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._find_base_site_packages"
    )
    def test_collect_base_info_success(
        self, mock_find_site_packages: Mock, mock_fs: Mock
    ) -> None:
        """
        Test successful base environment collection.
        """
        runtime_path = Path("/usr/bin/python3")
        site_packages = Path("/usr/lib/python3.11/site-packages")

        mock_find_site_packages.return_value = site_packages

        result = collect_base_environment_info(runtime_path, mock_fs)

        assert result is not None
        assert isinstance(result, PythonBaseEnvironment)
        assert result.canonical_path == str(site_packages)
        assert result.site_packages_path == str(site_packages)
        assert result.runtime_path == str(runtime_path)

    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._find_base_site_packages"
    )
    def test_collect_base_info_no_site_packages(
        self, mock_find_site_packages: Mock, mock_fs: Mock
    ) -> None:
        """
        Test base environment collection with no site-packages.
        """
        runtime_path = Path("/usr/bin/python3")
        mock_find_site_packages.return_value = None

        result = collect_base_environment_info(runtime_path, mock_fs)

        assert result is None

    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._find_base_site_packages"
    )
    def test_collect_base_info_exception(
        self, mock_find_site_packages: Mock, mock_fs: Mock
    ) -> None:
        """
        Test base environment collection with exception.
        """
        runtime_path = Path("/usr/bin/python3")
        mock_find_site_packages.side_effect = Exception("Find error")

        result = collect_base_environment_info(runtime_path, mock_fs)

        assert result is None


@pytest.mark.unit
class TestCollectUserEnvironmentInfo:
    """
    Test collect_user_environment_info function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._find_user_site_packages"
    )
    def test_collect_user_info_success(
        self, mock_find_site_packages: Mock, mock_fs: Mock
    ) -> None:
        """
        Test successful user environment collection.
        """
        site_packages = Path.home() / ".local/lib/python3.11/site-packages"
        mock_find_site_packages.return_value = site_packages

        result = collect_user_environment_info(mock_fs)

        assert result is not None
        assert isinstance(result, PythonUserEnvironment)
        assert result.canonical_path == str(site_packages)
        assert result.site_packages_path == str(site_packages)
        assert result.user_site_enabled is True

    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._find_user_site_packages"
    )
    def test_collect_user_info_no_site_packages(
        self, mock_find_site_packages: Mock, mock_fs: Mock
    ) -> None:
        """
        Test user environment collection with no site-packages.
        """
        mock_find_site_packages.return_value = None

        result = collect_user_environment_info(mock_fs)

        assert result is None

    @patch(
        "safety.system_scan.scanner.detectors.environments.collectors._find_user_site_packages"
    )
    def test_collect_user_info_exception(
        self, mock_find_site_packages: Mock, mock_fs: Mock
    ) -> None:
        """
        Test user environment collection with exception.
        """
        mock_find_site_packages.side_effect = Exception("Find error")

        result = collect_user_environment_info(mock_fs)

        assert result is None


@pytest.mark.unit
class TestParsePyvenvCfg:
    """
    Test _parse_pyvenv_cfg function.
    """

    def test_parse_simple_config(self) -> None:
        """
        Test parsing simple pyvenv.cfg content.
        """
        content = """home = /usr/bin
include-system-site-packages = false
version = 3.11.0
"""
        result = _parse_pyvenv_cfg(content)

        assert result == {
            "home": "/usr/bin",
            "include-system-site-packages": "false",
            "version": "3.11.0",
        }

    def test_parse_with_comments_and_empty_lines(self) -> None:
        """
        Test parsing config with comments and empty lines.
        """
        content = """# This is a comment
home = /usr/bin

# Another comment
include-system-site-packages = false
version = 3.11.0

"""
        result = _parse_pyvenv_cfg(content)

        assert result == {
            "home": "/usr/bin",
            "include-system-site-packages": "false",
            "version": "3.11.0",
        }

    def test_parse_with_whitespace(self) -> None:
        """
        Test parsing config with extra whitespace.
        """
        content = "  home   =   /usr/bin  \n  version  =  3.11.0  "
        result = _parse_pyvenv_cfg(content)

        assert result == {
            "home": "/usr/bin",
            "version": "3.11.0",
        }

    def test_parse_lines_without_equals(self) -> None:
        """
        Test parsing config with lines without equals sign.
        """
        content = """home = /usr/bin
invalid line without equals
version = 3.11.0
"""
        result = _parse_pyvenv_cfg(content)

        assert result == {
            "home": "/usr/bin",
            "version": "3.11.0",
        }

    def test_parse_empty_content(self) -> None:
        """
        Test parsing empty content.
        """
        result = _parse_pyvenv_cfg("")
        assert result == {}

    def test_parse_only_comments(self) -> None:
        """
        Test parsing content with only comments.
        """
        content = "# Comment 1\n# Comment 2"
        result = _parse_pyvenv_cfg(content)
        assert result == {}


@pytest.mark.unit
class TestDetectVenvCreator:
    """
    Test _detect_venv_creator function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    def test_detect_uv_creator(self, mock_fs: Mock) -> None:
        """
        Test detecting uv as creator.
        """
        venv_root = Path("/project/.venv")
        cast(Mock, mock_fs.is_file).side_effect = lambda p: str(p).endswith("uv.lock")

        result = _detect_venv_creator(venv_root, mock_fs)

        assert result is not None
        assert result.name == "uv"

    def test_detect_poetry_creator(self, mock_fs: Mock) -> None:
        """
        Test detecting poetry as creator.
        """
        venv_root = Path("/project/.venv")
        cast(Mock, mock_fs.is_file).side_effect = lambda p: str(p).endswith(
            "poetry.lock"
        )

        result = _detect_venv_creator(venv_root, mock_fs)

        assert result is not None
        assert result.name == "poetry"

    def test_detect_pipenv_creator(self, mock_fs: Mock) -> None:
        """
        Test detecting pipenv as creator.
        """
        venv_root = Path("/project/.venv")
        cast(Mock, mock_fs.is_file).side_effect = lambda p: str(p).endswith(
            "Pipfile.lock"
        )

        result = _detect_venv_creator(venv_root, mock_fs)

        assert result is not None
        assert result.name == "pipenv"

    def test_detect_pdm_creator(self, mock_fs: Mock) -> None:
        """
        Test detecting pdm as creator.
        """
        venv_root = Path("/project/.venv")
        cast(Mock, mock_fs.is_file).side_effect = lambda p: str(p).endswith("pdm.lock")

        result = _detect_venv_creator(venv_root, mock_fs)

        assert result is not None
        assert result.name == "pdm"

    def test_detect_default_venv_creator(self, mock_fs: Mock) -> None:
        """
        Test detecting default venv creator.
        """
        venv_root = Path("/project/.venv")
        cast(Mock, mock_fs.is_file).return_value = False

        result = _detect_venv_creator(venv_root, mock_fs)

        assert result is not None
        assert result.name == "venv"


@pytest.mark.unit
class TestFindVenvSitePackages:
    """
    Test _find_venv_site_packages function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    def test_find_unix_site_packages(self, mock_fs: Mock) -> None:
        """
        Test finding Unix-style site-packages.
        """
        venv_root = Path("/project/.venv")
        expected_path = venv_root / "lib/python3.11/site-packages"

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.return_value = [expected_path]
            cast(Mock, mock_fs.is_dir).return_value = True

            result = _find_venv_site_packages(venv_root, mock_fs)

            assert result == expected_path

    def test_find_windows_site_packages(self, mock_fs: Mock) -> None:
        """
        Test finding Windows-style site-packages.
        """
        venv_root = Path("C:/project/.venv")
        expected_path = venv_root / "Lib/site-packages"

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.side_effect = [
                [],
                [expected_path],
            ]  # First pattern fails, second succeeds
            cast(Mock, mock_fs.is_dir).return_value = True

            result = _find_venv_site_packages(venv_root, mock_fs)

            assert result == expected_path

    def test_find_site_packages_not_found(self, mock_fs: Mock) -> None:
        """
        Test finding site-packages when not found.
        """
        venv_root = Path("/project/.venv")

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.return_value = []

            result = _find_venv_site_packages(venv_root, mock_fs)

            assert result is None

    def test_find_site_packages_not_directory(self, mock_fs: Mock) -> None:
        """
        Test finding site-packages when path exists but is not directory.
        """
        venv_root = Path("/project/.venv")
        found_path = venv_root / "lib/python3.11/site-packages"

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.return_value = [found_path]
            cast(Mock, mock_fs.is_dir).return_value = False

            result = _find_venv_site_packages(venv_root, mock_fs)

            assert result is None


@pytest.mark.unit
class TestFindBaseSitePackages:
    """
    Test _find_base_site_packages function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    def test_find_base_site_packages_success(self, mock_fs: Mock) -> None:
        """
        Test finding base site-packages successfully.
        """
        runtime_path = Path("/usr/bin/python3")
        expected_path = Path("/usr/lib/python3.11/site-packages")

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.return_value = [expected_path]
            cast(Mock, mock_fs.is_dir).return_value = True

            result = _find_base_site_packages(runtime_path, mock_fs)

            assert result == expected_path

    def test_find_base_site_packages_lib64(self, mock_fs: Mock) -> None:
        """
        Test finding base site-packages in lib64.
        """
        runtime_path = Path("/usr/bin/python3")
        expected_path = Path("/usr/lib64/python3.11/site-packages")

        with patch.object(Path, "glob") as mock_glob:
            # First patterns fail, lib64 pattern succeeds
            mock_glob.side_effect = [[], [], [expected_path]]
            cast(Mock, mock_fs.is_dir).return_value = True

            result = _find_base_site_packages(runtime_path, mock_fs)

            assert result == expected_path

    def test_find_base_site_packages_not_found(self, mock_fs: Mock) -> None:
        """
        Test finding base site-packages when not found.
        """
        runtime_path = Path("/usr/bin/python3")

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.return_value = []

            result = _find_base_site_packages(runtime_path, mock_fs)

            assert result is None


@pytest.mark.unit
class TestFindUserSitePackages:
    """
    Test _find_user_site_packages function.
    """

    @pytest.fixture
    def mock_fs(self) -> Mock:
        """
        Mock filesystem runtime.
        """
        return Mock(spec=FsRuntime)

    @patch("platform.system")
    def test_find_user_site_packages_unix(
        self, mock_platform: Mock, mock_fs: Mock
    ) -> None:
        """
        Test finding user site-packages on Unix.
        """
        mock_platform.return_value = "Linux"
        expected_path = Path.home() / ".local/lib/python3.11/site-packages"

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.return_value = [expected_path]
            cast(Mock, mock_fs.is_dir).return_value = True

            result = _find_user_site_packages(mock_fs)

            assert result == expected_path

    @patch("platform.system")
    def test_find_user_site_packages_windows(
        self, mock_platform: Mock, mock_fs: Mock
    ) -> None:
        """
        Test finding user site-packages on Windows.
        """
        mock_platform.return_value = "Windows"
        expected_path = Path.home() / "AppData/Roaming/Python/Python311/site-packages"

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.side_effect = [
                [],
                [],
                [expected_path],
            ]  # Windows pattern succeeds
            cast(Mock, mock_fs.is_dir).return_value = True

            result = _find_user_site_packages(mock_fs)

            assert result == expected_path

    @patch("platform.system")
    def test_find_user_site_packages_not_found(
        self, mock_platform: Mock, mock_fs: Mock
    ) -> None:
        """
        Test finding user site-packages when not found.
        """
        mock_platform.return_value = "Linux"

        with patch.object(Path, "glob") as mock_glob:
            mock_glob.return_value = []

            result = _find_user_site_packages(mock_fs)

            assert result is None
