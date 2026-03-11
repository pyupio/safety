from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from safety.system_scan.scanner.detectors.environments.helpers import (
    _to_major_minor,
    _get_prefix,
    _extract_cellar_prefix,
    _collect_prefixes,
    _base_env_canonical_path,
    _get_base_package_dirs,
    _get_user_site_packages,
)

# All helpers use `platform.system()` via `import platform` in helpers.py.
# We patch at the helpers module level for reliable cross-platform testing.
HELPERS_PLATFORM = "safety.system_scan.scanner.detectors.environments.helpers.platform"


@pytest.mark.unit
class TestToMajorMinor:
    """
    Tests for _to_major_minor() helper.
    """

    @pytest.mark.parametrize(
        "version, expected",
        [
            ("3.11.6", "3.11"),
            ("3.11", "3.11"),
            ("3", None),
            (None, None),
            ("", None),
        ],
    )
    def test_to_major_minor(self, version: str | None, expected: str | None) -> None:
        assert _to_major_minor(version) == expected


@pytest.mark.unix_only
@pytest.mark.unit
class TestGetPrefix:
    """
    Tests for _get_prefix() helper (Unix paths).
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_linux_prefix(self, _mock) -> None:
        path = Path("/usr/bin/python3.11")
        assert _get_prefix(path) == Path("/usr")

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Darwin")
    def test_macos_prefix(self, _mock) -> None:
        path = Path(
            "/opt/homebrew/Cellar/python@3.11/3.11.6/Frameworks/"
            "Python.framework/Versions/3.11/bin/python3.11"
        )
        assert _get_prefix(path) == Path(
            "/opt/homebrew/Cellar/python@3.11/3.11.6/Frameworks/"
            "Python.framework/Versions/3.11"
        )


@pytest.mark.unix_only
@pytest.mark.unit
class TestExtractCellarPrefix:
    """
    Tests for _extract_cellar_prefix() helper.
    """

    def test_homebrew_macos(self) -> None:
        resolved = Path(
            "/opt/homebrew/Cellar/python@3.13/3.13.0/Frameworks/"
            "Python.framework/Versions/3.13/bin/python3.13"
        )
        assert _extract_cellar_prefix(resolved) == Path("/opt/homebrew")

    def test_homebrew_linux(self) -> None:
        resolved = Path(
            "/home/user/.linuxbrew/Cellar/python@3.11/3.11.6/bin/python3.11"
        )
        assert _extract_cellar_prefix(resolved) == Path("/home/user/.linuxbrew")

    def test_non_cellar_path(self) -> None:
        resolved = Path("/usr/bin/python3.11")
        assert _extract_cellar_prefix(resolved) is None

    def test_cellar_at_start(self) -> None:
        # /Cellar/ at position 0 -> idx == 0, not > 0
        resolved = Path("/Cellar/python/bin/python3")
        assert _extract_cellar_prefix(resolved) is None


@pytest.mark.unix_only
@pytest.mark.unit
class TestCollectPrefixes:
    """
    Tests for _collect_prefixes() helper (Unix paths).
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_standard_system_install(self, _mock) -> None:
        """
        Same path resolves to itself -> one prefix.
        """
        candidate = Path("/usr/bin/python3.11")
        resolved = Path("/usr/bin/python3.11")
        prefixes = _collect_prefixes(candidate, resolved)
        assert prefixes == [Path("/usr")]

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_pyenv_shim(self, _mock) -> None:
        """Shim resolves to different path -> two prefixes.
        _get_prefix on Unix does .parent.parent, so:
          resolved prefix = .../versions/3.11.6 (from .../bin/python3.11)
          candidate prefix = /home/alice/.pyenv  (from .../shims/python3.11)
        """
        candidate = Path("/home/alice/.pyenv/shims/python3.11")
        resolved = Path("/home/alice/.pyenv/versions/3.11.6/bin/python3.11")
        prefixes = _collect_prefixes(candidate, resolved)
        assert len(prefixes) == 2
        assert prefixes[0] == Path("/home/alice/.pyenv/versions/3.11.6")
        assert prefixes[1] == Path("/home/alice/.pyenv")

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Darwin")
    def test_homebrew_with_cellar(self, _mock) -> None:
        """
        Homebrew: candidate from /opt/homebrew, resolved in Cellar -> two prefixes.
        """
        candidate = Path("/opt/homebrew/bin/python3.13")
        resolved = Path(
            "/opt/homebrew/Cellar/python@3.13/3.13.0/Frameworks/"
            "Python.framework/Versions/3.13/bin/python3.13"
        )
        prefixes = _collect_prefixes(candidate, resolved)
        # resolved prefix = .../Versions/3.13
        # candidate prefix = /opt/homebrew
        # cellar prefix = /opt/homebrew (deduped with candidate prefix)
        assert len(prefixes) == 2
        assert prefixes[0] == Path(
            "/opt/homebrew/Cellar/python@3.13/3.13.0/Frameworks/"
            "Python.framework/Versions/3.13"
        )
        assert prefixes[1] == Path("/opt/homebrew")


@pytest.mark.unix_only
@pytest.mark.unit
class TestBaseEnvCanonicalPath:
    """
    Tests for _base_env_canonical_path() helper (Unix paths).
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_linux(self, _mock) -> None:
        assert _base_env_canonical_path(Path("/usr"), "3.11") == Path(
            "/usr/lib/python3.11"
        )

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Darwin")
    def test_macos(self, _mock) -> None:
        prefix = Path(
            "/opt/homebrew/Cellar/python@3.11/3.11.6/Frameworks/"
            "Python.framework/Versions/3.11"
        )
        expected = prefix / "lib" / "python3.11"
        assert _base_env_canonical_path(prefix, "3.11") == expected


@pytest.mark.unix_only
@pytest.mark.unit
class TestGetBasePackageDirs:
    """
    Tests for _get_base_package_dirs() helper (Unix paths).
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_linux_usr_prefix(self, _mock) -> None:
        """
        Linux with /usr prefix should include /usr/local and lib64 entries.
        """
        dirs = _get_base_package_dirs(Path("/usr"), "3.11")
        expected = [
            Path("/usr/lib/python3.11/site-packages"),
            Path("/usr/lib/python3.11/dist-packages"),
            Path("/usr/lib/python3/dist-packages"),
            Path("/usr/local/lib/python3.11/dist-packages"),
            Path("/usr/local/lib/python3.11/site-packages"),
            Path("/usr/lib64/python3.11/site-packages"),
            Path("/usr/local/lib64/python3.11/site-packages"),
        ]
        assert dirs == expected

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_linux_non_usr_prefix(self, _mock) -> None:
        """
        Linux with non-/usr prefix should NOT include /usr/local entries.
        """
        dirs = _get_base_package_dirs(Path("/opt/py"), "3.12")
        expected = [
            Path("/opt/py/lib/python3.12/site-packages"),
            Path("/opt/py/lib/python3.12/dist-packages"),
            Path("/opt/py/lib/python3/dist-packages"),
            Path("/opt/py/lib64/python3.12/site-packages"),
        ]
        assert dirs == expected


@pytest.mark.unix_only
@pytest.mark.unit
class TestGetUserSitePackages:
    """
    Tests for _get_user_site_packages() helper (Unix paths).
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Linux")
    def test_linux(self, _mock) -> None:
        result = _get_user_site_packages("3.11")
        assert result == Path.home() / ".local" / "lib" / "python3.11" / "site-packages"

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Darwin")
    def test_macos(self, _mock) -> None:
        result = _get_user_site_packages("3.13")
        assert result == (
            Path.home()
            / "Library"
            / "Python"
            / "3.13"
            / "lib"
            / "python"
            / "site-packages"
        )


@pytest.mark.windows_only
@pytest.mark.unit
class TestHelpersWindows:
    """
    Windows-specific tests for helper functions.
    Grouped here because WindowsPath serialization (backslashes) makes
    these tests fail on Unix hosts where Path produces PosixPath.
    """

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    def test_get_prefix(self, _mock) -> None:
        path = Path("/C/Python311/python.exe")
        result = _get_prefix(path)
        assert result == path.parent

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    def test_collect_prefixes_pyenv_win(self, _mock) -> None:
        """pyenv-win: candidate from shims, resolved to versions dir.
        On Windows, _get_prefix returns .parent (one level up)."""
        candidate = Path("/C/Users/alice/.pyenv/pyenv-win/shims/python.exe")
        resolved = Path("/C/Users/alice/.pyenv/pyenv-win/versions/3.11.6/python.exe")
        prefixes = _collect_prefixes(candidate, resolved)
        assert len(prefixes) == 2
        assert prefixes[0] == Path("/C/Users/alice/.pyenv/pyenv-win/versions/3.11.6")
        assert prefixes[1] == Path("/C/Users/alice/.pyenv/pyenv-win/shims")

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    def test_base_env_canonical_path(self, _mock) -> None:
        prefix = Path("/C/Python311")
        result = _base_env_canonical_path(prefix, "3.11")
        assert result == prefix / "Lib"

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    def test_get_base_package_dirs(self, _mock) -> None:
        prefix = Path("/C/Python311")
        dirs = _get_base_package_dirs(prefix, "3.11")
        assert len(dirs) == 1
        assert dirs[0] == prefix / "Lib" / "site-packages"

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    @patch.dict("os.environ", {"APPDATA": "/C/Users/alice/AppData/Roaming"})
    def test_get_user_site_packages(self, _mock) -> None:
        result = _get_user_site_packages("3.12")
        assert result is not None
        assert result.parts[-3:] == ("Python", "Python312", "site-packages")

    @patch(f"{HELPERS_PLATFORM}.system", return_value="Windows")
    @patch.dict("os.environ", {"APPDATA": ""})
    def test_get_user_site_packages_no_appdata(self, _mock) -> None:
        result = _get_user_site_packages("3.12")
        assert result is None
