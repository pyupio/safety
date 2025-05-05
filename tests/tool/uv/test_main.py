# type: ignore
import unittest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

import tomlkit
from rich.console import Console

from safety.tool.uv.main import Uv, backup_file
from safety.tool.constants import ORGANIZATION_REPOSITORY_URL


class TestUv(unittest.TestCase):
    """
    Test cases for Uv class functionality including various configuration scenarios.
    """

    def setUp(self):
        """
        Set up test environment before each test method.
        """
        self.test_console = Console(file=StringIO(), width=100)
        self.org_slug = "test-org"
        self.project_id = "test-project-id"
        self.pyproject_path = Path("/path/to/pyproject.toml")
        self.safety_url = "https://pypi.test-org.safetycli.com/simple/"
        self.public_url = "https://pypi.safetycli.com/simple/"

    def tearDown(self):
        """
        Clean up after each test method.
        """
        pass

    def test_is_installed_when_uv_exists(self):
        """
        Test is_installed method when uv is installed on the system.
        """
        with patch("shutil.which", return_value="/path/to/uv"):
            self.assertTrue(Uv.is_installed())

    def test_is_installed_when_uv_not_exists(self):
        """
        Test is_installed method when uv is not installed on the system.
        """
        with patch("shutil.which", return_value=None):
            self.assertFalse(Uv.is_installed())

    def test_is_uv_project_file_with_valid_config(self):
        """
        Test is_uv_project_file with a valid toml file containing uv config.
        """
        mock_content = """
[project]
name = "test-project"
version = "0.1.0"

[tool.uv]
no-build-isolation-package = ["flash-attn"]
        """
        with patch("pathlib.Path.read_text", return_value=mock_content):
            with patch("pathlib.Path.exists", return_value=False):
                self.assertTrue(Uv.is_uv_project_file(Path("/path/to/pyproject.toml")))

    def test_is_uv_project_file_with_lock_file(self):
        """
        Test is_uv_project_file when uv.lock exists but no uv config in toml.
        """
        mock_content = """
[project]
name = "test-project"
version = "0.1.0"
        """
        with patch("pathlib.Path.read_text", return_value=mock_content):
            with patch("pathlib.Path.exists", return_value=True):
                self.assertTrue(Uv.is_uv_project_file(Path("/path/to/pyproject.toml")))

    def test_is_uv_project_file_without_uv_config(self):
        """
        Test is_uv_project_file when file doesn't have uv config and no lock file.
        """
        mock_content = """
[project]
name = "test-project"
version = "0.1.0"
        """
        with patch("pathlib.Path.read_text", return_value=mock_content):
            with patch("pathlib.Path.exists", return_value=False):
                self.assertFalse(Uv.is_uv_project_file(Path("/path/to/pyproject.toml")))

    def test_is_uv_project_file_with_invalid_toml(self):
        """
        Test is_uv_project_file with an invalid toml file.
        """
        with patch("pathlib.Path.read_text", side_effect=ValueError):
            self.assertFalse(Uv.is_uv_project_file(Path("/path/to/pyproject.toml")))

    def test_is_uv_project_file_with_io_error(self):
        """
        Test is_uv_project_file when file can't be read.
        """
        with patch("pathlib.Path.read_text", side_effect=IOError):
            self.assertFalse(Uv.is_uv_project_file(Path("/path/to/pyproject.toml")))

    def test_configure_pyproject_when_uv_not_installed(self):
        """
        Test configure_pyproject when UV is not installed.
        """
        with patch.object(Uv, "is_installed", return_value=False):
            result = Uv.configure_pyproject(
                self.pyproject_path, self.org_slug, self.project_id, self.test_console
            )
            self.assertIsNone(result)

    def test_configure_pyproject_with_empty_file(self):
        """
        Test configure_pyproject with an initially empty file.
        """
        with patch.object(Uv, "is_installed", return_value=True):
            empty_doc = {"tool": {"uv": {"index": []}}}

            with patch("pathlib.Path.read_text", return_value=""):
                with patch("tomlkit.loads", return_value=empty_doc):
                    with patch("pathlib.Path.write_text"):
                        with patch.object(Uv, "filter_out_safety_index"):
                            with patch(
                                "tomlkit.dumps", return_value="mocked TOML content"
                            ):
                                result = Uv.configure_pyproject(
                                    self.pyproject_path,
                                    self.org_slug,
                                    self.project_id,
                                    self.test_console,
                                )

                                self.assertIsNotNone(result)
                                self.assertEqual(result, self.pyproject_path)

    def test_configure_pyproject_with_array_of_tables_format(self):
        """
        Test configure_pyproject with array of tables format for indexes.
        """
        with patch.object(Uv, "is_installed", return_value=True):
            mock_content = """
[project]
name = "uv-project"
version = "0.1.0"
description = "Test project"
readme = "README.md"
requires-python = ">=3.8"
dependencies = []

[[tool.uv.index]]
url = "https://test.pypi.org/simple"
default = true

[[tool.uv.index]]
url = "https://pypi.org/simple"
default = false
            """

            with patch("pathlib.Path.read_text", return_value=mock_content):
                with patch("pathlib.Path.write_text") as mock_write:
                    result = Uv.configure_pyproject(
                        self.pyproject_path,
                        self.org_slug,
                        self.project_id,
                        self.test_console,
                    )

                    self.assertEqual(result, self.pyproject_path)
                    mock_write.assert_called_once()

                    args = mock_write.call_args[0][0]
                    doc = tomlkit.parse(args)

                    first_index = doc["tool"]["uv"]["index"][0]
                    self.assertEqual(first_index["name"], "safety")
                    self.assertEqual(first_index["default"], False)

    def test_configure_pyproject_with_public_repository(self):
        """
        Test configure_pyproject with public repository (no org_slug).
        """
        with patch.object(Uv, "is_installed", return_value=True):
            mock_doc = {"tool": {"uv": {"index": []}}}

            with patch("pathlib.Path.read_text", return_value="mock content"):
                with patch("tomlkit.loads", return_value=mock_doc):
                    with patch("pathlib.Path.write_text"):
                        with patch.object(Uv, "filter_out_safety_index"):
                            with patch("tomlkit.dumps", return_value="mocked content"):
                                with patch("tomlkit.aot", return_value=[]):
                                    result = Uv.configure_pyproject(
                                        self.pyproject_path,
                                        None,
                                        None,
                                        self.test_console,
                                    )

                                    self.assertIsNotNone(result)
                                    self.assertEqual(result, self.pyproject_path)

    def test_configure_pyproject_with_existing_safety_index(self):
        """
        Test configure_pyproject when a safety index already exists.
        """
        with patch.object(Uv, "is_installed", return_value=True):
            mock_content = """
[project]
name = "uv-project"
version = "0.1.0"

[[tool.uv.index]]  
name = "safety"
url = "https://pypi.org/simple/"
default = true

[[tool.uv.index]]  
name = "safety"
url = "https://old-pkgs.safetycli.com/repository/safety-cybersecurity/pypi/simple/"
default = false
            """

            with patch("pathlib.Path.read_text", return_value=mock_content):
                with patch("pathlib.Path.write_text") as mock_write:
                    _ = Uv.configure_pyproject(
                        self.pyproject_path, self.org_slug, None, self.test_console
                    )

                    # Get the written TOML content
                    args = mock_write.call_args[0][0]
                    doc = tomlkit.parse(args)

                    # Check the old safety index is replaced
                    first_index = doc["tool"]["uv"]["index"][0]
                    self.assertEqual(first_index["name"], "safety")
                    self.assertEqual(
                        first_index["url"],
                        ORGANIZATION_REPOSITORY_URL.format(self.org_slug),
                    )
                    self.assertEqual(
                        len(doc["tool"]["uv"]["index"]), 2
                    )  # New safety + pypi.org

    def test_configure_pyproject_error_handling(self):
        """
        Test configure_pyproject error handling.
        """
        with patch.object(Uv, "is_installed", return_value=True):
            with patch(
                "pathlib.Path.read_text", side_effect=ValueError("Invalid TOML")
            ):
                result = Uv.configure_pyproject(
                    self.pyproject_path, self.org_slug, None, self.test_console
                )
                self.assertIsNone(result)

    def test_get_user_config_path_on_windows(self):
        """
        Test get_user_config_path on Windows platform.
        """
        with patch.dict(os.environ, {"APPDATA": r"C:\Users\test\AppData\Roaming"}):
            with patch("sys.platform", "win32"):
                path = Uv.get_user_config_path()
                expected_parts = ["C:\\Users\\test\\AppData\\Roaming", "uv", "uv.toml"]
                # Check the path components are correct rather than exactly matching the path format
                self.assertEqual(
                    str(path.parent.parent).lower(), expected_parts[0].lower()
                )
                self.assertEqual(path.parent.name, "uv")
                self.assertEqual(path.name, "uv.toml")

    def test_get_user_config_path_on_linux_with_xdg(self):
        """
        Test get_user_config_path on Linux with XDG_CONFIG_HOME set.
        """
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/home/test/.config"}):
            with patch("sys.platform", "linux"):
                path = Uv.get_user_config_path()
                self.assertEqual(path, Path("/home/test/.config/uv/uv.toml"))

    def test_get_user_config_path_on_macos_default(self):
        """
        Test get_user_config_path on macOS with default paths.
        """
        with patch.dict(os.environ, {}, clear=True):
            with patch("sys.platform", "darwin"):
                with patch.object(Path, "home", return_value=Path("/Users/test")):
                    path = Uv.get_user_config_path()
                    self.assertEqual(path, Path("/Users/test/.config/uv/uv.toml"))

    def test_filter_out_safety_index(self):
        """
        Test filter_out_safety_index removes safety indexes.
        """
        mock_index = [
            {"url": "https://pypi.safetycli.com/simple/", "default": False},
            {"url": "https://pypi.test-org.safetycli.com/simple/", "default": False},
            {"url": "https://pypi.org/simple", "default": True},
        ]

        mock_container = {"index": mock_index}

        Uv.filter_out_safety_index(mock_container)

        # Check only the non-safety index remains
        self.assertEqual(len(mock_container["index"]), 1)
        self.assertEqual(mock_container["index"][0]["url"], "https://pypi.org/simple")

    def test_configure_system_new_config(self):
        """
        Test configure_system when config file doesn't exist.
        """
        with patch.object(Uv, "get_user_config_path") as mock_path:
            mock_path.return_value = Path("/tmp/uv.toml")

            with patch("pathlib.Path.exists", return_value=False):
                with patch("pathlib.Path.parent") as mock_parent:
                    mock_parent.mkdir = MagicMock()

                    with patch("pathlib.Path.write_text") as mock_write:
                        result = Uv.configure_system(self.org_slug, self.test_console)

                        self.assertEqual(result, Path("/tmp/uv.toml"))
                        mock_parent.mkdir.assert_called_once_with(
                            parents=True, exist_ok=True
                        )
                        mock_write.assert_called_once()

                        # Check written content contains safety index
                        args = mock_write.call_args[0][0]
                        doc = tomlkit.parse(args)
                        self.assertTrue("index" in doc)
                        first_index = doc["index"][0]
                        self.assertEqual(first_index["name"], "safety")
                        self.assertEqual(
                            first_index["url"],
                            ORGANIZATION_REPOSITORY_URL.format(self.org_slug),
                        )

    def test_configure_system_existing_config(self):
        """
        Test configure_system when config file already exists.
        """
        # Create a mock config with an existing index including a safety index
        mock_content = """
[[index]]
url = "https://pypi.org/simple"
default = true

[[index]]
url = "https://pypi.old-org.safetycli.com/simple/"
default = false
name = "safety"
        """

        mock_doc = tomlkit.parse(mock_content)
        config_path = Path("/tmp/uv.toml")

        with patch.object(
            Uv, "get_user_config_path", return_value=config_path
        ) as mock_get_path:
            with patch("pathlib.Path.exists", return_value=True) as mock_exists:
                with patch(
                    "pathlib.Path.read_text", return_value=mock_content
                ) as mock_read:
                    with patch("tomlkit.loads", return_value=mock_doc) as mock_loads:
                        with patch("safety.tool.uv.main.backup_file") as mock_backup:
                            with patch("pathlib.Path.write_text") as mock_write:
                                with patch.object(
                                    Uv, "filter_out_safety_index"
                                ) as mock_filter:
                                    result = Uv.configure_system(
                                        self.org_slug, self.test_console
                                    )

                                    self.assertEqual(result, config_path)

                                    mock_get_path.assert_called_once()
                                    mock_exists.assert_called_once()
                                    mock_read.assert_called_once()
                                    mock_loads.assert_called_once_with(mock_content)
                                    mock_backup.assert_called_once_with(config_path)
                                    mock_filter.assert_called_once()
                                    mock_write.assert_called_once()

                                    written_content = mock_write.call_args[0][0]
                                    written_doc = tomlkit.parse(written_content)

                                    safety_found = False
                                    for index_item in written_doc["index"]:
                                        if index_item.get("name") == "safety":
                                            safety_found = True
                                            self.assertIn(
                                                "safetycli.com", index_item["url"]
                                            )
                                            self.assertEqual(
                                                index_item["default"], False
                                            )

                                    self.assertTrue(
                                        safety_found, "Safety index not found in config"
                                    )

    def test_configure_system_error_handling(self):
        """
        Test configure_system error handling.
        """
        with patch.object(Uv, "get_user_config_path") as mock_path:
            mock_path.return_value = Path("/tmp/uv.toml")

            with patch("pathlib.Path.exists", side_effect=Exception("Test error")):
                result = Uv.configure_system(self.org_slug, self.test_console)
                self.assertIsNone(result)

    def test_reset_system(self):
        """
        Test reset_system removes safety indexes from config.
        """
        mock_content = """
[[index]]
url = "https://pypi.org/simple"
default = true

[[index]]
url = "https://pypi.test-org.safetycli.com/simple/"
default = false
name = "safety"
        """

        mock_doc = tomlkit.parse(mock_content)
        config_path = Path("/tmp/uv.toml")

        with patch.object(Uv, "get_user_config_path", return_value=config_path):
            with patch("pathlib.Path.exists", return_value=True):
                with patch(
                    "pathlib.Path.read_text", return_value=mock_content
                ) as mock_read:
                    with patch("tomlkit.loads", return_value=mock_doc) as mock_loads:
                        with patch("safety.tool.uv.main.backup_file") as mock_backup:
                            with patch("pathlib.Path.write_text") as mock_write:
                                with patch.object(
                                    Uv,
                                    "filter_out_safety_index",
                                    wraps=Uv.filter_out_safety_index,
                                ) as spy_filter:
                                    Uv.reset_system(self.test_console)

                                    mock_backup.assert_called_once_with(config_path)
                                    mock_read.assert_called_once()
                                    mock_loads.assert_called_once_with(mock_content)
                                    spy_filter.assert_called_once()
                                    mock_write.assert_called_once()

                                    written_content = mock_write.call_args[0][0]
                                    written_doc = tomlkit.parse(written_content)

                                    for index_item in written_doc["index"]:
                                        self.assertNotIn(
                                            ".safetycli.com", index_item.get("url", "")
                                        )

                                    self.assertEqual(len(written_doc["index"]), 1)
                                    self.assertEqual(
                                        written_doc["index"][0]["url"],
                                        "https://pypi.org/simple",
                                    )

    def test_reset_system_error_handling(self):
        """
        Test reset_system error handling.
        """
        with patch.object(Uv, "get_user_config_path") as mock_path:
            mock_path.return_value = Path("/tmp/uv.toml")

            with patch("pathlib.Path.exists", side_effect=Exception("Test error")):
                Uv.reset_system(self.test_console)

    def test_backup_file(self):
        """
        Test backup_file functionality.
        """
        test_path = Path("/tmp/test.toml")

        with patch("pathlib.Path.exists", return_value=True):
            with patch("shutil.copy2") as mock_copy:
                backup_file(test_path)

                mock_copy.assert_called_once_with(
                    test_path, test_path.with_name(f"{test_path.name}.backup")
                )

    def test_backup_file_nonexistent(self):
        """
        Test backup_file when file doesn't exist.
        """
        test_path = Path("/tmp/test.toml")

        with patch("pathlib.Path.exists", return_value=False):
            with patch("shutil.copy2") as mock_copy:
                backup_file(test_path)

                mock_copy.assert_not_called()
