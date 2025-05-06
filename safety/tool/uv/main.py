import logging
import os
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, Optional
import tomlkit

from rich.console import Console
from safety.console import main_console
from safety.tool.constants import (
    ORGANIZATION_REPOSITORY_URL,
    PUBLIC_REPOSITORY_URL,
    PROJECT_REPOSITORY_URL,
)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

logger = logging.getLogger(__name__)


def backup_file(path: Path) -> None:
    """
    Create backup of file if it exists
    """
    if path.exists():
        backup_path = path.with_name(f"{path.name}.backup")
        shutil.copy2(path, backup_path)


class Uv:
    @classmethod
    def is_installed(cls) -> bool:
        """
        Checks if the UV program is installed

        Returns:
            True if UV is installed on system, or false otherwise
        """
        return shutil.which("uv") is not None

    @classmethod
    def is_uv_project_file(cls, file: Path) -> bool:
        try:
            cfg = tomllib.loads(file.read_text())
            return (
                cfg.get("tool", {}).get("uv") is not None
                or (file.parent / "uv.lock").exists()
            )
        except (IOError, ValueError):
            return False

    @classmethod
    def configure_pyproject(
        cls,
        file: Path,
        org_slug: Optional[str],
        project_id: Optional[str] = None,
        console: Console = main_console,
    ) -> Optional[Path]:
        """
        Configures index url for specified pyproject.toml file.

        Args:
            file (Path): Path to pyproject.toml file.
            org_slug (Optional[str]): Organization slug.
            project_id (Optional[str]): Project ID.
            console (Console): Console instance.
        """
        if not cls.is_installed():
            logger.error("UV is not installed.")
            return None

        repository_url = (
            PROJECT_REPOSITORY_URL.format(org_slug, project_id)
            if project_id and org_slug
            else (
                ORGANIZATION_REPOSITORY_URL.format(org_slug)
                if org_slug
                else PUBLIC_REPOSITORY_URL
            )
        )
        try:
            content = file.read_text()
            doc: Dict[str, Any] = tomlkit.loads(content)

            if "tool" not in doc:
                doc["tool"] = tomlkit.table()
            if "uv" not in doc["tool"]:  # type: ignore
                doc["tool"]["uv"] = tomlkit.table()  # type: ignore
            if "index" not in doc["tool"]["uv"]:  # type: ignore
                doc["tool"]["uv"]["index"] = tomlkit.aot()  # type: ignore

            index_container = doc["tool"]["uv"]  # type: ignore
            cls.filter_out_safety_index(index_container)

            safety_index = {
                "name": "safety",
                "url": repository_url,
                # In UV default:
                # True = lowest priority
                # False = highest priority
                "default": False,
            }
            non_safety_indexes = (
                doc.get("tool", {}).get("uv", {}).get("index", tomlkit.aot())
            )

            # Add safety index as first priority
            index_container["index"] = tomlkit.aot()  # type: ignore
            index_container["index"].append(safety_index)  # type: ignore
            index_container["index"].extend(non_safety_indexes)  # type: ignore

            # Write back to file
            file.write_text(tomlkit.dumps(doc))
            return file

        except (IOError, ValueError, Exception) as e:
            logger.error(f"Failed to configure {file} file: {e}")

        return None

    @classmethod
    def get_user_config_path(cls) -> Path:
        """
        Returns the path to the user config file for UV.

        This logic is based on the uv documentation:
        https://docs.astral.sh/uv/configuration/files/

        "uv will also discover user-level configuration at
        ~/.config/uv/uv.toml (or $XDG_CONFIG_HOME/uv/uv.toml) on macOS and Linux,
        or %APPDATA%\\uv\\uv.toml on Windows; ..."

        Returns:
            Path: The path to the user config file.
        """
        if sys.platform == "win32":
            return Path(os.environ.get("APPDATA", ""), "uv", "uv.toml")
        else:
            xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
            if xdg_config_home:
                return Path(xdg_config_home, "uv", "uv.toml")
            else:
                return Path(Path.home(), ".config", "uv", "uv.toml")

    @classmethod
    def filter_out_safety_index(cls, index_container: Any):
        if "index" not in index_container:
            return

        indexes = list(index_container["index"])
        index_container["index"] = tomlkit.aot()

        for index in indexes:
            index_url = index.get("url", "")

            if ".safetycli.com" in index_url:
                continue

            index_container["index"].append(index)

    @classmethod
    def configure_system(
        cls, org_slug: Optional[str], console: Console = main_console
    ) -> Optional[Path]:
        """
        Configures UV system to use to Safety index url.
        """
        try:
            repository_url = (
                ORGANIZATION_REPOSITORY_URL.format(org_slug)
                if org_slug
                else PUBLIC_REPOSITORY_URL
            )

            user_config_path = cls.get_user_config_path()

            if not user_config_path.exists():
                user_config_path.parent.mkdir(parents=True, exist_ok=True)
                content = ""
            else:
                backup_file(user_config_path)
                content = user_config_path.read_text()

            doc = tomlkit.loads(content)
            if "index" not in doc:
                doc["index"] = tomlkit.aot()
            cls.filter_out_safety_index(index_container=doc)

            safety_index = tomlkit.aot()
            safety_index.append(
                {
                    "name": "safety",
                    "url": repository_url,
                    # In UV default:
                    # True = lowest priority
                    # False = highest priority
                    "default": False,
                }
            )

            non_safety_indexes = doc.get("index", tomlkit.aot())

            # Add safety index as first priority
            doc["index"] = tomlkit.aot()
            doc.append("index", safety_index)
            doc.append("index", non_safety_indexes)

            user_config_path.write_text(tomlkit.dumps(doc))
            return user_config_path

        except Exception as e:
            logger.error(f"Failed to configure UV system: {e}")
            return None

    @classmethod
    def reset_system(cls, console: Console = main_console):
        try:
            user_config_path = cls.get_user_config_path()
            if user_config_path.exists():
                backup_file(user_config_path)
                content = user_config_path.read_text()
                doc = tomlkit.loads(content)
                cls.filter_out_safety_index(index_container=doc)
                user_config_path.write_text(tomlkit.dumps(doc))
        except Exception as e:
            msg = "Failed to reset UV global settings"
            logger.error(f"{msg}: {e}")
