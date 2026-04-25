import configparser
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Any
from safety_schemas.models import ProjectModel

# Import tomllib for Python 3.11+ with tomli fallback for older versions
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


PROJECT_CONFIG = ".safety-project.ini"
PYPROJECT_CONFIG = "pyproject.toml"
PROJECT_CONFIG_SECTION = "project"
PROJECT_CONFIG_ID = "id"
PROJECT_CONFIG_URL = "url"
PROJECT_CONFIG_NAME = "name"


logger = logging.getLogger(__name__)


@dataclass
class UnverifiedProjectModel:
    """
    Data class representing an unverified project model.
    """

    id: Optional[str]
    project_path: Path
    created: bool
    name: Optional[str] = None
    url_path: Optional[str] = None


def _load_from_pyproject_toml(project_root: Path) -> Optional[Dict[str, Any]]:
    """
    Loads project configuration from pyproject.toml if it exists.

    Args:
        project_root (Path): The root directory of the project.

    Returns:
        Optional[Dict[str, Any]]: Dictionary with 'id', 'url', 'name', and 'path'
                                  if config found, None otherwise.
    """
    pyproject_path = project_root / PYPROJECT_CONFIG

    if not pyproject_path.exists():
        return None

    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        # Check for [tool.safety.project] section
        safety_config = data.get("tool", {}).get("safety", {}).get("project", {})

        if not safety_config:
            return None

        return {
            "id": safety_config.get("id"),
            "url": safety_config.get("url"),
            "name": safety_config.get("name"),
            "path": pyproject_path,
        }
    except Exception as e:
        logger.debug(f"Error reading pyproject.toml: {e}")
        return None


def _load_from_ini(project_root: Path) -> Dict[str, Any]:
    """
    Loads project configuration from .safety-project.ini.

    Args:
        project_root (Path): The root directory of the project.

    Returns:
        Dict[str, Any]: Dictionary with 'id', 'url', 'name', and 'path'.
    """
    config = configparser.ConfigParser()
    project_path = project_root / PROJECT_CONFIG
    config.read(project_path)

    return {
        "id": config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_ID, fallback=None),
        "url": config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_URL, fallback=None),
        "name": config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_NAME, fallback=None),
        "path": project_path,
    }


def load_unverified_project_from_config(project_root: Path) -> UnverifiedProjectModel:
    """
    Loads an unverified project from the configuration file located at the project root.

    Priority:
    1. pyproject.toml ([tool.safety.project] section)
    2. .safety-project.ini (fallback)

    Args:
        project_root (Path): The root directory of the project.

    Returns:
        UnverifiedProjectModel: An instance of UnverifiedProjectModel.
    """
    # Try pyproject.toml first
    config_data = _load_from_pyproject_toml(project_root)

    # Fallback to .safety-project.ini
    if config_data is None:
        config_data = _load_from_ini(project_root)

    id = config_data["id"]
    url = config_data["url"]
    name = config_data["name"]
    project_path = config_data["path"]

    created = True
    if not id:
        created = False

    return UnverifiedProjectModel(
        id=id, url_path=url, name=name, project_path=project_path, created=created
    )


def save_project_info(project: ProjectModel, project_path: Path) -> bool:
    """
    Saves the project information to the configuration file.

    Args:
        project (ProjectModel): The ProjectModel object containing project
                                information.
        project_path (Path): The path to the configuration file.

    Returns:
        bool: True if the project information was saved successfully, False
              otherwise.
    """
    config = configparser.ConfigParser()
    config.read(project_path)

    if PROJECT_CONFIG_SECTION not in config.sections():
        config[PROJECT_CONFIG_SECTION] = {}

    config[PROJECT_CONFIG_SECTION][PROJECT_CONFIG_ID] = project.id
    if project.url_path:
        config[PROJECT_CONFIG_SECTION][PROJECT_CONFIG_URL] = project.url_path
    if project.name:
        config[PROJECT_CONFIG_SECTION][PROJECT_CONFIG_NAME] = project.name

    try:
        with open(project_path, "w") as configfile:
            config.write(configfile)
    except Exception:
        logger.exception("Error saving project info")
        return False

    return True
