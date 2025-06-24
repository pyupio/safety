import configparser
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from safety_schemas.models import ProjectModel


PROJECT_CONFIG = ".safety-project.ini"
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


def load_unverified_project_from_config(project_root: Path) -> UnverifiedProjectModel:
    """
    Loads an unverified project from the configuration file located at the project root.

    Args:
        project_root (Path): The root directory of the project.

    Returns:
        UnverifiedProjectModel: An instance of UnverifiedProjectModel.
    """
    config = configparser.ConfigParser()
    project_path = project_root / PROJECT_CONFIG
    config.read(project_path)
    id = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_ID, fallback=None)
    url = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_URL, fallback=None)
    name = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_NAME, fallback=None)
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
