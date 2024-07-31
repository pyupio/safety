import configparser
import logging
from pathlib import Path
import re
import time
from typing import Any, Dict, Generator, Optional, Set, Tuple, Union
from pydantic import ValidationError
import typer
from ..auth.utils import SafetyAuthSession
from ..errors import SafetyError
from .ecosystems.base import InspectableFile
from .ecosystems.target import InspectableFileContext
from .models import ScanExport, UnverifiedProjectModel

from safety_schemas.models import FileType, PolicyFileModel, PolicySource, \
    ConfigModel, Stage, ProjectModel, ScanType


LOG = logging.getLogger(__name__)

PROJECT_CONFIG = ".safety-project.ini"
PROJECT_CONFIG_SECTION = "project"
PROJECT_CONFIG_ID = "id"
PROJECT_CONFIG_URL = "url"
PROJECT_CONFIG_NAME = "name"


def download_policy(session: SafetyAuthSession, project_id: str, stage: Stage, branch: Optional[str]) -> Optional[PolicyFileModel]:
    """
    Downloads the policy file from the cloud for the given project and stage.

    Args:
        session (SafetyAuthSession): SafetyAuthSession object for authentication.
        project_id (str): The ID of the project.
        stage (Stage): The stage of the project.
        branch (Optional[str]): The branch of the project (optional).

    Returns:
        Optional[PolicyFileModel]: PolicyFileModel object if successful, otherwise None.
    """
    result = session.download_policy(project_id=project_id, stage=stage,
                                     branch=branch)

    if result and "uuid" in result and result["uuid"]:
        LOG.debug(f"Loading CLOUD policy file {result['uuid']} from cloud.")
        LOG.debug(result)
        uuid = result["uuid"]
        err = f'Unable to load the Safety Policy file ("{uuid}"), from cloud.'
        config = None

        try:
            yml_raw = result["settings"]
            # TODO: Move this to safety_schemas
            parse = "parse_obj"
            import importlib
            module_name = (
                "safety_schemas." "config.schemas." f"v3_0.main"
            )
            module = importlib.import_module(module_name)
            config_model = module.Config
            validated_policy_file = getattr(config_model, parse)(yml_raw)
            config = ConfigModel.from_v30(obj=validated_policy_file)
        except ValidationError as e:
            LOG.error(f"Failed to parse policy file {uuid}.", exc_info=True)
            raise SafetyError(f"{err}, details: {e}")
        except ValueError as e:
            LOG.error(f"Wrong YML file for policy file {uuid}.", exc_info=True)
            raise SafetyError(f"{err}, details: {e}")

        return PolicyFileModel(id=result["uuid"],
                                source=PolicySource.cloud,
                                location=None,
                                config=config)

    return None


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
    id = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_ID, fallback=None)
    url = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_URL, fallback=None)
    name = config.get(PROJECT_CONFIG_SECTION, PROJECT_CONFIG_NAME, fallback=None)
    created = True
    if id:
        created = False

    return UnverifiedProjectModel(id=id, url_path=url,
                                  name=name, project_path=project_path,
                                  created=created)


def save_project_info(project: ProjectModel, project_path: Path) -> None:
    """
    Saves the project information to the configuration file.

    Args:
        project (ProjectModel): The ProjectModel object containing project information.
        project_path (Path): The path to the configuration file.
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

    with open(project_path, 'w') as configfile:
        config.write(configfile)


def load_policy_file(path: Path) -> Optional[PolicyFileModel]:
    """
    Loads a policy file from the specified path.

    Args:
        path (Path): The path to the policy file.

    Returns:
        Optional[PolicyFileModel]: PolicyFileModel object if successful, otherwise None.
    """
    config = None

    if not path or not path.exists():
        return None

    err = f'Unable to load the Safety Policy file ("{path}"), this command ' \
        "only supports version 3.0"

    try:
        config = ConfigModel.parse_policy_file(raw_report=path)
    except ValidationError as e:
        LOG.error(f"Failed to parse policy file {path}.", exc_info=True)
        raise SafetyError(f"{err}, details: {e}")
    except ValueError as e:
        LOG.error(f"Wrong YML file for policy file {path}.", exc_info=True)
        raise SafetyError(f"{err}, details: {e}")

    return PolicyFileModel(id=str(path), source=PolicySource.local,
                           location=path, config=config)


def resolve_policy(local_policy: Optional[PolicyFileModel], cloud_policy: Optional[PolicyFileModel]) -> Optional[PolicyFileModel]:
    """
    Resolves the policy to be used, preferring cloud policy over local policy.

    Args:
        local_policy (Optional[PolicyFileModel]): The local policy file model (optional).
        cloud_policy (Optional[PolicyFileModel]): The cloud policy file model (optional).

    Returns:
        Optional[PolicyFileModel]: The resolved PolicyFileModel object.
    """
    policy = None

    if cloud_policy:
        policy = cloud_policy
    elif local_policy:
        policy = local_policy

    return policy


def save_report_as(scan_type: ScanType, export_type: ScanExport, at: Path, report: Any) -> None:
    """
    Saves the scan report to the specified location.

    Args:
        scan_type (ScanType): The type of scan.
        export_type (ScanExport): The type of export.
        at (Path): The path to save the report.
        report (Any): The report content.
    """
    tag = int(time.time())

    if at.is_dir():
        at = at / Path(
            f"{scan_type.value}-{export_type.get_default_file_name(tag=tag)}")

    with open(at, 'w+') as report_file:
        report_file.write(report)


def process_files(paths: Dict[str, Set[Path]], config: Optional[ConfigModel] = None) -> Generator[Tuple[Path, InspectableFile], None, None]:
    """
    Processes the files and yields each file path along with its inspectable file.

    Args:
        paths (Dict[str, Set[Path]]): A dictionary of file paths by file type.
        config (Optional[ConfigModel]): The configuration model (optional).

    Yields:
        Tuple[Path, InspectableFile]: A tuple of file path and inspectable file.
    """
    if not config:
        config = ConfigModel()

    for file_type_key, f_paths in paths.items():
        file_type = FileType(file_type_key)
        if not file_type or not file_type.ecosystem:
            continue
        for f_path in f_paths:
            with InspectableFileContext(f_path, file_type=file_type) as inspectable_file:
                if inspectable_file and inspectable_file.file_type:
                    inspectable_file.inspect(config=config)
                    inspectable_file.remediate()
                    yield f_path, inspectable_file
