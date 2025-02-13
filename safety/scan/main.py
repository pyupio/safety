import logging
import os
import platform
import time
from pathlib import Path
from typing import Any, Dict, Generator, Optional, Set, Tuple

from pydantic import ValidationError
from safety_schemas.models import (
    ConfigModel,
    FileType,
    PolicyFileModel,
    PolicySource,
    ScanType,
    Stage,
)

from safety.scan.util import GIT

from ..auth.utils import SafetyAuthSession
from ..errors import SafetyError
from .ecosystems.base import InspectableFile
from .ecosystems.target import InspectableFileContext
from .models import ScanExport

LOG = logging.getLogger(__name__)


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

def build_meta(target: Path) -> Dict[str, Any]:
    """
    Build the meta JSON object for a file.

    Args:
        target (Path): The path of the repository.

    Returns:
        Dict[str, Any]: The metadata dictionary.
    """
    target_obj = target.resolve()
    git_utils = GIT(target_obj)

    git_data = git_utils.build_git_data()
    git_metadata = {
        "branch": git_data.branch if git_data else None,
        "commit": git_data.commit if git_data else None,
        "dirty": git_data.dirty if git_data else None,
        "tag": git_data.tag if git_data else None,
        "origin": git_data.origin if git_data else None,
    }

    os_metadata = {
        "type": os.environ.get("SAFETY_OS_TYPE", None) or platform.system(),
        "release": os.environ.get("SAFETY_OS_RELEASE", None) or platform.release(),
        "description": os.environ.get("SAFETY_OS_DESCRIPTION", None) or platform.platform(),
    }

    python_metadata= {
        "version": platform.python_version(),
    }

    client_metadata = {
        "version": get_version(),
    }

    return {
        "target": str(target),
        "os": os_metadata,
        "git": git_metadata,
        "python": python_metadata,
        "client": client_metadata,
    }

def process_files(paths: Dict[str, Set[Path]], config: Optional[ConfigModel] = None, use_server_matching: bool = False, obj=None, target=Path(".")) -> Generator[Tuple[Path, InspectableFile], None, None]:
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

    # old GET implementation
    if not use_server_matching:
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

    # new POST implementation
    else:
        files = []
        meta = build_meta(target)
        for file_type_key, f_paths in paths.items():
            file_type = FileType(file_type_key)
            if not file_type or not file_type.ecosystem:
                continue
            for f_path in f_paths:
                relative_path = os.path.relpath(f_path, start=os.getcwd())
                # Read the file content
                try:
                    with open(f_path, "r") as file:
                        content = file.read()
                except Exception as e:
                    LOG.error(f"Error reading file {f_path}: {e}")
                    continue
                # Append metadata to the payload
                files.append({
                    "name": relative_path,
                    "content": content,
                })

        # Prepare the payload with metadata at the top level
        payload = {
            "meta": meta,
            "files": files,
        }

        response = obj.auth.client.upload_requirements(payload)

        if response.status_code == 200:
            LOG.info("Scan Payload successfully sent to the API.")
        else:
            LOG.error(f"Failed to send scan payload to the API. Status code: {response.status_code}")
            LOG.error(f"Response: {response.text}")
