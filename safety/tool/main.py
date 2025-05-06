from typing import Any, Dict, List, Tuple
import os.path
from pathlib import Path
from typing import Optional

from safety.constants import USER_CONFIG_DIR
from safety.tool.utils import (
    PipConfigurator,
    PipRequirementsConfigurator,
    PoetryConfigurator,
    PoetryPyprojectConfigurator,
    UvConfigurator,
    UvPyprojectConfigurator,
    is_os_supported,
)

from safety_schemas.models.events.types import ToolType

from .interceptors import create_interceptor

import logging

logger = logging.getLogger(__name__)


def find_local_tool_files(directory: Path) -> List[Path]:
    configurators = [
        PipRequirementsConfigurator(),
        PoetryPyprojectConfigurator(),
        UvPyprojectConfigurator(),
    ]

    results = []

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    results.append(file)

    return results


def configure_system(org_slug: Optional[str]) -> List[Tuple[ToolType, Optional[Path]]]:
    configurators: List[Tuple[ToolType, Any, Dict[str, Any]]] = [
        (ToolType.PIP, PipConfigurator(), {"org_slug": org_slug}),
        (ToolType.POETRY, PoetryConfigurator(), {"org_slug": org_slug}),
        (ToolType.UV, UvConfigurator(), {"org_slug": org_slug}),
    ]

    results = []
    for tool_type, configurator, kwargs in configurators:
        result = configurator.configure(**kwargs)
        results.append((tool_type, result))
    return results


def reset_system():
    configurators = [PipConfigurator(), PoetryConfigurator(), UvConfigurator()]

    for configurator in configurators:
        configurator.reset()


def configure_alias() -> Optional[List[Tuple[ToolType, Optional[Path]]]]:
    if not is_os_supported():
        logger.warning("OS not supported for alias configuration.")
        return None

    interceptor = create_interceptor()
    result = interceptor.install_interceptors()

    if result:
        config = Path(f"{USER_CONFIG_DIR}/.safety_profile")
        return [
            (ToolType.PIP, config),
            (ToolType.POETRY, config),
            (ToolType.UV, config),
        ]

    return [(ToolType.PIP, None), (ToolType.POETRY, None), (ToolType.UV, None)]


def configure_local_directory(
    directory: Path, org_slug: Optional[str], project_id: Optional[str]
):
    configurators = [
        PipRequirementsConfigurator(),
        PoetryPyprojectConfigurator(),
        UvPyprojectConfigurator(),
    ]

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    configurator.configure(file, org_slug, project_id)
