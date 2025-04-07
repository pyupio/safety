from typing import List
import os.path
from pathlib import Path
from typing import Optional

from safety.tool.utils import (
    PipConfigurator,
    PipRequirementsConfigurator,
    PoetryPyprojectConfigurator,
    is_os_supported,
)

from .interceptors import create_interceptor

import logging

logger = logging.getLogger(__name__)


def find_local_tool_files(directory: Path) -> List[Path]:
    configurators = [PipRequirementsConfigurator(), PoetryPyprojectConfigurator()]

    results = []

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    results.append(file)

    return results


def configure_system(org_slug: Optional[str]) -> List[Optional[Path]]:
    configurators = [PipConfigurator()]

    results = []
    for configurator in configurators:
        result = configurator.configure(org_slug)
        results.append(result)
    return results


def reset_system():
    configurators = [PipConfigurator()]

    for configurator in configurators:
        configurator.reset()


def configure_alias() -> Optional[List[Optional[Path]]]:
    if not is_os_supported():
        logger.warning("OS not supported for alias configuration.")
        return None

    interceptor = create_interceptor()
    result = interceptor.install_interceptors()

    if result:
        return [Path("~/.safety-profile")]

    return [None]


def configure_local_directory(directory: Path, org_slug: Optional[str]):
    configurators = [PipRequirementsConfigurator(), PoetryPyprojectConfigurator()]

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    configurator.configure(file, org_slug)
