import os.path
from pathlib import Path
from typing import Optional

from safety.console import main_console as console
from safety.tool.utils import (
    PipConfigurator,
    PipRequirementsConfigurator,
    PoetryPyprojectConfigurator,
    is_os_supported,
)

from .interceptors import create_interceptor


def has_local_tool_files(directory: Path) -> bool:
    configurators = [PipRequirementsConfigurator(), PoetryPyprojectConfigurator()]

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    return True

    return False


def configure_system(org_slug: Optional[str]):
    configurators = [PipConfigurator()]

    for configurator in configurators:
        configurator.configure(org_slug)


def reset_system():
    configurators = [PipConfigurator()]

    for configurator in configurators:
        configurator.reset()


def configure_alias():
    if not is_os_supported():
        return

    interceptor = create_interceptor()
    interceptor.install_interceptors()

    console.print("Configured PIP alias")


def configure_local_directory(
    directory: Path, org_slug: Optional[str], project_id: Optional[str]
):
    configurators = [PipRequirementsConfigurator(), PoetryPyprojectConfigurator()]

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    configurator.configure(file, org_slug, project_id)
