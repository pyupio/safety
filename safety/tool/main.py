import os.path
from pathlib import Path

from safety.console import main_console as console
from safety.tool.utils import PipConfigurator, PipRequirementsConfigurator, PoetryPyprojectConfigurator, is_os_supported


def has_local_tool_files(directory: Path) -> bool:
    configurators = [PipRequirementsConfigurator(), PoetryPyprojectConfigurator()]

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    return True

    return False


def configure_system():
    configurators = [PipConfigurator()]

    for configurator in configurators:
        configurator.configure()

def configure_alias():
    if not is_os_supported():
        return

    home = Path.home()
    with open(home / '.profile', "a+") as f:
        content = f.read()

        alias = f'alias pip="safety pip"\n'
        if content.find(alias) == -1:
            f.seek(0)
            f.write(content + '\n' + alias)

            console.print("Configured PIP alias")

def configure_local_directory(directory: Path):
    configurators = [PipRequirementsConfigurator(), PoetryPyprojectConfigurator()]

    for file_name in os.listdir(directory):
        if os.path.isfile(file_name):
            file = Path(file_name)
            for configurator in configurators:
                if configurator.is_supported(file):
                    configurator.configure(file)
