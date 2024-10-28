import shutil
import subprocess
from pathlib import Path
from typing import Optional
import sys

from rich.console import Console

from safety.console import main_console
from safety.tool.pip import REPOSITORY_URL
from safety.tool.resolver import get_unwrapped_command

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

class Poetry:

    @classmethod
    def is_installed(cls) -> bool:
        """
        Checks if the PIP program is installed

        Returns:
            True if PIP is installed on system, or false otherwise
        """
        return shutil.which("poetry") is not None

    @classmethod
    def is_poetry_project_file(cls, file: Path) -> bool:
        try:
            cfg = tomllib.loads(file.read_text())
            return cfg.get("build-system", {}).get("requires") == "poetry-core"
        except (IOError, ValueError) as e:
            return False

    @classmethod
    def configure_pyproject(cls, file: Path, console: Optional[Console] = main_console) -> None:
        """
        Configures index url for specified requirements file.

        Args:
            file (Path): Path to requirements.txt file.
            console (Console): Console instance.
        """
        if not cls.is_installed():
            console.log("Poetry is not installed.")

        subprocess.run([get_unwrapped_command(name="poetry"), "source", "add", "safety", REPOSITORY_URL], capture_output=True)
        console.print(f"Configured {file} file")
