import shutil
import subprocess
from pathlib import Path
import sys
from typing import Optional

from rich.console import Console
import urllib.parse

from safety.console import main_console
from safety.tool.constants import PUBLIC_REPOSITORY_URL, ORGANIZATION_REPOSITORY_URL
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
        except (IOError, ValueError):
            return False

    @classmethod
    def configure_pyproject(
        cls,
        file: Path,
        org_slug: Optional[str],
        project_id: str,
        console: Console = main_console,
    ) -> None:
        """
        Configures index url for specified requirements file.

        Args:
            file (Path): Path to requirements.txt file.
            console (Console): Console instance.
        """
        if not cls.is_installed():
            console.log("Poetry is not installed.")

        repository_url = (
            ORGANIZATION_REPOSITORY_URL.format(org_slug)
            if org_slug
            else PUBLIC_REPOSITORY_URL
        )
        repository_url = repository_url + urllib.parse.urlencode(
            {"project-id": project_id}
        )
        subprocess.run(
            [
                get_unwrapped_command(name="poetry"),
                "source",
                "add",
                "safety",
                repository_url,
            ],
            capture_output=True,
        )
        console.print(f"Configured {file} file")
