import logging
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

logger = logging.getLogger(__name__)


class Poetry:
    @classmethod
    def is_installed(cls) -> bool:
        """
        Checks if the Poetry program is installed

        Returns:
            True if Poetry is installed on system, or false otherwise
        """
        return shutil.which("poetry") is not None

    @classmethod
    def is_poetry_project_file(cls, file: Path) -> bool:
        try:
            cfg = tomllib.loads(file.read_text())
            return cfg.get("build-system", {}).get("requires") in [
                ["poetry-core"],
                "poetry-core",
            ]
        except (IOError, ValueError):
            return False

    @classmethod
    def configure_pyproject(
        cls,
        file: Path,
        org_slug: Optional[str],
        project_id: Optional[str] = None,
        console: Console = main_console,
    ) -> Optional[Path]:
        """
        Configures index url for specified requirements file.

        Args:
            file (Path): Path to requirements.txt file.
            org_slug (Optional[str]): Organization slug.
            project_id (Optional[str]): Project ID.
            console (Console): Console instance.
        """
        if not cls.is_installed():
            logger.error("Poetry is not installed.")
            return None

        repository_url = (
            ORGANIZATION_REPOSITORY_URL.format(org_slug)
            if org_slug
            else PUBLIC_REPOSITORY_URL
        )
        if project_id:
            repository_url = repository_url + urllib.parse.urlencode(
                {"project-id": project_id}
            )
        result = subprocess.run(
            [
                get_unwrapped_command(name="poetry"),
                "source",
                "add",
                "safety",
                repository_url,
            ],
            capture_output=True,
        )

        if result.returncode != 0:
            logger.error(f"Failed to configure {file} file")
            return None

        return file
