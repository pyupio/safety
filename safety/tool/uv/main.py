import logging
from pathlib import Path
import shutil
import sys
from typing import Optional
import urllib.parse
import tomlkit

from rich.console import Console
from safety.console import main_console
from safety.tool.constants import ORGANIZATION_REPOSITORY_URL, PUBLIC_REPOSITORY_URL

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

logger = logging.getLogger(__name__)


class Uv:
    @classmethod
    def is_installed(cls) -> bool:
        """
        Checks if the UV program is installed

        Returns:
            True if UV is installed on system, or false otherwise
        """
        return shutil.which("uv") is not None

    @classmethod
    def is_uv_project_file(cls, file: Path) -> bool:
        try:
            cfg = tomllib.loads(file.read_text())
            return (
                cfg.get("tool", {}).get("uv") is not None
                or (file.parent / "uv.lock").exists()
            )
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
        Configures index url for specified pyproject.toml file.

        Args:
            file (Path): Path to pyproject.toml file.
            org_slug (Optional[str]): Organization slug.
            project_id (Optional[str]): Project ID.
            console (Console): Console instance.
        """
        if not cls.is_installed():
            console.log("UV is not installed.")

        repository_url = (
            ORGANIZATION_REPOSITORY_URL.format(org_slug)
            if org_slug
            else PUBLIC_REPOSITORY_URL
        )
        if project_id:
            repository_url = repository_url + urllib.parse.urlencode(
                {"project-id": project_id}
            )
        try:
            # Read the file
            content = file.read_text()
            doc = tomlkit.parse(content)

            # Create tool table if it doesn't exist
            if "tool" not in doc:
                doc.add("tool", tomlkit.table())

            tool = doc.get("tool")

            if not tool:
                tool = tomlkit.table()
                doc.add("tool", tool)

            uv = tool.get("uv")

            if not uv:
                uv = tomlkit.table()
                tool.add("uv", uv)

            index = uv.get("index")

            if not index:
                index = tomlkit.table()
                uv.add("index", index)

            index.add("name", "safety")
            index.add("url", repository_url)

            # Write back to file
            file.write_text(tomlkit.dumps(doc))
            return file

        except (IOError, ValueError) as e:
            logger.error(f"Failed to configure {file} file: {e}")

        return None
