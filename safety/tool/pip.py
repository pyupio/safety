import base64
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import typer
from rich.console import Console

from safety.tool.constants import PUBLIC_REPOSITORY_URL, ORGANIZATION_REPOSITORY_URL
from safety.tool.resolver import get_unwrapped_command

from safety.console import main_console


logger = logging.getLogger(__name__)


class Pip:
    @classmethod
    def is_installed(cls) -> bool:
        """
        Checks if the PIP program is installed

        Returns:
            True if PIP is installed on system, or false otherwise
        """
        return shutil.which("pip") is not None

    @classmethod
    def configure_requirements(
        cls,
        file: Path,
        org_slug: Optional[str],
        console: Console = main_console,
    ) -> Optional[Path]:
        """
        Configures Safety index url for specified requirements file.

        Args:
            file (Path): Path to requirements.txt file.
            org_slug (str): Organization slug.
            console (Console): Console instance.
        """

        with open(file, "r+") as f:
            content = f.read()

            repository_url = (
                ORGANIZATION_REPOSITORY_URL.format(org_slug)
                if org_slug
                else PUBLIC_REPOSITORY_URL
            )
            index_config = f"-i {repository_url}\n"
            if content.find(index_config) == -1:
                f.seek(0)
                f.write(index_config + content)

                logger.info(f"Configured {file} file")
                return file
            else:
                logger.info(f"{file} is already configured. Skipping.")

        return None

    @classmethod
    def configure_system(
        cls, org_slug: Optional[str], console: Console = main_console
    ) -> Optional[Path]:
        """
        Configures PIP system to use to Safety index url.
        """
        try:
            repository_url = (
                ORGANIZATION_REPOSITORY_URL.format(org_slug)
                if org_slug
                else PUBLIC_REPOSITORY_URL
            )
            result = subprocess.run(
                [
                    get_unwrapped_command(name="pip"),
                    "config",
                    "set",
                    "global.index-url",
                    repository_url,
                ],
                capture_output=True,
            )

            if result.returncode != 0:
                logger.error(
                    f"Failed to configure PIP global settings: {result.stderr.decode('utf-8')}"
                )
                return None

            output = result.stdout.decode("utf-8")
            match = re.search(r"Writing to (.+)", output)

            if match:
                config_file_path = match.group(1).strip()
                return Path(config_file_path)

            logger.error("Failed to match the config file path written by pip.")
            return Path()
        except Exception:
            logger.exception("Failed to configure PIP global settings.")

        return None

    @classmethod
    def reset_system(cls, console: Console = main_console):
        # TODO: Move this logic and implement it in a more robust way
        try:
            subprocess.run(
                [
                    get_unwrapped_command(name="pip"),
                    "config",
                    "unset",
                    "global.index-url",
                ],
                capture_output=True,
            )
        except Exception:
            console.print("Failed to reset PIP global settings.")

    @classmethod
    def index_credentials(cls, ctx: typer.Context):
        api_key = None
        token = None

        if auth := getattr(ctx.obj, "auth", None):
            client = auth.client
            token = client.token.get("access_token") if client.token else None
            api_key = client.api_key

        auth_envelop = json.dumps(
            {
                "version": "1.0",
                "access_token": token,
                "api_key": api_key,
                "project_id": ctx.obj.project.id if ctx.obj.project else None,
            }
        )
        return base64.urlsafe_b64encode(auth_envelop.encode("utf-8")).decode("utf-8")

    @classmethod
    def default_index_url(cls) -> str:
        return "https://pypi.org/simple/"

    @classmethod
    def build_index_url(cls, ctx: typer.Context, index_url: Optional[str]) -> str:
        if index_url is None:
            index_url = PUBLIC_REPOSITORY_URL

        url = urlsplit(index_url)

        encoded_auth = cls.index_credentials(ctx)
        netloc = f"user:{encoded_auth}@{url.netloc}"

        if type(url.netloc) is bytes:
            url = url._replace(netloc=netloc.encode("utf-8"))
        elif type(url.netloc) is str:
            url = url._replace(netloc=netloc)

        return urlunsplit(url)
