import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import typer
from rich.console import Console

from safety.tool.resolver import get_unwrapped_command

from safety.console import main_console

REPOSITORY_URL = "https://pkgs.safetycli.com/repository/public/pypi/simple/"


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
    def configure_requirements(cls, file: Path, console: Optional[Console] = main_console) -> None:
        """
        Configures Safety index url for specified requirements file.

        Args:
            file (Path): Path to requirements.txt file.
            console (Console): Console instance.
        """

        with open(file, "r+") as f:
            content = f.read()

            index_config = f"-i {REPOSITORY_URL}\n"
            if content.find(index_config) == -1:
                f.seek(0)
                f.write(index_config + content)

                console.print(f"Configured {file} file")
            else:
                console.print(f"{file} is already configured. Skipping.")

    @classmethod
    def configure_system(cls, console: Optional[Console] = main_console):
        """
        Configures PIP system to use to Safety index url.
        """
        try:
            subprocess.run([get_unwrapped_command(name="pip"), "config", "set", "global.index-url", REPOSITORY_URL], capture_output=True)
            console.print("Configured PIP global settings")
        except Exception as e:
            console.print("Failed to configure PIP global settings.")

    @classmethod
    def reset_system(cls, console: Optional[Console] = main_console):
        # TODO: Move this logic and implement it in a more robust way
        try:
            subprocess.run([get_unwrapped_command(name="pip"), "config", "unset", "global.index-url"], capture_output=True)
        except Exception as e:
            console.print("Failed to reset PIP global settings.")
            

    @classmethod
    def index_credentials(cls, ctx: typer.Context):
        auth_envelop = json.dumps({
            "version": "1.0",
            "access_token": ctx.obj.auth.client.token["access_token"],
            "api_key": ctx.obj.auth.client.api_key,
            "project_id": ctx.obj.project.id if ctx.obj.project else None,
        })
        return base64.urlsafe_b64encode(auth_envelop.encode("utf-8")).decode("utf-8")

    @classmethod
    def default_index_url(cls) -> str:
        return "https://pypi.org/simple/"

    @classmethod
    def build_index_url(cls, ctx: typer.Context, index_url: Optional[str]) -> str:
        if index_url is None:
            index_url = REPOSITORY_URL

        url = urlsplit(index_url)

        encoded_auth = cls.index_credentials(ctx)
        netloc = f'user:{encoded_auth}@{url.netloc}'

        if type(url.netloc) == bytes:
            url = url._replace(netloc=netloc.encode("utf-8"))
        elif type(url.netloc) == str:
            url = url._replace(netloc=netloc)

        return urlunsplit(url)
