from typing import List, Optional
from pathlib import Path

from .main import Uv
import typer
from safety.tool.auth import index_credentials
from ..base import BaseCommand
from ..environment_diff import EnvironmentDiffTracker, PipEnvironmentDiffTracker
from ..mixins import InstallationAuditMixin
from safety_schemas.models.events.types import ToolType
from safety.models import ToolResult
from .parser import UvParser


class UvCommand(BaseCommand):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def get_command_name(self) -> List[str]:
        return ["uv"]

    def get_diff_tracker(self) -> "EnvironmentDiffTracker":
        return PipEnvironmentDiffTracker()

    def get_tool_type(self) -> ToolType:
        return ToolType.UV

    def get_package_list_command(self) -> List[str]:
        # uv --active flag would ignore the uv project virtual environment,
        # by passing the --active flag then we can list the packages for the
        # correct environment.
        active = (
            ["--active"]
            if self._intention and self._intention.options.get("active")
            else []
        )
        list_pkgs = Path(__file__).parent / "list_pkgs.py"

        # --no-project flag is used to avoid uv to create the venv or lock file if it doesn't exist
        return [
            *self.get_command_name(),
            "run",
            *active,
            "--no-sync",
            "python",
            str(list_pkgs),
        ]

    @classmethod
    def from_args(cls, args: List[str], **kwargs):
        if uv_intention := UvParser().parse(args):
            kwargs["intention"] = uv_intention

            if uv_intention.modifies_packages():
                return AuditableUvCommand(args, **kwargs)

        return UvCommand(args, **kwargs)


class AuditableUvCommand(UvCommand, InstallationAuditMixin):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.__index_url = None

    def before(self, ctx: typer.Context):
        super().before(ctx)
        args: List[Optional[str]] = self._args.copy()  # type: ignore

        if self._intention:
            if index_opt := self._intention.options.get(
                "index-url"
            ) or self._intention.options.get("i"):
                index_value = index_opt["value"]

                if index_value and index_value.startswith("https://pkgs.safetycli.com"):
                    self.__index_url = index_value

                arg_index = index_opt["arg_index"]
                value_index = index_opt["value_index"]

                if (
                    arg_index
                    and value_index
                    and arg_index < len(args)
                    and value_index < len(args)
                ):
                    args[arg_index] = None
                    args[value_index] = None

        self._args = [arg for arg in args if arg is not None]

    def after(self, ctx: typer.Context, result: ToolResult):
        super().after(ctx, result)
        self.handle_installation_audit(ctx, result)

    def env(self, ctx: typer.Context) -> dict:
        env = super().env(ctx)

        default_index_url = Uv.build_index_url(ctx, self.__index_url)
        # uv config precedence:
        # 1. Command line args -> We rewrite the args if the a default index is provided via command line args.
        # 2. Environment variables -> We set the default index to the Safety index
        # 3. Config files

        env.update(
            {
                # Default index URL
                # When the package manager is wrapped, we provide a default index so the search always falls back to the Safety index
                # UV_INDEX_URL is deprecated by UV, we comment it out to avoid a anoying warning, UV_DEFAULT_INDEX is available since uv 0.4.23
                # So we decided to support only UV_DEFAULT_INDEX, as we don't inject the uv version in the command pipeline yet.
                #
                # "UV_INDEX_URL": default_index_url,
                #
                "UV_DEFAULT_INDEX": default_index_url,
                # Credentials for the named index in case of being set in the pyproject.toml
                "UV_INDEX_SAFETY_USERNAME": "user",
                "UV_INDEX_SAFETY_PASSWORD": index_credentials(ctx),
            }
        )

        return env
