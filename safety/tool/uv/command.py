from typing import List

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
        return [*self.get_command_name(), "pip", "list", "--format=json"]

    def env(self, ctx: typer.Context) -> dict:
        env = super().env(ctx)

        env.update(
            {
                "UV_INDEX_SAFETY_USERNAME": "user",
                "UV_INDEX_SAFETY_PASSWORD": index_credentials(ctx),
            }
        )

        return env

    @classmethod
    def from_args(cls, args: List[str], **kwargs):
        if uv_intention := UvParser().parse(args):
            kwargs["intention"] = uv_intention

            if uv_intention.modifies_packages():
                return AuditableUvCommand(args, **kwargs)

        return UvCommand(args, **kwargs)


class AuditableUvCommand(UvCommand, InstallationAuditMixin):
    def after(self, ctx: typer.Context, result: ToolResult):
        super().after(ctx, result)
        self.handle_installation_audit(ctx, result)
