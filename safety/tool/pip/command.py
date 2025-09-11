from typing import TYPE_CHECKING, List, Optional

import logging
import typer

from safety.models import ToolResult
from .parser import PipParser

from ..base import BaseCommand
from safety_schemas.models.events.types import ToolType
from ..environment_diff import EnvironmentDiffTracker, PipEnvironmentDiffTracker
from ..mixins import InstallationAuditMixin
from ..utils import Pip


if TYPE_CHECKING:
    from ..environment_diff import EnvironmentDiffTracker

logger = logging.getLogger(__name__)


class PipCommand(BaseCommand):
    """
    Main class for hooks into pip commands.
    """

    def get_tool_type(self) -> ToolType:
        return ToolType.PIP

    def get_command_name(self) -> List[str]:
        """
        This uses command alias if available, with this we support
        pip3.13, pip3.12, etc.
        """

        cmd_name = ["pip"]

        if self._command_alias_used:
            cmd_name = [self._command_alias_used]

        return cmd_name

    def get_diff_tracker(self) -> "EnvironmentDiffTracker":
        return PipEnvironmentDiffTracker()

    @classmethod
    def from_args(cls, args: List[str], **kwargs):
        parser = PipParser()

        if intention := parser.parse(args):
            kwargs["intention"] = intention

            if intention.modifies_packages():
                return AuditablePipCommand(args, **kwargs)

        return PipCommand(args, **kwargs)


class AuditablePipCommand(PipCommand, InstallationAuditMixin):
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
        env["PIP_INDEX_URL"] = Pip.build_index_url(ctx, self.__index_url)
        return env
