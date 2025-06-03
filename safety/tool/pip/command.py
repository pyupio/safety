import os
from pathlib import Path
import re
from tempfile import mkstemp
from typing import TYPE_CHECKING, List, Optional

import logging
import typer

from safety.models import ToolResult
from .parser import PipParser

from ..base import BaseCommand
from ..intents import ToolIntentionType
from safety_schemas.models.events.types import ToolType
from ..environment_diff import EnvironmentDiffTracker, PipEnvironmentDiffTracker
from ..mixins import InstallationAuditMixin
from ..utils import Pip
from ...encoding import detect_encoding


PIP_LOCK = "safety-pip.lock"

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

    def get_lock_path(self) -> str:
        return PIP_LOCK

    def get_diff_tracker(self) -> "EnvironmentDiffTracker":
        return PipEnvironmentDiffTracker()

    def should_track_state(self) -> bool:
        command_str = " ".join(self._args).lower()

        package_modifying_commands = [
            "install",
            "uninstall",
        ]

        return any(cmd in command_str for cmd in package_modifying_commands)

    @classmethod
    def from_args(cls, args: List[str], **kwargs):
        parser = PipParser()

        if intention := parser.parse(args):
            if intention.intention_type is ToolIntentionType.ADD_PACKAGE:
                return PipInstallCommand(args, intention=intention, **kwargs)

        return PipGenericCommand(args, **kwargs)


class PipGenericCommand(PipCommand):
    pass


class PipInstallCommand(PipCommand, InstallationAuditMixin):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._packages = []
        self.__index_url = None

    def before(self, ctx: typer.Context):
        super().before(ctx)
        args: List[Optional[str]] = self._args.copy()  # type: ignore

        if self._intention:
            for pkg in self._intention.packages:
                self._packages.append((pkg.name, pkg.version_constraint))

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

            if req_opt := self._intention.options.get(
                "requirement"
            ) or self._intention.options.get("r"):
                req_value = req_opt["value"]
                if req_value and Path(req_value).is_file():
                    with open(
                        req_value, "r", encoding=detect_encoding(Path(req_value))
                    ) as f:
                        fd, tmp_requirements_path = mkstemp(
                            suffix="safety-requirements.txt", text=True
                        )
                        with os.fdopen(fd, "w") as tf:
                            requirements = re.sub(
                                r"^(-i|--index-url).*$",
                                "",
                                f.read(),
                                flags=re.MULTILINE,
                            )
                            tf.write(requirements)

                        args[req_opt["value_index"]] = tmp_requirements_path

        self._args = [arg for arg in args if arg is not None]

    def after(self, ctx: typer.Context, result: ToolResult):
        super().after(ctx, result)
        self.handle_installation_audit(ctx, result)

    def env(self, ctx: typer.Context) -> dict:
        env = super().env(ctx)
        env["PIP_INDEX_URL"] = Pip.build_index_url(ctx, self.__index_url)
        return env
