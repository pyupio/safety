import os
from pathlib import Path
import re
from tempfile import mkstemp
from typing import TYPE_CHECKING, Any, List, Optional

import logging
from rich.padding import Padding
import typer

from safety.models import ToolResult
from .parser import PipParser

from ..base import BaseCommand
from ..intents import ToolIntentionType
from safety_schemas.models.events.types import ToolType
from ..environment_diff import EnvironmentDiffTracker, PipEnvironmentDiffTracker
from ..utils import Pip

from safety.console import main_console as console
from ...init.render import render_header, progressive_print

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


class PipInstallCommand(PipCommand):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.__packages = []
        self.__index_url = None

    def before(self, ctx: typer.Context):
        super().before(ctx)
        args: List[Optional[str]] = self._args.copy()  # type: ignore

        if self._intention:
            for pkg in self._intention.packages:
                self.__packages.append((pkg.name, pkg.version_constraint))

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
                    with open(req_value, "r") as f:
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

        self.__render_installation_warnings(ctx)

        if not result.process or result.process.returncode != 0:
            self.__render_package_details()

    def env(self, ctx: typer.Context) -> dict:
        env = super().env(ctx)
        env["PIP_INDEX_URL"] = Pip.build_index_url(ctx, self.__index_url)
        return env

    def __render_installation_warnings(self, ctx: typer.Context):
        packages_audit = self.__audit_packages(ctx)

        warning_messages = []
        for audited_package in packages_audit.get("audit", {}).get("packages", []):
            vulnerabilities = audited_package.get("vulnerabilities", {})
            critical_vulnerabilities = vulnerabilities.get("critical", 0)
            total_vulnerabilities = 0
            for count in vulnerabilities.values():
                total_vulnerabilities += count

            if total_vulnerabilities == 0:
                continue

            warning_message = f"[[yellow]Warning[/yellow]] {audited_package.get('package_specifier')} contains {total_vulnerabilities} vulnerabilities"
            if critical_vulnerabilities > 0:
                warning_message += f", including {critical_vulnerabilities} critical severity vulnerabilities"

            warning_message += "."
            warning_messages.append(warning_message)

        if len(warning_messages) > 0:
            console.print()
            render_header(" Safety Report")
            progressive_print(warning_messages)

    def __render_package_details(self):
        for package_name, version_specifier in self.__packages:
            console.print(
                Padding(
                    f"Learn more: [link]https://data.safetycli.com/packages/pypi/{package_name}/[/link]",
                    (0, 0, 0, 1),
                ),
                emoji=True,
            )

    def __audit_packages(self, ctx: typer.Context) -> Any:
        try:
            added, _, updated = self._diff_tracker.get_diff()
            packages = {**added, **updated}

            return ctx.obj.auth.client.audit_packages(
                [
                    f"{package_name}=={version[-1] if isinstance(version, tuple) else version}"
                    for (package_name, version) in packages.items()
                ]
            )
        except Exception:
            logger.debug("Audit API failed with error", exc_info=True)
            # do not propagate the error in case the audit failed
            return dict()
