from typing import TYPE_CHECKING, List, Optional, Dict, Any, Literal
from typing import Tuple

import logging
import typer

from safety.models import ToolResult
from .parser import NpmParser

from ..base import BaseCommand
from safety_schemas.models.events.types import ToolType
from ..environment_diff import EnvironmentDiffTracker, NpmEnvironmentDiffTracker
from ..mixins import InstallationAuditMixin
from ..constants import TOP_NPMJS_PACKAGES
from ..auth import build_index_url
import json


if TYPE_CHECKING:
    from ..environment_diff import EnvironmentDiffTracker

logger = logging.getLogger(__name__)


class NpmCommand(BaseCommand):
    """
    Main class for hooks into npm commands.
    """

    def get_tool_type(self) -> ToolType:
        return ToolType.NPM

    def get_command_name(self) -> List[str]:
        return ["npm"]

    def get_ecosystem(self) -> Literal["pypi", "npmjs"]:
        return "npmjs"

    def get_package_list_command(self) -> List[str]:
        return [*self.get_command_name(), "list", "--json", "--all", "-l"]

    def _flatten_packages(self, dependencies: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Flatten npm list --json --all -l output into a list of package dictionaries with file paths.

        Args:
            dependencies: The root dependencies dictionary from JSON output from npm list --json --all -l

        Returns:
            List of dictionaries with name, version, and location keys
        """
        result = []

        def traverse(dependencies: Dict[str, Any]):
            if not dependencies:
                return

            for name, info in dependencies.items():
                result.append(
                    {
                        "name": name,
                        "version": info.get("version", ""),
                        "location": info.get("path", ""),
                    }
                )

                # Recursively process nested dependencies
                if "dependencies" in info:
                    traverse(info["dependencies"])

        traverse(dependencies)

        return result

    def parse_package_list_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Handle the output of the npm list command.

        Args:
            output: Command output

        Returns:
            List[Dict[str, Any]]: List of package dictionaries
        """
        try:
            result = json.loads(output)
        except json.JSONDecodeError:
            # Log error and return empty list
            logger.exception(f"Error parsing package list output: {output[:100]}...")
            return []

        return self._flatten_packages(result.get("dependencies", {}))

    def get_diff_tracker(self) -> "EnvironmentDiffTracker":
        return NpmEnvironmentDiffTracker()

    def _get_typosquatting_reference_packages(self) -> Tuple[str]:
        return TOP_NPMJS_PACKAGES

    @classmethod
    def from_args(cls, args: List[str], **kwargs):
        parser = NpmParser()

        if intention := parser.parse(args):
            kwargs["intention"] = intention

            if intention.modifies_packages():
                return AuditableNpmCommand(args, **kwargs)

            if intention.queries_packages():
                return SearchCommand(args, **kwargs)

        return NpmCommand(args, **kwargs)


class NpmIndexEnvMixin:
    """
    Mixin to inject Safety's default index URL into npm's environment.
    Expects implementers to define `self._index_url` (Optional[str]).
    """

    def env(self, ctx: typer.Context) -> dict:
        env = super().env(ctx)  # pyright: ignore[reportAttributeAccessIssue]
        default_index_url = build_index_url(
            ctx, getattr(self, "_index_url", None), "npm"
        )
        env["NPM_CONFIG_REGISTRY"] = default_index_url
        return env


class SearchCommand(NpmIndexEnvMixin, NpmCommand):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._index_url = None


class AuditableNpmCommand(NpmIndexEnvMixin, NpmCommand, InstallationAuditMixin):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._index_url = None

    def before(self, ctx: typer.Context):
        super().before(ctx)
        args: List[Optional[str]] = self._args.copy()  # type: ignore

        if self._intention:
            if registry_opt := self._intention.options.get(
                "registry"
            ) or self._intention.options.get("r"):
                registry_value = registry_opt["value"]

                if registry_value and registry_value.startswith(
                    "https://pkgs.safetycli.com"
                ):
                    self._index_url = registry_value

                arg_index = registry_opt["arg_index"]
                value_index = registry_opt["value_index"]

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
