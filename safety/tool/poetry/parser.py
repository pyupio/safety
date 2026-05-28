from typing import Dict, Optional, Union, Set

from ..base import ToolCommandLineParser
from ..intents import Dependency, ToolIntentionType


class PoetryParser(ToolCommandLineParser):
    def get_tool_name(self) -> str:
        return "poetry"

    def get_command_hierarchy(self) -> Dict[str, Union[ToolIntentionType, Dict]]:
        """
        Allow base parser to recognize poetry commands and intentions.
        """
        return {
            "add": ToolIntentionType.ADD_PACKAGE,
            "remove": ToolIntentionType.REMOVE_PACKAGE,
            "update": ToolIntentionType.UPDATE_PACKAGE,
            "install": ToolIntentionType.SYNC_PACKAGES,
            "build": ToolIntentionType.BUILD_PROJECT,
            "show": ToolIntentionType.LIST_PACKAGES,
            "init": ToolIntentionType.INIT_PROJECT,
        }

    def get_known_flags(self) -> Dict[str, Set[str]]:
        """
        Flags that DO NOT take a value, derived from `poetry --help` and subcommand helps.
        """
        return {
            "global": {
                "help",
                "h",
                "quiet",
                "q",
                "version",
                "V",
                "ansi",
                "no-ansi",
                "no-interaction",
                "n",
                "no-plugins",
                "no-cache",
                "verbose",
                "v",
                "vv",
                "vvv",
            },
            "add": {
                "dev",
                "D",
                "editable",
                "e",
                "allow-prereleases",
                "dry-run",
                "lock",
            },
            "remove": {
                "dev",
                "D",
                "dry-run",
                "lock",
            },
            "update": {
                "sync",
                "dry-run",
                "lock",
            },
            "install": {
                "sync",
                "no-root",
                "no-directory",
                "dry-run",
                "all-extras",
                "all-groups",
                "only-root",
                "compile",
            },
            "build": {
                "clean",
            },
        }

    def _parse_package_spec(
        self, spec_str: str, arg_index: int
    ) -> Optional[Dependency]:
        """
        Parse a package specification string into a Dependency object.
        Handles various formats including Poetry-specific syntax and standard PEP 508 requirements.

        Args:
            spec_str: Package specification string (e.g. "requests>=2.25.0[security]")

        Returns:
            Dependency: Parsed dependency information

        Raises:
            ValueError: If the specification cannot be parsed
        """
        try:
            # TODO: This is a very basic implementation and not well tested
            # our main target for now is to get the package name.
            from packaging.requirements import Requirement

            include_specifier = False

            # Handle @ operator (package@version)
            if "@" in spec_str and not spec_str.startswith("git+"):
                name = spec_str.split("@")[0]

            # Handle caret requirements (package^version)
            elif "^" in spec_str:
                name = spec_str.split("^")[0]

            # Handle tilde requirements (package~version)
            elif "~" in spec_str and "~=" not in spec_str:
                name = spec_str.split("~")[0]

            else:
                # Common PEP 440 cases
                name = spec_str
                include_specifier = True

            req = Requirement(name)

            return Dependency(
                name=req.name,
                version_constraint=str(req.specifier) if include_specifier else None,
                extras=req.extras,
                arg_index=arg_index,
                original_text=spec_str,
            )
        except Exception:
            # If spec parsing fails, just ignore for now
            return None
