from typing import Dict, List, Optional

from ..base import ToolCommandLineParser, CommandToolIntention
from ..intents import Dependency, ToolIntentionType


class PoetryParser(ToolCommandLineParser):
    def get_tool_name(self) -> str:
        return "poetry"

    @property
    def intention_mapping(self) -> Dict[str, ToolIntentionType]:
        """
        Maps specific commands to intention types
        """
        return {
            "add": ToolIntentionType.ADD_PACKAGE,
            "remove": ToolIntentionType.REMOVE_PACKAGE,
            "update": ToolIntentionType.UPDATE_PACKAGE,
            "show": ToolIntentionType.LIST_PACKAGES,
            "init": ToolIntentionType.INIT_PROJECT,
            "build": ToolIntentionType.BUILD_PROJECT,
            "install": ToolIntentionType.SYNC_PACKAGES,
        }

    def parse(self, args: List[str]) -> Optional[CommandToolIntention]:
        """
        Parse the command line arguments into a CommandToolIntention object.

        Args:
            args (List[str]): Command line arguments

        Returns:
            Optional[CommandToolIntention]: Parsed command tool intention
        """
        if not self.can_handle(args):
            return None

        command = args[0].lower()
        intention_type = self.map_intention(command)
        options = {}
        packages = []
        raw_args = args.copy()

        # Process command arguments based on intention type
        i = 1  # Skip command
        while i < len(args):
            arg = args[i]

            if arg.startswith("-"):
                # Handle options
                option_key = arg.lstrip("-")

                # Handle option with value
                if i + 1 < len(args) and not args[i + 1].startswith("-"):
                    option_value = args[i + 1]
                    options[option_key] = {
                        "arg_index": i,
                        "raw_option": arg,
                        "value": option_value,
                        "value_index": i + 1,
                    }
                    i += 2
                else:
                    # Flag option (no value)
                    options[option_key] = {
                        "arg_index": i,
                        "raw_option": arg,
                        "value": True,
                    }
                    i += 1
            else:
                # Parse non-option arguments
                if intention_type == ToolIntentionType.ADD_PACKAGE:
                    try:
                        # Parse package specification
                        dep = self._parse_package_spec(arg, i)
                        if not dep:
                            # Let's skip this dependency
                            i += 1
                            continue

                        # Check if this is a dev dependency
                        is_dev = any(opt in ["dev", "D"] for opt in options.keys())
                        dep.is_dev_dependency = is_dev

                        packages.append(dep)
                    except ValueError:
                        # Not a valid package spec, store as unknown option
                        options[f"unknown_{len(options)}"] = {
                            "arg_index": i,
                            "value": arg,
                        }
                elif intention_type in [
                    ToolIntentionType.REMOVE_PACKAGE,
                    ToolIntentionType.UPDATE_PACKAGE,
                ]:
                    # Handle packages for remove/update commands
                    # These often have simpler formats than add commands
                    dep = Dependency(name=arg, arg_index=i, original_text=arg)
                    packages.append(dep)
                i += 1

        return CommandToolIntention(
            tool=self._tool_name,
            command=command,
            intention_type=intention_type,
            packages=packages,
            options=options,
            raw_args=raw_args,
        )

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
