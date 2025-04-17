from typing import Dict, List, Optional

from ..base import ToolCommandLineParser, CommandToolIntention
from ..intents import Dependency, ToolIntentionType


class PipParser(ToolCommandLineParser):
    def get_tool_name(self) -> str:
        return "pip"

    @property
    def intention_mapping(self) -> Dict[str, ToolIntentionType]:
        """
        Maps specific commands to intention types
        """
        return {
            "install": ToolIntentionType.ADD_PACKAGE,
            "uninstall": ToolIntentionType.REMOVE_PACKAGE,
            "list": ToolIntentionType.LIST_PACKAGES,
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
                if intention_type in [
                    ToolIntentionType.ADD_PACKAGE,
                    ToolIntentionType.REMOVE_PACKAGE,
                ]:
                    try:
                        # Parse package specification
                        dep = self._parse_package_spec(arg, i)
                        if not dep:
                            # Let's skip this dependency
                            i += 1
                            continue

                        packages.append(dep)
                    except ValueError:
                        # Not a valid package spec, store as unknown option
                        options[f"unknown_{len(options)}"] = {
                            "arg_index": i,
                            "value": arg,
                        }
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
        try:
            from packaging.requirements import Requirement

            # TODO: pip install . should be excluded
            req = Requirement(spec_str)

            return Dependency(
                name=req.name,
                version_constraint=str(req.specifier),
                extras=req.extras,
                arg_index=arg_index,
                original_text=spec_str,
            )
        except Exception:
            # If spec parsing fails, just ignore for now
            return None
