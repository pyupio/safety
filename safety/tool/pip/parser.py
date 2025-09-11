from typing import Dict

from ..base import ToolCommandLineParser
from ..intents import ToolIntentionType

from typing import Union, Set


class PipParser(ToolCommandLineParser):
    def get_tool_name(self) -> str:
        return "pip"

    def get_command_hierarchy(self) -> Dict[str, Union[ToolIntentionType, Dict]]:
        """
        Context for command hierarchy parsing
        """
        return {
            "install": ToolIntentionType.ADD_PACKAGE,
            "uninstall": ToolIntentionType.REMOVE_PACKAGE,
            "download": ToolIntentionType.DOWNLOAD_PACKAGE,
        }

    def get_known_flags(self) -> Dict[str, Set[str]]:
        """
        Define flags that DON'T take values to avoid consuming packages
        """
        return {
            # Global flags (available for all commands)
            "global": {
                "verbose",
                "v",
                "quiet",
                "q",
                "help",
                "h",
                "version",
                "V",
                "debug",
                "isolated",
            },
            # install-specific flags
            "install": {
                "upgrade",
                "U",
                "force-reinstall",
                "no-deps",
                "user",
                "system",
                "compile",
                "no-compile",
                "no-warn-script-location",
                "no-warn-conflicts",
                "break-system-packages",
                "require-hashes",
                "no-build-isolation",
                "use-pep517",
                "no-use-pep517",
                "check-build-dependencies",
                "no-clean",
                "disable-pip-version-check",
            },
            # uninstall-specific flags
            "uninstall": {"yes", "y"},
            # download-specific flags
            "download": {"no-deps", "no-binary", "only-binary"},
        }
