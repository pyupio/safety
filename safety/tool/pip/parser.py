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
            "wheel": ToolIntentionType.DOWNLOAD_PACKAGE,
            "query": ToolIntentionType.SEARCH_PACKAGES,
            "index": {
                "versions": ToolIntentionType.SEARCH_PACKAGES,
            },
        }

    def get_known_flags(self) -> Dict[str, Set[str]]:
        """
        Define flags that DON'T take values to avoid consuming packages
        """
        return {
            # Global flags (available for all commands)
            "global": {
                "help",
                "h",
                "debug",
                "isolated",
                "require-virtualenv",
                "verbose",
                "v",
                "version",
                "V",
                "quiet",
                "q",
                "no-input",
                "no-cache-dir",
                "disable-pip-version-check",
                "no-color",
                # Index specific
                "no-index",
            },
            # install-specific flags
            "install": {
                "no-deps",
                "pre",
                "dry-run",
                "user",
                "upgrade",
                "U",
                "force-reinstall",
                "ignore-installed",
                "I",
                "ignore-requires-python",
                "no-build-isolation",
                "use-pep517",
                "no-use-pep517",
                "check-build-dependencies",
                "break-system-packages",
                "compile",
                "no-compile",
                "no-warn-script-location",
                "no-warn-conflicts",
                "prefer-binary",
                "require-hashes",
                "no-clean",
            },
            # uninstall-specific flags
            "uninstall": {
                "yes",
                "y",
                "break-system-packages",
            },
            # download-specific flags
            "download": {
                "no-deps",
                "no-binary",
                "only-binary",
                "prefer-binary",
                "pre",
                "require-hashes",
                "no-build-isolation",
                "use-pep517",
                "no-use-pep517",
                "check-build-dependencies",
                "ignore-requires-python",
                "no-clean",
            },
            "index.versions": {
                "ignore-requires-python",
                "pre",
                "json",
                "no-index",
            },
        }
