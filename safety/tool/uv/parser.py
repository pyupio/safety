from typing import Dict

from ..base import ToolCommandLineParser
from ..intents import ToolIntentionType
from typing import Union


class UvParser(ToolCommandLineParser):
    def get_tool_name(self) -> str:
        return "uv"

    def get_command_hierarchy(self) -> Dict[str, Union[ToolIntentionType, Dict]]:
        """
        Context for command hierarchy parsing
        """
        return {
            # 2-level commands
            "add": ToolIntentionType.ADD_PACKAGE,
            "remove": ToolIntentionType.REMOVE_PACKAGE,
            "build": ToolIntentionType.BUILD_PROJECT,
            # 3-level commands
            "pip": {
                "install": ToolIntentionType.ADD_PACKAGE,
                "uninstall": ToolIntentionType.REMOVE_PACKAGE,
                "download": ToolIntentionType.DOWNLOAD_PACKAGE,
            },
            "tool": {
                "install": ToolIntentionType.ADD_PACKAGE,
                "uninstall": ToolIntentionType.REMOVE_PACKAGE,
            },
        }

    def get_known_flags(self) -> Dict[str, set]:
        """
        Define flags that DON'T take values for uv.
        These were derived from `uv --help` and subcommand helps.
        """
        return {
            "global": {
                # Global options
                "quiet",
                "q",
                "verbose",
                "v",
                "native-tls",
                "offline",
                "no-progress",
                "no-config",
                "help",
                "h",
                "version",
                "V",
                # Python options that are flags
                "managed-python",
                "no-managed-python",
                "no-python-downloads",
            },
            # 2-level commands
            "add": {
                # From `uv add --help`
                "no-sync",
                "locked",
                "frozen",
                "active",
                "workspace",
                "no-workspace",
                "no-install-project",
                "no-install-workspace",
                # Resolver/installer/build/cache flags inherited
                "upgrade",
                "no-sources",
                "reinstall",
                "compile-bytecode",
                "no-build-isolation",
                "no-build",
                "no-binary",
                "no-cache",
                "refresh",
            },
            "remove": {
                "dev",
                "no-sync",
                "active",
                "locked",
                "frozen",
                # Inherited flags (see sections in help)
                "upgrade",
                "no-sources",
                "reinstall",
                "compile-bytecode",
                "no-build-isolation",
                "no-build",
                "no-binary",
                "no-cache",
                "refresh",
            },
            # 3-level pip commands
            "pip.install": {
                # pip install-like flags in uv
                "user",
                "upgrade",
                "no-sources",
                "reinstall",
                "compile-bytecode",
                "no-build-isolation",
                "no-build",
                "no-binary",
                "no-cache",
                "refresh",
            },
            "pip.uninstall": {
                "system",
                "break-system-packages",
                "no-break-system-packages",
                "dry-run",
                # global/cache flags also apply
                "no-cache",
            },
            "tool.install": {
                "editable",
                "e",
                "force",
                # inherited sections
                "upgrade",
                "no-sources",
                "reinstall",
                "compile-bytecode",
                "no-build-isolation",
                "no-build",
                "no-binary",
                "no-cache",
                "refresh",
            },
        }
