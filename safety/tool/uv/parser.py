from typing import Dict, Union, Set

from ..base import ToolCommandLineParser
from ..intents import ToolIntentionType


UV_CACHE_FLAGS = {
    "no-cache",
    "n",
    "refresh",
}

UV_PYTHON_FLAGS = {
    "managed-python",
    "no-managed-python",
    "no-python-downloads",
}


UV_INDEX_FLAGS = {
    "no-index",
}

UV_RESOLVER_FLAGS = {
    "upgrade",
    "U",
    "no-sources",
}

UV_INSTALLER_FLAGS = {
    "reinstall",
    "compile-bytecode",
}

UV_BUILD_FLAGS = {
    "no-build-isolation",
    "no-build",
    "no-binary",
}

UV_GLOBAL_FLAGS = {
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
}

UV_PIP_INSTALL_FLAGS = {
    "all-extras",
    "no-deps",
    "require-hashes",
    "no-verify-hashes",
    "system",
    "break-system-packages",
    "no-break-system-packages",
    "no-build",
    "exact",
    "strict",
    "dry-run",
    "user",
}

UV_PIP_UNINSTALL_FLAGS = {
    "system",
    "break-system-packages",
    "no-break-system-packages",
    "dry-run",
}


UV_KNOWN_FLAGS: Dict[str, Set[str]] = {
    "global": UV_GLOBAL_FLAGS
    | UV_CACHE_FLAGS
    | UV_PYTHON_FLAGS
    | UV_INDEX_FLAGS
    | UV_RESOLVER_FLAGS
    | UV_INSTALLER_FLAGS
    | UV_BUILD_FLAGS,
    # 2-level commands
    "add": {
        # From `uv add --help`
        "dev",
        "editable",
        "raw",
        "no-sync",
        "locked",
        "frozen",
        "active",
        "workspace",
        "no-workspace",
        "no-install-project",
        "no-install-workspace",
    },
    "remove": {
        "dev",
        "no-sync",
        "active",
        "locked",
        "frozen",
    },
    "sync": {
        "all-extras",
        "no-dev",
        "only-dev",
        "no-default-groups",
        "all-groups",
        "no-editable",
        "inexact",
        "active",
        "no-install-project",
        "no-install-workspace",
        "locked",
        "frozen",
        "dry-run",
        "all-packages",
        "check",
    },
    # 3-level pip commands
    "pip.install": UV_PIP_INSTALL_FLAGS,
    "pip.uninstall": UV_PIP_UNINSTALL_FLAGS,
}


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
            "sync": ToolIntentionType.SYNC_PACKAGES,
            # 3-level commands
            "pip": {
                "install": ToolIntentionType.ADD_PACKAGE,
                "uninstall": ToolIntentionType.REMOVE_PACKAGE,
                "download": ToolIntentionType.DOWNLOAD_PACKAGE,
                "list": ToolIntentionType.LIST_PACKAGES,
            },
        }

    def get_known_flags(self) -> Dict[str, Set[str]]:
        """
        Define flags that DON'T take values for uv.
        These were derived from `uv --help` and subcommand helps.
        """
        return UV_KNOWN_FLAGS
