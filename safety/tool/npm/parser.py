from typing import Dict

from ..base import ToolCommandLineParser
from ..intents import ToolIntentionType

from typing import Union, Set, Optional, Mapping
from ..intents import Dependency

ADD_PACKAGE_ALIASES = [
    "install",
    "add",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
]

REMOVE_PACKAGE_ALIASES = [
    "uninstall",
    "unlink",
    "remove",
    "rm",
    "r",
    "un",
]

UPDATE_PACKAGE_ALIASES = [
    "update",
    "up",
    "upgrade",
    "udpate",
]

SYNC_PACKAGES_ALIASES = [
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
]

LIST_PACKAGES_ALIASES = [
    "list",
    "ls",
    "ll",
    "la",
]

SEARCH_PACKAGES_ALIASES = [
    # Via view
    "view",
    "info",
    "show",
    "v",
    # Via search
    "search",
    "find",
    "s",
    "se",
]

INIT_PROJECT_ALIASES = [
    "init",
    "create",
]


class NpmParser(ToolCommandLineParser):
    def get_tool_name(self) -> str:
        return "npm"

    def get_command_hierarchy(self) -> Mapping[str, Union[ToolIntentionType, Mapping]]:
        """
        Context for command hierarchy parsing
        """

        alias_map = {
            ToolIntentionType.ADD_PACKAGE: ADD_PACKAGE_ALIASES,
            ToolIntentionType.REMOVE_PACKAGE: REMOVE_PACKAGE_ALIASES,
            ToolIntentionType.UPDATE_PACKAGE: UPDATE_PACKAGE_ALIASES,
            ToolIntentionType.SYNC_PACKAGES: SYNC_PACKAGES_ALIASES,
            ToolIntentionType.SEARCH_PACKAGES: SEARCH_PACKAGES_ALIASES,
            ToolIntentionType.LIST_PACKAGES: LIST_PACKAGES_ALIASES,
            ToolIntentionType.INIT_PROJECT: INIT_PROJECT_ALIASES,
        }

        hierarchy = {
            alias.lower().strip(): intention
            for intention, aliases in alias_map.items()
            for alias in aliases
        }

        return hierarchy

    def get_known_flags(self) -> Dict[str, Set[str]]:
        """
        Define flags that DON'T take values to avoid consuming packages
        """
        GLOBAL_FLAGS = {
            "S",
            "save",
            "no-save",
            "save-prod",
            "save-dev",
            "save-optional",
            "save-peer",
            "save-bundle",
            "g",
            "global",
            "workspaces",
            "include-workspace-root",
            "install-links",
            "json",
            "no-color",
            "parseable",
            "p",
            "no-description",
            "prefer-offline",
            "offline",
        }

        OTHER_FLAGS = {
            "E",
            "save-exact",
            "legacy-bundling",
            "global-style",
            "strict-peer-deps",
            "prefer-dedupe",
            "no-package-lock",
            "package-lock-only",
            "foreground-scripts",
            "ignore-scripts",
            "no-audit",
            "no-bin-links",
            "no-fund",
            "dry-run",
        }

        return {
            # We don't need to differentiate between flags for different commands
            "global": GLOBAL_FLAGS | OTHER_FLAGS,
        }

    def _parse_package_spec(
        self, spec_str: str, arg_index: int
    ) -> Optional[Dependency]:
        """
        Parse npm registry specs like "react", "@types/node@^20",
        and aliases like "alias@npm:@sentry/node@7".
        Skips non-registry (git/url/path).
        """
        import re

        s = spec_str.strip()

        REGISTRY_RE = re.compile(
            r"""^(?P<name>@[^/\s]+/[^@\s]+|[A-Za-z0-9._-]+)(?:@(?P<constraint>.+))?$"""
        )
        ALIAS_RE = re.compile(
            r"""^(?P<alias>@?[^@\s/]+(?:/[^@\s/]+)?)@npm:(?P<target>.+)$"""
        )

        def mk(name: str, constraint: Optional[str]) -> Dependency:
            dep = Dependency(
                name=name.lower(),
                version_constraint=(constraint or None),
                arg_index=arg_index,
                original_text=spec_str,
            )

            return dep

        # alias form
        m = ALIAS_RE.match(s)
        if m:
            alias = m.group("alias")
            target = m.group("target").strip()
            rm = REGISTRY_RE.match(target)
            if rm:
                return mk(alias, rm.group("constraint"))
            # out-of-scope target
            return None

        # plain registry form
        m = REGISTRY_RE.match(s)
        if m:
            return mk(m.group("name"), m.group("constraint"))

        return None
