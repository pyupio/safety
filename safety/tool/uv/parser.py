from typing import Dict

from ..pip.parser import PipParser
from ..intents import ToolIntentionType


class UvParser(PipParser):
    def get_tool_name(self) -> str:
        return "uv"

    @property
    def intention_mapping(self) -> Dict[str, ToolIntentionType]:
        """
        Maps specific commands to intention types
        """
        return {
            "add": ToolIntentionType.ADD_PACKAGE,
            "remove": ToolIntentionType.REMOVE_PACKAGE,
            "sync": ToolIntentionType.SYNC_PACKAGES,
        }
