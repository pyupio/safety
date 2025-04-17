from typing import List
from safety.tool.intents import ToolIntentionType
from safety.tool.pip.parser import PipParser
from ..pip.command import PipCommand, PipInstallCommand, PipGenericCommand
from safety_schemas.models.events.types import ToolType


class UvCommand(PipCommand):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._name = ["uv"]

    def get_tool_type(self) -> ToolType:
        return ToolType.UV

    def get_package_list_command(self) -> List[str]:
        return [*self._name, "pip", "list", "--format=json"]

    def should_track_state(self) -> bool:
        should_track = super().should_track_state()

        if should_track:
            return True

        command_str = " ".join(self._args).lower()

        package_modifying_commands = [
            "sync",
        ]

        return any(cmd in command_str for cmd in package_modifying_commands)

    @classmethod
    def from_args(cls, args: List[str]):
        parser = PipParser()

        to_parse = args[1:] if args[0] == "pip" else args

        if intention := parser.parse(to_parse):
            if intention.intention_type is ToolIntentionType.ADD_PACKAGE:
                return UvInstallCommand(to_parse, intention=intention)

        return UvGenericCommand(to_parse)


class UvInstallCommand(PipInstallCommand, UvCommand):
    def get_command_name(self) -> List[str]:
        return ["uv", "pip"]


class UvGenericCommand(PipGenericCommand, UvCommand):
    pass
