from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from safety.cli_util import CommandType, FeatureType
from safety.constants import CONTEXT_COMMAND_TYPE, CONTEXT_FEATURE_TYPE


class ContextSettingsModel(BaseModel):
    """
    Model for command context settings.
    """

    allow_extra_args: bool = Field(default=True)
    ignore_unknown_options: bool = Field(default=True)
    command_type: CommandType = Field(default=CommandType.BETA)
    feature_type: FeatureType = Field(default=FeatureType.FIREWALL)
    help_option_names: List[str] = Field(default=["--safety-help"])

    def as_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format expected by Typer.

        Returns:
            Dict[str, Any]: Dictionary representation of the context settings
        """
        result = {
            "allow_extra_args": self.allow_extra_args,
            "ignore_unknown_options": self.ignore_unknown_options,
            CONTEXT_COMMAND_TYPE: self.command_type,
            CONTEXT_FEATURE_TYPE: self.feature_type,
            "help_option_names": self.help_option_names,
        }
        return result


class CommandSettingsModel(BaseModel):
    """
    Model for command settings used in the Typer decorator.
    """

    help: str
    name: str
    options_metavar: str = Field(default="[OPTIONS]")
    context_settings: ContextSettingsModel = Field(default_factory=ContextSettingsModel)


class ToolCommandModel(BaseModel):
    """
    Model for a tool command definition.
    """

    name: str
    display_name: str
    help: str
    # Path to custom Typer app if available
    custom_app: Optional[str] = None
    # Custom command settings for the tool
    command_settings: Optional[CommandSettingsModel] = None

    def get_command_settings(self) -> CommandSettingsModel:
        """
        Get command settings, using defaults if not specified.

        Returns:
            CommandSettingsModel: Command settings with defaults
        """
        if self.command_settings:
            return self.command_settings

        return CommandSettingsModel(
            help=self.help,
            name=self.display_name,
        )


# Tool definitions
TOOLS = [
    ToolCommandModel(
        name="poetry",
        display_name="poetry",
        help="[BETA] Commands for managing Safety project.\nExample: safety poetry add httpx",
    ),
    ToolCommandModel(
        name="pip",
        display_name="pip",
        help="[BETA] Commands for managing Safety project.\nExample: safety pip list",
    ),
    ToolCommandModel(
        name="uv",
        display_name="uv",
        help="[BETA] Commands for managing Safety project.\nExample: safety uv pip list",
    ),
]
