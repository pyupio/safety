# type: ignore
import unittest
from safety.tool.uv.command import UvCommand
from ..base import CommandToolCaseMixin


class TestUvCommand(CommandToolCaseMixin, unittest.TestCase):
    """
    Test cases for UvCommand functionality.
    """

    command_class = UvCommand
    command_args = ["uv", "pip", "install", "package"]
    parent_env = {"EXISTING_VAR": "existing_value", "PATH": "/usr/bin:/bin"}
    expected_env_vars = {
        "UV_INDEX_SAFETY_USERNAME": "user",
        "UV_INDEX_SAFETY_PASSWORD": "mock_credentials_value",
    }
    mock_configurations = [
        {
            "target": "safety.tool.uv.command.index_credentials",
            "return_value": "mock_credentials_value",
        }
    ]
