# type: ignore
import unittest
from safety.tool.uv.command import AuditableUvCommand
from ..base import CommandToolCaseMixin


class TestUvCommand(CommandToolCaseMixin, unittest.TestCase):
    """
    Test cases for UvCommand functionality.
    """

    command_class = AuditableUvCommand
    command_args = ["uv", "pip", "install", "package"]
    parent_env = {"EXISTING_VAR": "existing_value", "PATH": "/usr/bin:/bin"}
    expected_env_vars = {
        "UV_INDEX_SAFETY_USERNAME": "user",
        "UV_INDEX_SAFETY_PASSWORD": "mock_credentials_value",
        # UV < 0.4.23 does only support UV_INDEX_URL, so we comment it out to avoid a warning in modern versions
        # "UV_INDEX_URL": "https://user:mock_credentials_value@pkgs.safetycli.com/repository/public/pypi/simple/",
        "UV_DEFAULT_INDEX": "https://user:mock_credentials_value@pkgs.safetycli.com/repository/public/pypi/simple/",
    }
    mock_configurations = [
        {
            "target": "safety.tool.uv.command.index_credentials",
            "return_value": "mock_credentials_value",
        },
        {
            "target": "safety.tool.uv.command.Uv.build_index_url",
            "return_value": "https://user:mock_credentials_value@pkgs.safetycli.com/repository/public/pypi/simple/",
        },
    ]
