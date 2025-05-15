# type: ignore
import unittest

from safety.tool.poetry.command import PoetryCommand
from ..base import CommandToolCaseMixin


class TestPoetryCommand(CommandToolCaseMixin, unittest.TestCase):
    """
    Test cases for PoetryCommand functionality.
    """

    command_class = PoetryCommand
    command_args = ["poetry", "add", "foobar"]
    parent_env = {"EXISTING_VAR": "existing_value", "PATH": "/usr/bin:/bin"}
    expected_env_vars = {
        "POETRY_HTTP_BASIC_SAFETY_USERNAME": "user",
        "POETRY_HTTP_BASIC_SAFETY_PASSWORD": "mock_credentials_value",
    }
    mock_configurations = [
        {
            "target": "safety.tool.poetry.command.index_credentials",
            "return_value": "mock_credentials_value",
        }
    ]
