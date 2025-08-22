"""
Test suite for UvParser functionality.
"""

import pytest

from safety.tool.uv.parser import UvParser
from safety.tool.intents import ToolIntentionType


@pytest.mark.unit
class TestUvParser:
    def setup_method(self):
        self.parser = UvParser()

    def test_uv_parser_pip_install_chain_recognized(self):
        """
        Test uv pip install chain with ADD_PACKAGE intention
        """
        intention = self.parser.parse(["pip", "install", "requests"])

        assert intention is not None
        assert intention.tool == "uv"
        assert intention.command == "pip install"
        assert intention.command_chain == ["pip", "install"]
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_direct_add_command(self):
        """
        Test direct uv add command
        """
        intention = self.parser.parse(["add", "requests"])

        assert intention is not None
        assert intention.command == "add"
        assert intention.command_chain == ["add"]
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_pip_uninstall_chain(self):
        """
        Test uv pip uninstall chain with REMOVE_PACKAGE intention
        """
        intention = self.parser.parse(["pip", "uninstall", "requests"])

        assert intention is not None
        assert intention.command == "pip uninstall"
        assert intention.command_chain == ["pip", "uninstall"]
        assert intention.intention_type == ToolIntentionType.REMOVE_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_remove_command(self):
        """
        Test uv remove command
        """
        intention = self.parser.parse(["remove", "requests"])

        assert intention is not None
        assert intention.command == "remove"
        assert intention.command_chain == ["remove"]
        assert intention.intention_type == ToolIntentionType.REMOVE_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_pip_download_command(self):
        """
        Test uv pip download command
        """
        intention = self.parser.parse(["pip", "download", "requests"])

        assert intention is not None
        assert intention.command == "pip download"
        assert intention.command_chain == ["pip", "download"]
        assert intention.intention_type == ToolIntentionType.DOWNLOAD_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_build_command(self):
        """
        Test uv build command
        """
        intention = self.parser.parse(["build"])

        assert intention is not None
        assert intention.command == "build"
        assert intention.command_chain == ["build"]
        assert intention.intention_type == ToolIntentionType.BUILD_PROJECT
        assert len(intention.packages) == 0  # Build doesn't take packages

    def test_uv_parser_flags_dont_consume_packages(self):
        """
        Test UV flags don't consume package names
        """
        intention = self.parser.parse(["add", "--no-sync", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE

        # Flags should be parsed correctly
        assert "no-sync" in intention.options
        assert intention.options["no-sync"]["value"] is True

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_pip_install_flags(self):
        """
        Test UV pip install flags
        """
        intention = self.parser.parse(
            ["pip", "install", "--upgrade", "--user", "requests"]
        )

        assert intention is not None
        assert intention.command_chain == ["pip", "install"]

        # Flags should be parsed correctly
        assert "upgrade" in intention.options
        assert intention.options["upgrade"]["value"] is True
        assert "user" in intention.options
        assert intention.options["user"]["value"] is True

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_global_flags(self):
        """
        Test global UV flags work across commands
        """
        intention = self.parser.parse(["add", "--verbose", "--no-progress", "requests"])

        assert intention is not None

        # Global flags should be recognized
        assert "verbose" in intention.options
        assert intention.options["verbose"]["value"] is True
        assert "no-progress" in intention.options
        assert intention.options["no-progress"]["value"] is True

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_add_command_flags(self):
        """
        Test UV add command specific flags
        """
        intention = self.parser.parse(
            ["add", "--locked", "--frozen", "--upgrade", "requests"]
        )

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE

        # Add-specific flags should be recognized
        assert "locked" in intention.options
        assert intention.options["locked"]["value"] is True
        assert "frozen" in intention.options
        assert intention.options["frozen"]["value"] is True
        assert "upgrade" in intention.options
        assert intention.options["upgrade"]["value"] is True

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_remove_command_flags(self):
        """
        Test UV remove command flags
        """
        intention = self.parser.parse(["remove", "--locked", "--frozen", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.REMOVE_PACKAGE

        # Remove-specific flags should be recognized
        assert "locked" in intention.options
        assert intention.options["locked"]["value"] is True
        assert "frozen" in intention.options
        assert intention.options["frozen"]["value"] is True

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_value_options(self):
        """
        Test UV options that take values
        """
        intention = self.parser.parse(
            [
                "pip",
                "install",
                "--python",
                "3.9",
                "--index-url",
                "https://pypi.org/simple",
                "requests",
            ]
        )

        assert intention is not None

        # Value options should be parsed correctly
        assert "python" in intention.options
        assert intention.options["python"]["value"] == "3.9"
        assert "index-url" in intention.options
        assert intention.options["index-url"]["value"] == "https://pypi.org/simple"

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_uv_parser_multiple_packages_with_specs(self):
        """
        Test parsing multiple packages with version specifications
        """
        intention = self.parser.parse(["add", "requests>=2.25.1", "django"])

        assert intention is not None
        assert len(intention.packages) == 2

        # Check each package
        assert intention.packages[0].name == "requests"
        assert intention.packages[0].version_constraint == ">=2.25.1"

        assert intention.packages[1].name == "django"

    def test_uv_parser_complex_pip_install_command(self):
        """
        Test complex UV pip install command
        """
        intention = self.parser.parse(
            [
                "pip",
                "install",
                "--upgrade",
                "--user",
                "--index-url",
                "https://custom.pypi.org",
                "--no-build-isolation",
                "requests>=2.25.1",
                "flask",
            ]
        )

        assert intention is not None
        assert intention.command_chain == ["pip", "install"]
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE

        # Check flags
        assert intention.options["upgrade"]["value"] is True
        assert intention.options["user"]["value"] is True
        assert intention.options["no-build-isolation"]["value"] is True

        # Check value option
        assert intention.options["index-url"]["value"] == "https://custom.pypi.org"

        # Check packages
        assert len(intention.packages) == 2
        assert intention.packages[0].name == "requests"
        assert intention.packages[1].name == "flask"

    def test_uv_parser_invalid_command_returns_none(self):
        """
        Test invalid UV commands return None
        """
        intention = self.parser.parse(["invalid-command", "requests"])
        assert intention is None
