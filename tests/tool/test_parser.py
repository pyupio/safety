"""
Test suite for the base ToolCommandLineParser functionality.
"""

import pytest

from safety.tool.base import ToolCommandLineParser
from safety.tool.intents import ToolIntentionType


class MockParser(ToolCommandLineParser):
    """Mock parser for testing base functionality"""

    def get_tool_name(self) -> str:
        return "test-tool"

    def get_command_hierarchy(self):
        return {
            "install": ToolIntentionType.ADD_PACKAGE,
            "remove": ToolIntentionType.REMOVE_PACKAGE,
            "pip": {
                "install": ToolIntentionType.ADD_PACKAGE,
                "uninstall": ToolIntentionType.REMOVE_PACKAGE,
            },
        }

    def get_known_flags(self):
        return {
            "global": {"verbose", "v", "quiet", "q", "help", "h"},
            "install": {"upgrade", "no-deps", "user"},
            "pip.install": {"upgrade", "force-reinstall", "user"},
        }


@pytest.mark.unit
class TestToolCommandLineParser:
    """Test base parser functionality"""

    def setup_method(self):
        """Set up test fixtures"""
        self.parser = MockParser()

    def test_parser_known_flag_without_value_does_not_consume_next_arg(self):
        """Ensure flags like --upgrade don't consume package names"""
        intention = self.parser.parse(["install", "--upgrade", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"
        assert "upgrade" in intention.options
        assert intention.options["upgrade"]["value"] is True

    def test_parser_option_equals_value_form_is_parsed(self):
        """Test --index-url=https://... format"""
        intention = self.parser.parse(
            ["install", "--index-url=https://pypi.org/simple", "requests"]
        )

        assert intention is not None
        assert "index-url" in intention.options
        assert intention.options["index-url"]["value"] == "https://pypi.org/simple"
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_parser_option_space_value_form_is_parsed(self):
        """Test --index-url https://... format"""
        intention = self.parser.parse(
            ["install", "--index-url", "https://pypi.org/simple", "requests"]
        )

        assert intention is not None
        assert "index-url" in intention.options
        assert intention.options["index-url"]["value"] == "https://pypi.org/simple"
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_parser_unknown_dash_arg_stored_as_unknown(self):
        """Unknown dash args recorded with arg_index"""
        intention = self.parser.parse(["install", "--unknown-option", "requests"])

        assert intention is not None
        assert "unknown-option" in intention.options
        # Unknown option followed by non-dash arg will consume the next arg as value
        assert intention.options["unknown-option"]["value"] == "requests"
        assert "arg_index" in intention.options["unknown-option"]
        assert len(intention.packages) == 0  # requests was consumed as option value

    def test_parser_packages_extracted_with_arg_index_and_spec(self):
        """Package specs parsed correctly when valid"""
        intention = self.parser.parse(["install", "requests>=2.25.1", "flask==2.0.1"])

        assert intention is not None
        assert len(intention.packages) == 2

        # First package
        pkg1 = intention.packages[0]
        assert pkg1.name == "requests"
        assert pkg1.version_constraint == ">=2.25.1"
        assert pkg1.original_text == "requests>=2.25.1"
        assert pkg1.arg_index == 1

        # Second package
        pkg2 = intention.packages[1]
        assert pkg2.name == "flask"
        assert pkg2.version_constraint == "==2.0.1"
        assert pkg2.original_text == "flask==2.0.1"
        assert pkg2.arg_index == 2

    def test_parser_multilevel_command_hierarchy_parsed(self):
        """Test pip install command recognition"""
        intention = self.parser.parse(["pip", "install", "requests"])

        assert intention is not None
        assert intention.command_chain == ["pip", "install"]
        assert intention.command == "pip install"
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_parser_command_specific_flags_override_global(self):
        """Command-specific flags take precedence over global flags"""
        intention = self.parser.parse(["pip", "install", "--upgrade", "requests"])

        assert intention is not None
        assert "upgrade" in intention.options
        assert intention.options["upgrade"]["value"] is True
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_parser_invalid_command_returns_none(self):
        """Invalid commands return None"""
        intention = self.parser.parse(["invalid-command", "requests"])

        assert intention is None

    def test_parser_empty_args_returns_none(self):
        """Empty arguments return None"""
        intention = self.parser.parse([])

        assert intention is None

    def test_parser_non_package_intentions_dont_parse_packages(self):
        """Non-package intentions store args as unknown"""
        # Add a non-package intention to our mock
        self.parser.get_command_hierarchy = lambda: {
            "sync": ToolIntentionType.SYNC_PACKAGES,
            "install": ToolIntentionType.ADD_PACKAGE,
        }

        intention = self.parser.parse(["sync", "some-arg"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.SYNC_PACKAGES
        assert len(intention.packages) == 0
        assert "unknown_0" in intention.options
        assert intention.options["unknown_0"]["value"] == "some-arg"

    def test_parser_raw_args_preserved(self):
        """Original raw arguments are preserved"""
        args = ["install", "--upgrade", "requests>=2.0"]
        intention = self.parser.parse(args)

        assert intention is not None
        assert intention.raw_args == args
        # Ensure original args are not modified
        assert args == ["install", "--upgrade", "requests>=2.0"]

    def test_parser_arg_indices_correct(self):
        """Argument indices are correctly tracked"""
        intention = self.parser.parse(
            ["install", "--verbose", "--index-url", "https://pypi.org", "requests"]
        )

        assert intention is not None

        # Option indices
        assert intention.options["verbose"]["arg_index"] == 1
        assert intention.options["index-url"]["arg_index"] == 2
        assert intention.options["index-url"]["value_index"] == 3

        # Package index
        assert intention.packages[0].arg_index == 4

    def test_parser_mixed_flags_and_options(self):
        """Mix of boolean flags and value options parsed correctly"""
        intention = self.parser.parse(
            [
                "install",
                "--upgrade",
                "--index-url",
                "https://custom.pypi.org",
                "--user",
                "requests",
                "flask",
            ]
        )

        assert intention is not None

        # Boolean flags
        assert intention.options["upgrade"]["value"] is True
        assert intention.options["user"]["value"] is True

        # Value option
        assert intention.options["index-url"]["value"] == "https://custom.pypi.org"

        # Packages
        assert len(intention.packages) == 2
        assert intention.packages[0].name == "requests"
        assert intention.packages[1].name == "flask"

    def test_parser_tool_name_set(self):
        """Parser correctly sets tool name in intention"""
        intention = self.parser.parse(["install", "requests"])

        assert intention is not None
        assert intention.tool == "test-tool"
