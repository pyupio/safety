"""
Test suite for PipParser functionality.
"""

import pytest

from safety.tool.pip.parser import PipParser
from safety.tool.intents import ToolIntentionType


@pytest.mark.unit
class TestPipParser:
    """
    Test pip-specific parser functionality
    """

    def setup_method(self):
        self.parser = PipParser()

    def test_pip_parser_respects_command_hierarchy_multilevel(self):
        """
        Test pip install command recognition
        """
        intention = self.parser.parse(["install", "requests"])

        assert intention is not None
        assert intention.tool == "pip"
        assert intention.command == "install"
        assert intention.command_chain == ["install"]
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_download_intention_for_pip_download_and_wheel(self):
        """
        Test DOWNLOAD_PACKAGE intention for download and wheel commands
        """
        # Test download command
        download_intention = self.parser.parse(["download", "requests"])

        assert download_intention is not None
        assert download_intention.intention_type == ToolIntentionType.DOWNLOAD_PACKAGE
        assert download_intention.command == "download"
        assert len(download_intention.packages) == 1
        assert download_intention.packages[0].name == "requests"

        # Test wheel command
        wheel_intention = self.parser.parse(["wheel", "requests"])

        assert wheel_intention is not None
        assert wheel_intention.intention_type == ToolIntentionType.DOWNLOAD_PACKAGE
        assert wheel_intention.command == "wheel"
        assert len(wheel_intention.packages) == 1
        assert wheel_intention.packages[0].name == "requests"

    def test_pip_parser_uninstall_intention(self):
        """
        Test REMOVE_PACKAGE intention for uninstall command
        """
        intention = self.parser.parse(["uninstall", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.REMOVE_PACKAGE
        assert intention.command == "uninstall"
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_install_flags_dont_consume_packages(self):
        """
        Test install-specific flags don't consume package names
        """
        intention = self.parser.parse(["install", "--upgrade", "--user", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE

        # Flags should be parsed correctly
        assert "upgrade" in intention.options
        assert intention.options["upgrade"]["value"] is True
        assert "user" in intention.options
        assert intention.options["user"]["value"] is True

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_force_reinstall_flag(self):
        """
        Test --force-reinstall flag parsing
        """
        intention = self.parser.parse(["install", "--force-reinstall", "requests"])

        assert intention is not None
        assert "force-reinstall" in intention.options
        assert intention.options["force-reinstall"]["value"] is True
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_no_deps_flag(self):
        """
        Test --no-deps flag parsing
        """
        intention = self.parser.parse(["install", "--no-deps", "requests"])

        assert intention is not None
        assert "no-deps" in intention.options
        assert intention.options["no-deps"]["value"] is True
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_short_flags(self):
        """
        Test short flag variants like -U for --upgrade
        """
        intention = self.parser.parse(["install", "-U", "-v", "requests"])

        assert intention is not None

        # Short flags should be recognized
        assert "U" in intention.options
        assert intention.options["U"]["value"] is True
        assert "v" in intention.options
        assert intention.options["v"]["value"] is True

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_uninstall_yes_flag(self):
        """
        Test uninstall -y/--yes flag
        """
        intention = self.parser.parse(["uninstall", "--yes", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.REMOVE_PACKAGE
        assert "yes" in intention.options
        assert intention.options["yes"]["value"] is True
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_download_flags(self):
        """
        Test download-specific flags
        """
        intention = self.parser.parse(["download", "--no-deps", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.DOWNLOAD_PACKAGE

        assert "no-deps" in intention.options
        assert intention.options["no-deps"]["value"] is True

        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_global_flags(self):
        """
        Test global flags work across commands
        """
        # Test with install
        install_intention = self.parser.parse(["install", "--verbose", "requests"])

        assert install_intention is not None
        assert "verbose" in install_intention.options
        assert install_intention.options["verbose"]["value"] is True

        # Test with uninstall
        uninstall_intention = self.parser.parse(["uninstall", "--quiet", "requests"])

        assert uninstall_intention is not None
        assert "quiet" in uninstall_intention.options
        assert uninstall_intention.options["quiet"]["value"] is True

    def test_pip_parser_value_options(self):
        """
        Test options that take values
        """
        intention = self.parser.parse(
            [
                "install",
                "--index-url",
                "https://pypi.org/simple",
                "--target",
                "/custom/path",
                "requests",
            ]
        )

        assert intention is not None

        # Value options should be parsed correctly
        assert "index-url" in intention.options
        assert intention.options["index-url"]["value"] == "https://pypi.org/simple"
        assert "target" in intention.options
        assert intention.options["target"]["value"] == "/custom/path"

        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    def test_pip_parser_equals_format_options(self):
        """
        Test --option=value format
        """
        intention = self.parser.parse(
            ["install", "--index-url=https://pypi.org/simple", "requests"]
        )

        assert intention is not None
        assert "index-url" in intention.options
        assert intention.options["index-url"]["value"] == "https://pypi.org/simple"
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"

    @pytest.mark.parametrize(
        "pkg_spec,expected_name",
        [
            ("requests", "requests"),
            (
                "requests[security,socks,use_chardet_on_py3] >= 2.25.0, != 2.26.0, < 3.0.0 ; python_version >= '3.8' and python_version < '3.12' and platform_system == 'Linux' and implementation_name == 'cpython' and platform_machine in 'x86_64 aarch64' and sys_platform != 'win32' and os_name == 'posix' and platform_release >= '5.0' and extra == 'dev' and python_full_version >= '3.8.5'",
                "requests",
            ),
        ],
    )
    def test_pip_parser_short_index_url_option_with_indices(
        self, pkg_spec, expected_name
    ):
        """
        Test short -i option for index-url, ensuring value and indices are set,
        for both simple and complex requirement specs.
        """
        args = ["install", "-i", "https://pypi.org/simple", pkg_spec]
        intention = self.parser.parse(args)

        assert intention is not None
        # Short option should be captured under key 'i'
        assert "i" in intention.options
        opt = intention.options["i"]
        assert opt["value"] == "https://pypi.org/simple"
        # arg_index/value_index should point to original args positions
        # remaining_args_start is 1 (after 'install'), so indices are 1 and 2
        assert opt.get("arg_index") == 1
        assert opt.get("value_index") == 2
        # Package should still be parsed
        assert len(intention.packages) == 1
        assert intention.packages[0].name == expected_name

    def test_pip_parser_multiple_packages(self):
        """
        Test parsing multiple packages
        """
        intention = self.parser.parse(
            ["install", "requests>=2.25.1", "flask==2.0.1", "django[redis]"]
        )

        assert intention is not None
        assert len(intention.packages) == 3

        # Check each package
        assert intention.packages[0].name == "requests"
        assert intention.packages[0].version_constraint == ">=2.25.1"

        assert intention.packages[1].name == "flask"
        assert intention.packages[1].version_constraint == "==2.0.1"

        assert intention.packages[2].name == "django"
        assert "redis" in intention.packages[2].extras

    def test_pip_parser_complex_command(self):
        """
        Test complex pip command with multiple options and packages
        """
        intention = self.parser.parse(
            [
                "install",
                "--upgrade",
                "--user",
                "--index-url",
                "https://custom.pypi.org",
                "--no-deps",
                "requests>=2.25.1",
                "flask",
            ]
        )

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.ADD_PACKAGE

        # Check flags
        assert intention.options["upgrade"]["value"] is True
        assert intention.options["user"]["value"] is True
        assert intention.options["no-deps"]["value"] is True

        # Check value option
        assert intention.options["index-url"]["value"] == "https://custom.pypi.org"

        # Check packages
        assert len(intention.packages) == 2
        assert intention.packages[0].name == "requests"
        assert intention.packages[1].name == "flask"

    def test_pip_parser_invalid_command_returns_none(self):
        """
        Test invalid pip commands return None
        """
        intention = self.parser.parse(["invalid-command", "requests"])
        assert intention is None

    def test_pip_parser_index_versions_is_search_with_package(self):
        """
        Test that 'index versions <pkg>' is categorized as SEARCH_PACKAGES and parses the package
        """
        intention = self.parser.parse(["index", "versions", "requests"])

        assert intention is not None
        assert intention.intention_type == ToolIntentionType.SEARCH_PACKAGES
        assert intention.command_chain == ["index", "versions"]
        assert len(intention.packages) == 1
        assert intention.packages[0].name == "requests"
