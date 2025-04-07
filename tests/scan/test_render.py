# type: ignore
import os
import unittest
from unittest.mock import MagicMock, Mock, call, patch
from pathlib import Path
import datetime

from safety.scan.render import (
    print_announcements,
    print_summary,
    render_header,
    prompt_project_id,
)
from safety_schemas.models import ProjectModel, IgnoreCodes, PolicySource


class TestRender(unittest.TestCase):
    def setUp(self):
        self.console = MagicMock()
        self.project = ProjectModel(id="test-project")
        self.project.policy = MagicMock()
        self.project.policy.source = PolicySource.cloud

    @patch("safety.scan.render.get_version")
    def test_render_header(self, mock_get_safety_version):
        mock_get_safety_version.return_value = "3.0.0"

        datetime_mock = Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(
            2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        )

        test_cases = [
            (
                [Path("/target1"), Path("/target2")],
                False,
                "Safety 3.0.0 scanning {0}, {1}\n2025-01-01 00:00:00 UTC",
            ),
            (
                [Path("/target1")],
                False,
                "Safety 3.0.0 scanning {0}\n2025-01-01 00:00:00 UTC",
            ),
            ([], False, "Safety 3.0.0 scanning \n2025-01-01 00:00:00 UTC"),
            (
                [Path("/target1"), Path("/target2")],
                True,
                "Safety 3.0.0 running system scan\n2025-01-01 00:00:00 UTC",
            ),
        ]

        for targets, is_system_scan, expected_result in test_cases:
            with patch("datetime.datetime", new=datetime_mock):
                # Normalize paths to POSIX format (use forward slashes)
                posix_targets = [t.as_posix() for t in targets]
                result = str(render_header(targets, is_system_scan))

                # On Windows, convert backslashes to forward slashes in the result for comparison
                if os.name == "nt":
                    result = result.replace("\\", "/")

                expected = expected_result.format(*posix_targets)
                self.assertEqual(result, expected)

    @patch("safety.scan.render.safety.get_announcements")
    @patch("safety.scan.render.get_basic_announcements")
    @patch("safety.scan.render.Console")
    def test_print_announcements(
        self, mock_console, mock_get_basic_announcements, mock_get_announcements
    ):
        mock_get_announcements.return_value = [
            {"type": "info", "message": "Info message"},
            {"type": "warning", "message": "Warning message"},
            {"type": "error", "message": "Error message"},
        ]

        mock_get_basic_announcements.return_value = mock_get_announcements.return_value
        console = mock_console.return_value

        ctx = MagicMock()
        ctx.obj.auth.client = MagicMock()
        ctx.obj.config.telemetry_enabled = False
        ctx.obj.telemetry = MagicMock()

        print_announcements(console, ctx)

        # Include empty calls and correct sequence
        console.print.assert_has_calls(
            [
                call(),
                call("[bold]Safety Announcements:[/bold]"),
                call(),
                call("[default]* Info message[/default]"),
                call("[yellow]* Warning message[/yellow]"),
                call("[red]* Error message[/red]"),
            ]
        )

    @patch("safety.scan.render.render_to_console")
    def test_print_summary(self, mock_render_to_console):
        ignored_vulns_data = [
            MagicMock(
                ignored_code=IgnoreCodes.manual.value,
                vulnerability_id="v1",
                package_name="p1",
            ),
            MagicMock(
                ignored_code=IgnoreCodes.cvss_severity.value,
                vulnerability_id="v2",
                package_name="p2",
            ),
            MagicMock(
                ignored_code=IgnoreCodes.unpinned_specification.value,
                vulnerability_id="v3",
                package_name="p3",
            ),
            MagicMock(
                ignored_code=IgnoreCodes.environment_dependency.value,
                vulnerability_id="v4",
                package_name="p4",
            ),
        ]

        print_summary(
            self.console,
            total_issues_with_duplicates=0,
            total_ignored_issues=0,
            project=self.project,
            dependencies_count=5,
            fixes_count=0,
            resolved_vulns_per_fix=0,
            ignored_vulns_data=ignored_vulns_data,
        )

        self.console.print.assert_has_calls(
            [
                call(
                    "Tested [number]5[/number] dependencies for security issues using policy fetched from Safety Platform"
                ),
                call("0 security issues found, 0 fixes suggested."),
                call(
                    "[number]0[/number] fixes suggested, resolving [number]0[/number] vulnerabilities."
                ),
            ]
        )

        print_summary(
            self.console,
            total_issues_with_duplicates=0,
            total_ignored_issues=0,
            project=self.project,
            dependencies_count=5,
            fixes_count=0,
            resolved_vulns_per_fix=0,
        )

        self.console.print.assert_has_calls(
            [
                call(
                    "Tested [number]5[/number] dependencies for security issues using policy fetched from Safety Platform"
                ),
                call("0 security issues found, 0 fixes suggested."),
                call(
                    "[number]0[/number] fixes suggested, resolving [number]0[/number] vulnerabilities."
                ),
            ]
        )

    @patch("safety.scan.render.clean_project_id")
    def test_prompt_project_id_non_interactive(self, clean_project_id):
        """
        Under these cases, the default project ID should be cleaned and
        returned. The prompt should not be shown.
        """

        test_cases = [
            # Non-interactive mode
            (True, False, "default_a", "default_a_cleaned"),
            # Quiet mode like JSON output under interactive mode
            (True, True, "default_b", "default_b_cleaned"),
            # No Quiet and Not interactive mode
            (False, False, "default_c", "default_c_cleaned"),
        ]

        for quiet, is_interactive, default_id, expected_result in test_cases:
            with self.subTest(quiet=quiet, is_interactive=is_interactive):
                clean_project_id.return_value = f"{default_id}_cleaned"
                console = MagicMock(quiet=quiet, is_interactive=is_interactive)

                result = prompt_project_id(console, default_id)

                assert result == expected_result

                assert result == expected_result, (
                    f"Failed for quiet={quiet}, "
                    f"is_interactive={is_interactive}\n"
                    f"Expected: {expected_result}\n"
                    f"Got: {result}\n"
                    f"Default ID was: {default_id}"
                )

                try:
                    clean_project_id.assert_called_once_with(default_id)
                except AssertionError:
                    raise AssertionError(
                        f"Mock wasn't called correctly for "
                        f"quiet={quiet}, is_interactive={is_interactive}\n"
                        f"Expected (1) call with: {default_id}\n"
                        f"Actual calls were "
                        f"({len(clean_project_id.call_args_list)}): "
                        f"{clean_project_id.call_args_list}"
                    )

                clean_project_id.reset_mock()

    @patch("safety.scan.render.clean_project_id")
    def test_prompt_project_id_interactive(self, clean_project_id):
        default_id = "default-project"
        default_id_cleaned = f"{default_id}_cleaned"

        test_cases = [
            ("custom-project", "custom-project_cleaned"),
            ("", default_id_cleaned),
        ]

        for user_input, expected in test_cases:
            with self.subTest(user_input=user_input):
                console = MagicMock(quiet=False, is_interactive=True)

                clean_project_id.side_effect = lambda input_string: (
                    f"{input_string}_cleaned"
                )

                with patch("safety.scan.render.Prompt.ask") as ask:
                    # We mimic the behavior of Prompt.ask on empty input
                    ask.side_effect = lambda *args, **kwargs: (
                        kwargs["default"] if user_input == "" else user_input
                    )

                    result = prompt_project_id(console, default_id)

                    # Verify Prompt.ask was called correctly
                    ask.assert_called_once_with(
                        f"\nEnter a name for this codebase (or press [bold]Enter[/bold] to use '\\[{default_id_cleaned}]')",
                        console=console,
                        default=default_id_cleaned,
                        show_default=False,
                    )

                    calls = [call(default_id)]
                    call_count = 1

                    if user_input != "":
                        calls.append(call(user_input))
                        call_count = 2

                    clean_project_id.assert_has_calls(calls)
                    assert clean_project_id.call_count == call_count

                    print(result, expected)
                    assert result == expected

                # Reset mocks for next test case
                clean_project_id.reset_mock()
