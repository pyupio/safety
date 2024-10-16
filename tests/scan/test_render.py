import os
import unittest
from unittest.mock import MagicMock, Mock, call, patch
from pathlib import Path
import datetime

from safety.scan.render import print_announcements, print_summary, render_header
from safety_schemas.models import ProjectModel, IgnoreCodes, PolicySource

class TestRender(unittest.TestCase):

    def setUp(self):
        self.console = MagicMock()
        self.project = ProjectModel(id='test-project')
        self.project.policy = MagicMock()
        self.project.policy.source = PolicySource.cloud

    @patch('safety.scan.render.get_safety_version')
    def test_render_header(self, mock_get_safety_version):
        mock_get_safety_version.return_value = '3.0.0'

        datetime_mock = Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

        test_cases = [
            ([Path('/target1'), Path('/target2')], False, 'Safety 3.0.0 scanning {0}, {1}\n2025-01-01 00:00:00 UTC'),
            ([Path('/target1')], False, 'Safety 3.0.0 scanning {0}\n2025-01-01 00:00:00 UTC'),
            ([], False, 'Safety 3.0.0 scanning \n2025-01-01 00:00:00 UTC'),
            ([Path('/target1'), Path('/target2')], True, 'Safety 3.0.0 running system scan\n2025-01-01 00:00:00 UTC'),
        ]

        for targets, is_system_scan, expected_result in test_cases:
            with patch('datetime.datetime', new=datetime_mock):
                # Normalize paths to POSIX format (use forward slashes)
                posix_targets = [t.as_posix() for t in targets]
                result = str(render_header(targets, is_system_scan))

                # On Windows, convert backslashes to forward slashes in the result for comparison
                if os.name == 'nt':
                    result = result.replace('\\', '/')

                expected = expected_result.format(*posix_targets)
                self.assertEqual(result, expected)

    @patch('safety.scan.render.safety.get_announcements')
    @patch('safety.scan.render.get_basic_announcements')
    @patch('safety.scan.render.Console')
    def test_print_announcements(self, mock_console, mock_get_basic_announcements, mock_get_announcements):
        
        mock_get_announcements.return_value = [
            {'type': 'info', 'message': 'Info message'},
            {'type': 'warning', 'message': 'Warning message'},
            {'type': 'error', 'message': 'Error message'},
        ]
        
        mock_get_basic_announcements.return_value = mock_get_announcements.return_value
        console = mock_console.return_value
        
        ctx = MagicMock()
        ctx.obj.auth.client = MagicMock()
        ctx.obj.config.telemetry_enabled = False
        ctx.obj.telemetry = MagicMock()
        
        print_announcements(console, ctx)

        # Include empty calls and correct sequence
        console.print.assert_has_calls([
            call(),
            call("[bold]Safety Announcements:[/bold]"),
            call(),
            call("[default]* Info message[/default]"),
            call("[yellow]* Warning message[/yellow]"),
            call("[red]* Error message[/red]")
        ])


    @patch('safety.scan.render.render_to_console')
    def test_print_summary(self, mock_render_to_console):
        ignored_vulns_data = [
            MagicMock(ignored_code=IgnoreCodes.manual.value, vulnerability_id='v1', package_name='p1'),
            MagicMock(ignored_code=IgnoreCodes.cvss_severity.value, vulnerability_id='v2', package_name='p2'),
            MagicMock(ignored_code=IgnoreCodes.unpinned_specification.value, vulnerability_id='v3', package_name='p3'),
            MagicMock(ignored_code=IgnoreCodes.environment_dependency.value, vulnerability_id='v4', package_name='p4'),
        ]

        print_summary(
            self.console,
            total_issues_with_duplicates=0,
            total_ignored_issues=0,
            project=self.project,
            dependencies_count=5,
            fixes_count=0,
            resolved_vulns_per_fix=0,
            ignored_vulns_data=ignored_vulns_data
        )

        self.console.print.assert_has_calls([
            call('Tested [number]5[/number] dependencies for security issues using policy fetched from Safety Platform'),
            call('0 security issues found, 0 fixes suggested.'),
            call('[number]0[/number] fixes suggested, resolving [number]0[/number] vulnerabilities.')
        ])

        print_summary(
            self.console,
            total_issues_with_duplicates=0,
            total_ignored_issues=0,
            project=self.project,
            dependencies_count=5,
            fixes_count=0,
            resolved_vulns_per_fix=0
        )

        self.console.print.assert_has_calls([
            call('Tested [number]5[/number] dependencies for security issues using policy fetched from Safety Platform'),
            call('0 security issues found, 0 fixes suggested.'),
            call('[number]0[/number] fixes suggested, resolving [number]0[/number] vulnerabilities.')
        ])

if __name__ == '__main__':
    unittest.main()
