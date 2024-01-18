import unittest
from unittest import mock
from unittest.mock import MagicMock, Mock, patch
from pathlib import Path
import datetime

from safety.scan.render import print_announcements, print_ignore_details, render_header
from safety_schemas.models import ProjectModel, IgnoreCodes

class TestRender(unittest.TestCase):
    @patch('safety.scan.render.get_safety_version')
    def test_render_header(self, mock_get_safety_version):
        mock_get_safety_version.return_value = '3.0.0'

        datetime_mock = Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

        with patch('datetime.datetime', new=datetime_mock) as mock_now:
            mock_now.return_value = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

            # Project scan
            targets = [Path('/target1'), Path('/target2')]
            expected_result = f'Safety 3.0.0 scanning {targets[0]}, {targets[1]}\n2025-01-01 00:00:00 UTC'
            self.assertEqual(str(render_header(targets, False)), expected_result)

            # System Scan
            expected_result = 'Safety 3.0.0 running system scan\n2025-01-01 00:00:00 UTC'
            self.assertEqual(str(render_header(targets, True)), expected_result)

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

        console.print.assert_any_call()
        console.print.assert_any_call("[bold]Safety Announcements:[/bold]")
        console.print.assert_any_call()
        console.print.assert_any_call("[default]* Info message[/default]")
        console.print.assert_any_call("[yellow]* Warning message[/yellow]")
        console.print.assert_any_call("[red]* Error message[/red]")    


    @patch('safety.scan.render.render_to_console')
    def test_print_ignore_details(self, render_to_console_mocked):
        render_to_console_mocked.return_value = "render_to_console_mocked"
        from safety.console import main_console
        console = MagicMock(wraps=main_console)
        console.print = MagicMock()

        # Create a fake project
        project = ProjectModel(id='prj-id')

        # Create a fake ignored vulnerabilities data
        ignored_vulns_data = [
            MagicMock(ignored_code=IgnoreCodes.manual.value, vulnerability_id='v1', package_name='p1'),
            MagicMock(ignored_code=IgnoreCodes.cvss_severity.value, vulnerability_id='v2', package_name='p2'),
            MagicMock(ignored_code=IgnoreCodes.unpinned_specification.value, vulnerability_id='v3', package_name='p3'),
            MagicMock(ignored_code=IgnoreCodes.environment_dependency.value, vulnerability_id='v4', package_name='p4'),
        ]

        # Call the function
        print_ignore_details(console, project, [], True, ignored_vulns_data)

        # Check that the console.print method was called with the expected arguments
        console.print.assert_any_call("[number]1[/number] were manually ignored due to the project policy:")
        console.print.assert_any_call("[number]1[/number] vulnerability was ignored because of their severity or exploitability impacted the following package: p2")
        console.print.assert_any_call("[number]1[/number] vulnerability was ignored because they are inside an environment dependency.")
        console.print.assert_any_call("[number]1[/number] vulnerability was ignored because this package has unpinned specs: p3")
