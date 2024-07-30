import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from rich.console import Console
from safety.errors import SafetyException
from safety.scan.models import ScanOutput, SystemScanOutput
from safety_schemas.models import ConfigModel, ProjectModel, PolicySource, ScanType, MetadataModel, ReportSchemaVersion, TelemetryModel

from safety.scan.decorators import (
    initialize_scan,
    scan_project_command_init,
    scan_system_command_init,
    inject_metadata
)

class TestInitializeScan(unittest.TestCase):

    @patch('safety.scan.decorators.LOG')
    def test_initialize_scan(self, mock_log):
        ctx = MagicMock()
        ctx.obj.auth.client.initialize_scan.return_value = {'platform-enabled': True}
        console = MagicMock()
        initialize_scan(ctx, console)
        self.assertTrue(ctx.obj.platform_enabled)
        ctx.obj.auth.client.initialize_scan.assert_called_once()

class TestScanProjectCommandInit(unittest.TestCase):

    @patch('safety.scan.decorators.load_unverified_project_from_config')
    @patch('safety.scan.decorators.print_header')
    @patch('safety.scan.decorators.verify_project')
    @patch('safety.scan.decorators.load_policy_file')
    @patch('safety.scan.decorators.resolve_policy')
    @patch('safety.scan.decorators.print_announcements')
    @patch('safety.scan.decorators.initialize_scan')
    def test_scan_project_command_init(self, mock_initialize_scan, mock_print_announcements, mock_resolve_policy, mock_load_policy_file, mock_verify_project, mock_print_header, mock_load_unverified_project_from_config):
        mock_load_unverified_project_from_config.return_value = MagicMock()
        mock_resolve_policy.return_value = MagicMock()
        mock_load_policy_file.return_value = MagicMock()
        mock_verify_project.return_value = MagicMock()

        @scan_project_command_init
        def dummy_func(ctx, target, output, *args, **kwargs):
            return "scan project"

        ctx = MagicMock()
        ctx.obj.auth.stage = "development"
        ctx.obj.telemetry = TelemetryModel(
            safety_options={},
            safety_version="1.0.0",
            safety_source="CLI",
            os_type="Linux",
            os_release="5.4.0",
            os_description="Linux-5.4.0-42-generic-x86_64-with-Ubuntu-20.04-focal",
            python_version="3.8.5",
            safety_command="scan"
        )
        policy_file_path = None
        target = Path("/path/to/target")
        output = MagicMock(spec=ScanOutput)
        output.is_silent = MagicMock(return_value=False)
        console = MagicMock(spec=Console)

        result = dummy_func(ctx, policy_file_path, target, output, console)
        self.assertEqual(result, "scan project")
        mock_initialize_scan.assert_called_once()
        mock_print_announcements.assert_called_once()
        mock_print_header.assert_called_once()


class TestInjectMetadata(unittest.TestCase):

    def test_inject_metadata(self):

        @inject_metadata
        def dummy_func(ctx, *args, **kwargs):
            return "metadata injected"

        ctx = MagicMock()
        ctx.command.name = "scan"
        ctx.invoked_subcommand = None
        ctx.obj.auth.stage = "development"
        ctx.obj.auth.client.get_authentication_type.return_value = "api_key"
        ctx.obj.auth.client.is_using_auth_credentials.return_value = True

        target = Path("/path/to/target")
        kwargs = {"target": target}

        result = dummy_func(ctx, **kwargs)
        self.assertEqual(result, "metadata injected")
        self.assertEqual(ctx.obj.metadata.scan_type, ScanType.scan)
        self.assertEqual(ctx.obj.metadata.scan_locations, [target])
        self.assertEqual(ctx.obj.metadata.authenticated, True)

if __name__ == '__main__':
    unittest.main()
