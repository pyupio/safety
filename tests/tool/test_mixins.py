# type: ignore

import pytest
from unittest.mock import MagicMock, patch
from typing import List, Tuple, Optional

import typer

from safety.models import ToolResult
from safety.tool.mixins import InstallationAuditMixin
from safety.tool.environment_diff import EnvironmentDiffTracker


class MockAuditableCommand(InstallationAuditMixin):
    """
    Mock implementation of an auditable command.
    """

    def __init__(self, packages=None, diff_data=None):
        self._mock_packages = packages or []
        self._mock_diff_data = diff_data or ({}, {}, {})

    @property
    def _diff_tracker(self) -> "EnvironmentDiffTracker":
        mock_tracker = MagicMock(spec=EnvironmentDiffTracker)
        mock_tracker.get_diff.return_value = self._mock_diff_data
        return mock_tracker

    @property
    def _packages(self) -> List[Tuple[str, Optional[str]]]:
        return self._mock_packages


class TestInstallationAuditMixin:
    """
    Test suite for InstallationAuditMixin functionality.
    """

    def setup_method(self):
        """
        Set up test fixtures.
        """
        self.ctx = MagicMock(spec=typer.Context)
        self.ctx.obj = MagicMock()
        self.ctx.obj.auth = MagicMock()
        self.ctx.obj.auth.client = MagicMock()
        self.result = MagicMock(spec=ToolResult)
        self.result.process = MagicMock()
        self.result.process.returncode = 0
        self.result.duration_ms = 100  # Add the missing duration_ms attribute

    @patch("safety.tool.mixins.console")
    def test_audit_packages_with_diff(self, mock_console):
        """
        Test audit_packages method with diff tracker.
        """
        added_packages = {"package1": "1.0.0", "package2": "2.0.0"}
        updated_packages = {"package3": "3.0.0"}
        diff_data = (added_packages, {}, updated_packages)  # (added, removed, updated)

        command = MockAuditableCommand(diff_data=diff_data)
        self.ctx.obj.auth.client.audit_packages.return_value = {
            "audit": {
                "packages": [
                    {
                        "package_specifier": "package1==1.0.0",
                        "vulnerabilities": {"critical": 2, "high": 1},
                    }
                ]
            }
        }

        result = command.audit_packages(self.ctx)

        self.ctx.obj.auth.client.audit_packages.assert_called_once()
        expected_packages = ["package1==1.0.0", "package2==2.0.0", "package3==3.0.0"]
        actual_packages = self.ctx.obj.auth.client.audit_packages.call_args[0][0]
        assert sorted(actual_packages) == sorted(expected_packages)
        assert result == self.ctx.obj.auth.client.audit_packages.return_value

    @patch("safety.tool.mixins.console")
    def test_audit_packages_with_tuple_version(self, mock_console):
        """
        Test audit_packages method with tuple version.
        """
        added_packages = {"package1": ("0.9.0", "1.0.0")}
        diff_data = (added_packages, {}, {})

        command = MockAuditableCommand(diff_data=diff_data)
        self.ctx.obj.auth.client.audit_packages.return_value = {
            "audit": {"packages": []}
        }

        result = command.audit_packages(self.ctx)

        self.ctx.obj.auth.client.audit_packages.assert_called_once_with(
            ["package1==1.0.0"]
        )
        assert result == self.ctx.obj.auth.client.audit_packages.return_value

    @patch("safety.tool.mixins.console")
    def test_audit_packages_without_auth(self, mock_console):
        """
        Test audit_packages method without auth client.
        """
        command = MockAuditableCommand()
        self.ctx.obj.auth = None

        result = command.audit_packages(self.ctx)

        assert result == {}

    @patch("safety.tool.mixins.console")
    def test_audit_packages_with_exception(self, mock_console):
        """
        Test audit_packages method with exception.
        """
        command = MockAuditableCommand(diff_data=({"package1": "1.0.0"}, {}, {}))
        self.ctx.obj.auth.client.audit_packages.side_effect = Exception("API error")

        result = command.audit_packages(self.ctx)

        assert result == {}

    @patch("safety.tool.mixins.console")
    @patch("safety.tool.mixins.render_header")
    @patch("safety.tool.mixins.progressive_print")
    def test_render_installation_warnings_with_vulnerabilities(
        self, mock_progressive_print, mock_render_header, mock_console
    ):
        """
        Test render_installation_warnings with vulnerability data.
        """
        command = MockAuditableCommand()
        packages_audit = {
            "audit": {
                "packages": [
                    {
                        "package_specifier": "vulnerable-package==1.0.0",
                        "vulnerabilities": {"critical": 2, "high": 1, "medium": 3},
                    },
                    {
                        "package_specifier": "safe-package==2.0.0",
                        "vulnerabilities": {},  # A backend mismatch
                    },
                ]
            }
        }

        command.render_installation_warnings(self.ctx, packages_audit)

        mock_render_header.assert_called_once_with(" Safety Report")
        mock_progressive_print.assert_called_once()
        warning_messages = mock_progressive_print.call_args[0][0]
        assert len(warning_messages) == 1
        assert (
            "vulnerable-package==1.0.0 contains 6 vulnerabilities"
            in warning_messages[0]
        )
        assert "including 2 critical severity vulnerabilities" in warning_messages[0]

    @patch("safety.tool.mixins.console")
    def test_render_installation_warnings_without_audit_data(self, mock_console):
        """
        Test render_installation_warnings without audit data.
        """
        command = MockAuditableCommand()
        command.render_installation_warnings(self.ctx, {})
        mock_console.print.assert_not_called()

    @patch("safety.tool.mixins.console")
    def test_render_package_details(self, mock_console):
        """
        Test render_package_details method.
        """
        packages = [("package1", "1.0.0"), ("package2", None)]
        command = MockAuditableCommand(packages=packages)

        command.render_package_details()

        assert mock_console.print.call_count == 2
        for call_args in mock_console.print.call_args_list:
            padding_arg = call_args[0][0]
            assert "Learn more: " in str(padding_arg)
            assert "https://data.safetycli.com/packages/pypi/" in str(padding_arg)

    @patch.object(MockAuditableCommand, "audit_packages")
    @patch.object(MockAuditableCommand, "render_installation_warnings")
    @patch.object(MockAuditableCommand, "render_package_details")
    @patch("safety.tool.base.BaseCommand._perform_diff")
    @patch("safety.tool.base.BaseCommand._handle_command_result")
    def test_handle_installation_audit_success(
        self,
        mock_handle_result,
        mock_perform_diff,
        mock_render_details,
        mock_render_warnings,
        mock_audit_packages,
    ):
        """
        Test handle_installation_audit with successful process.
        """
        command = MockAuditableCommand()
        mock_audit_packages.return_value = {"audit": {"packages": []}}
        self.result.process.returncode = 0

        command.handle_installation_audit(self.ctx, self.result)

        mock_audit_packages.assert_called_once_with(self.ctx)
        mock_render_warnings.assert_called_once_with(
            self.ctx, mock_audit_packages.return_value
        )
        mock_render_details.assert_not_called()  # Should not be called for successful process

    @patch.object(MockAuditableCommand, "audit_packages")
    @patch.object(MockAuditableCommand, "render_installation_warnings")
    @patch.object(MockAuditableCommand, "render_package_details")
    @patch("safety.tool.base.BaseCommand._perform_diff")
    @patch("safety.tool.base.BaseCommand._handle_command_result")
    def test_handle_installation_audit_failure(
        self,
        mock_handle_result,
        mock_perform_diff,
        mock_render_details,
        mock_render_warnings,
        mock_audit_packages,
    ):
        """
        Test handle_installation_audit with failed process.
        """

        command = MockAuditableCommand()
        mock_audit_packages.return_value = {"audit": {"packages": []}}
        self.result.process.returncode = 1  # Non-zero indicates failure

        command.handle_installation_audit(self.ctx, self.result)

        mock_audit_packages.assert_called_once_with(self.ctx)
        mock_render_warnings.assert_called_once_with(
            self.ctx, mock_audit_packages.return_value
        )
        mock_render_details.assert_called_once()  # Should be called for failed process

    def test_handle_installation_audit_type_error(self):
        """
        Test handle_installation_audit with non-AuditableCommand instance.
        """
        non_auditable = InstallationAuditMixin()

        with pytest.raises(TypeError):
            non_auditable.handle_installation_audit(self.ctx, self.result)
