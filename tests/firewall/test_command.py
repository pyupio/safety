"""
Unit tests for safety firewall init command.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from safety.cli import cli


class TestFirewallInit:
    """
    Tests for the firewall init command.
    """

    @pytest.mark.unit
    def test_exits_when_org_slug_not_resolved(self) -> None:
        """
        When resolve_org_slug returns None, command exits with code 1
        without calling configure_system or install_interceptors.
        """
        runner = CliRunner()

        with (
            patch("safety.auth.cli_utils.configure_auth_session"),
            patch("safety.firewall.command.resolve_org_slug", return_value=None),
            patch("safety.firewall.command.configure_system") as mock_configure,
            patch("safety.firewall.command.create_interceptor") as mock_interceptor,
        ):
            result = runner.invoke(cli, ["firewall", "init"])

        assert result.exit_code == 1
        mock_configure.assert_not_called()
        mock_interceptor.assert_not_called()

    @pytest.mark.unit
    def test_calls_configure_system_and_interceptors(self) -> None:
        """
        When auth resolves org_slug, both configure_system and
        install_interceptors are called with correct args.
        """
        runner = CliRunner()

        mock_interceptor_instance = MagicMock()
        mock_interceptor_instance.tools.keys.return_value = [
            "pip",
            "poetry",
            "uv",
            "npm",
        ]

        with (
            patch("safety.auth.cli_utils.configure_auth_session"),
            patch("safety.firewall.command.resolve_org_slug", return_value="my-org"),
            patch("safety.firewall.command.configure_system") as mock_configure,
            patch(
                "safety.firewall.command.create_interceptor",
                return_value=mock_interceptor_instance,
            ),
        ):
            result = runner.invoke(cli, ["firewall", "init"])

        assert result.exit_code == 0
        mock_configure.assert_called_once_with(
            "my-org", tools=["pip", "poetry", "uv", "npm"]
        )
        mock_interceptor_instance.install_interceptors.assert_called_once_with(
            tools=["pip", "poetry", "uv", "npm"]
        )

    @pytest.mark.unit
    def test_with_tool_filter(self) -> None:
        """
        When --tool is specified, only selected tools are passed to both
        configure_system and install_interceptors.
        """
        runner = CliRunner()

        mock_interceptor_instance = MagicMock()

        with (
            patch("safety.auth.cli_utils.configure_auth_session"),
            patch("safety.firewall.command.resolve_org_slug", return_value="my-org"),
            patch("safety.firewall.command.configure_system") as mock_configure,
            patch(
                "safety.firewall.command.create_interceptor",
                return_value=mock_interceptor_instance,
            ),
        ):
            result = runner.invoke(
                cli, ["firewall", "init", "--tool", "pip", "--tool", "uv"]
            )

        assert result.exit_code == 0
        mock_configure.assert_called_once_with("my-org", tools=["pip", "uv"])
        mock_interceptor_instance.install_interceptors.assert_called_once_with(
            tools=["pip", "uv"]
        )
