"""Unit tests for auth status command enrollment display.

Verifies the status command correctly displays:
- Enrolled-only state: machine_id and timestamp without OAuth2
- Enrolled + OAuth2 coexistence: both auth and enrollment info
- Unauthenticated state: login and enroll suggestions
"""

import unittest
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from importlib.metadata import version
from packaging.version import Version

from safety.cli import cli
from safety.config.auth import MachineCredentialConfig
from safety.models import SafetyCLI


def _make_configure_auth_session_mock(*, machine_token=None, machine_id=None):
    """Return a patch that sets up a minimal ctx.obj for CLI commands.

    configure_auth_session normally creates the Auth object and OAuth2
    client.  For status tests we need ctx.obj.auth to exist with a
    controllable platform mock.
    """

    def _side_effect(ctx, **kwargs):
        if not ctx.obj:
            ctx.obj = SafetyCLI()
        mock_auth = MagicMock()
        mock_auth.org = None
        mock_auth.email = None
        mock_auth.email_verified = False
        # Control the machine_token/machine_id attributes on platform
        mock_auth.platform._machine_token = machine_token
        mock_auth.platform._machine_id = machine_id
        mock_auth.platform.has_machine_token = bool(machine_token)
        mock_auth.platform.machine_id = machine_id
        ctx.obj.auth = mock_auth

    return patch("safety.cli_util.configure_auth_session", side_effect=_side_effect)


@pytest.mark.unit
class TestAuthStatusEnrollmentDisplay(unittest.TestCase):
    """Tests for auth status command enrollment and authentication display."""

    def setUp(self):
        self.maxDiff = None
        if Version(version("click")) >= Version("8.2.0"):
            self.runner = CliRunner()
        else:
            self.runner = CliRunner(mix_stderr=False)

        cli.commands = cli.all_commands
        self.cli = cli

    # ------------------------------------------------------------------
    # 1. Enrolled-only display shows machine_id and timestamp
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.get_auth_info", return_value=None)
    def test_enrolled_only_shows_machine_id_and_timestamp(
        self,
        mock_get_auth_info,
        mock_initialize,
    ):
        """When enrolled but not OAuth2-authenticated, status shows enrollment info
        but NOT the unauthenticated message."""
        fake_cred = MachineCredentialConfig(
            machine_id="enrolled-machine-42",
            machine_token="sfmt_secret_token",
            enrolled_at="2025-07-01T10:30:00",
        )

        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=fake_cred,
            ),
        ):
            result = self.runner.invoke(self.cli, ["auth", "status"])

        self.assertEqual(result.exit_code, 0, result.output)

        # Enrollment info is displayed
        self.assertIn("Enrolled system: enrolled-machine-42", result.output)
        self.assertIn("Enrolled at: 2025-07-01T10:30:00", result.output)

        # MSG_NON_AUTHENTICATED should NOT appear (enrolled systems skip it)
        self.assertNotIn("safety auth login", result.output)
        self.assertNotIn("safety auth enroll", result.output)

        # Anti-no-op: verify get_auth_info was actually called
        mock_get_auth_info.assert_called_once()
        # Anti-no-op: verify initialize was called
        mock_initialize.assert_called_once()

    # ------------------------------------------------------------------
    # 2. Enrolled + OAuth2 coexistence shows both
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.is_email_verified", return_value=True)
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.get_auth_info")
    def test_enrolled_plus_oauth2_shows_both(
        self,
        mock_get_auth_info,
        mock_initialize,
        mock_is_email_verified,
    ):
        """When both enrolled AND OAuth2-authenticated, status shows the
        authenticated user AND the enrollment info."""
        mock_get_auth_info.return_value = {
            "email": "user@example.com",
            "name": "Test User",
        }

        fake_cred = MachineCredentialConfig(
            machine_id="coexist-machine-99",
            machine_token="sfmt_another_token",
            enrolled_at="2025-06-15T08:00:00",
        )

        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=fake_cred,
            ),
        ):
            result = self.runner.invoke(self.cli, ["auth", "status"])

        self.assertEqual(result.exit_code, 0, result.output)

        # OAuth2 authentication info is displayed
        self.assertIn("Authenticated as user@example.com", result.output)

        # Enrollment info is also displayed
        self.assertIn("Enrolled system: coexist-machine-99", result.output)
        self.assertIn("Enrolled at: 2025-06-15T08:00:00", result.output)

        # Anti-no-op: verify both auth paths were exercised
        mock_get_auth_info.assert_called_once()
        mock_is_email_verified.assert_called_once()

    # ------------------------------------------------------------------
    # 3. Unauthenticated display includes both login and enroll suggestions
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.get_auth_info", return_value=None)
    def test_unauthenticated_shows_login_and_enroll_suggestions(
        self,
        mock_get_auth_info,
        mock_initialize,
    ):
        """When neither enrolled nor OAuth2-authenticated, status shows the
        MSG_NON_AUTHENTICATED message which includes both login and enroll
        suggestions."""

        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
        ):
            result = self.runner.invoke(self.cli, ["auth", "status"])

        self.assertEqual(result.exit_code, 0, result.output)

        # MSG_NON_AUTHENTICATED includes both suggestions.
        # Rich console may wrap long lines, so join output for assertion.
        joined_output = " ".join(result.output.split())
        self.assertIn("safety auth login", joined_output)
        self.assertIn("safety auth enroll", joined_output)

        # No enrollment info should be displayed
        self.assertNotIn("Enrolled system:", result.output)
        self.assertNotIn("Enrolled at:", result.output)

        # Anti-no-op: verify get_auth_info was actually called
        mock_get_auth_info.assert_called_once()

    # ------------------------------------------------------------------
    # 4. Machine token auth returns early with status message
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.initialize")
    def test_machine_token_shows_authenticated_and_returns_early(
        self,
        mock_initialize,
    ):
        """When ctx.obj.auth.platform.has_machine_token is True, status prints
        'Authenticated via machine token' and returns early without checking
        OAuth2 or enrollment state."""
        with (
            _make_configure_auth_session_mock(
                machine_token="sfmt_early_return_token",
                machine_id="mt-machine-42",
            ),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=None,
            ) as mock_from_storage,
            patch("safety.auth.cli.get_auth_info") as mock_get_auth_info,
        ):
            result = self.runner.invoke(self.cli, ["auth", "status"])

        self.assertEqual(result.exit_code, 0, result.output)

        # Machine token status message is displayed
        self.assertIn("Authenticated via machine token", result.output)
        self.assertIn("mt-machine-42", result.output)

        # initialize is called with refresh=True on the early-return path
        mock_initialize.assert_called_once()

        # Early return: OAuth2 auth info and enrollment storage are NOT checked
        mock_get_auth_info.assert_not_called()
        mock_from_storage.assert_not_called()

    # ------------------------------------------------------------------
    # 5. OAuth2 authenticated but email not verified shows warning
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.is_email_verified", return_value=False)
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.get_auth_info")
    def test_oauth2_email_not_verified_shows_warning(
        self,
        mock_get_auth_info,
        mock_initialize,
        mock_is_email_verified,
    ):
        """When OAuth2-authenticated but email is not verified, status shows
        the email with a '(email not verified)' warning."""
        mock_get_auth_info.return_value = {
            "email": "unverified@example.com",
            "name": "Unverified User",
        }

        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
        ):
            result = self.runner.invoke(self.cli, ["auth", "status"])

        self.assertEqual(result.exit_code, 0, result.output)

        joined_output = " ".join(result.output.split())
        # Authenticated email is shown
        self.assertIn("unverified@example.com", joined_output)
        # Email-not-verified warning is displayed
        self.assertIn("email not verified", joined_output)

        # Anti-no-op
        mock_get_auth_info.assert_called_once()
        mock_is_email_verified.assert_called_once()

    # ------------------------------------------------------------------
    # 6. Enrolled but enrolled_at is None omits timestamp line
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.get_auth_info", return_value=None)
    def test_enrolled_without_enrolled_at_omits_timestamp(
        self,
        mock_get_auth_info,
        mock_initialize,
    ):
        """When enrolled but enrolled_at is falsy (None/empty), the status
        command shows machine_id but omits the 'Enrolled at:' line."""
        fake_cred = MagicMock()
        fake_cred.machine_id = "no-ts-machine-7"
        fake_cred.enrolled_at = None

        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=fake_cred,
            ),
        ):
            result = self.runner.invoke(self.cli, ["auth", "status"])

        self.assertEqual(result.exit_code, 0, result.output)

        # Machine ID is displayed
        self.assertIn("Enrolled system: no-ts-machine-7", result.output)
        # Timestamp line is NOT displayed
        self.assertNotIn("Enrolled at:", result.output)

        # Enrolled systems should NOT show unauthenticated message
        self.assertNotIn("safety auth login", result.output)

        # Anti-no-op
        mock_get_auth_info.assert_called_once()

    # ------------------------------------------------------------------
    # 7. --ensure-auth triggers browser login flow on timeout
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.get_auth_info", return_value=None)
    @patch(
        "safety.auth.cli.get_authorization_data",
        return_value=("http://auth.example.com", "state-xyz"),
    )
    @patch("safety.auth.cli.process_browser_callback", return_value=None)
    def test_ensure_auth_timeout_exits_with_error(
        self,
        mock_process_browser,
        mock_get_auth_data,
        mock_get_auth_info,
        mock_initialize,
    ):
        """When --ensure-auth is passed and browser auth times out,
        status prints a timeout error and exits with code 1."""
        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
        ):
            result = self.runner.invoke(
                self.cli, ["auth", "status", "--ensure-auth", "--login-timeout", "30"]
            )

        self.assertEqual(result.exit_code, 1, result.output)

        joined_output = " ".join(result.output.split())
        # Ensure-auth header is shown
        self.assertIn("ensure-auth", joined_output)
        # Browser launch message is shown
        self.assertIn("Launching default browser to log in", joined_output)
        # Timeout error message is shown
        self.assertIn("Timeout error", joined_output)

        # Anti-no-op: browser flow was triggered
        mock_get_auth_data.assert_called_once()
        mock_process_browser.assert_called_once()

    # ------------------------------------------------------------------
    # 8. --ensure-auth succeeds after browser login
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.render_successful_login")
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.get_auth_info", return_value=None)
    @patch(
        "safety.auth.cli.get_authorization_data",
        return_value=("http://auth.example.com", "state-abc"),
    )
    @patch("safety.auth.cli.process_browser_callback")
    def test_ensure_auth_success_renders_login(
        self,
        mock_process_browser,
        mock_get_auth_data,
        mock_get_auth_info,
        mock_initialize,
        mock_render_login,
    ):
        """When --ensure-auth is passed and browser auth succeeds,
        status renders the successful login message."""
        mock_process_browser.return_value = {
            "email": "authed@example.com",
            "name": "Authed User",
        }

        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
        ):
            result = self.runner.invoke(self.cli, ["auth", "status", "--ensure-auth"])

        self.assertEqual(result.exit_code, 0, result.output)

        joined_output = " ".join(result.output.split())
        # Ensure-auth header is shown
        self.assertIn("ensure-auth", joined_output)
        # Browser launch message is shown
        self.assertIn("Launching default browser to log in", joined_output)

        # Anti-no-op: login was rendered
        mock_render_login.assert_called_once()
        mock_process_browser.assert_called_once()
