"""Unit tests for the `safety auth enroll` CLI command."""

import unittest
from unittest.mock import Mock, patch

from click.testing import CliRunner
from importlib.metadata import version
from packaging.version import Version

import httpx
import pytest

from safety.auth.enrollment import call_enrollment_endpoint
from safety.cli import cli
from safety.config.auth import MachineCredentialConfig
from safety.errors import (
    EnrollmentError,
    EnrollmentTransientFailure,
    MachineIdUnavailableError,
)
from tests.auth.helpers import (
    patch_configure_auth_session as _patch_configure_auth_session,
)


# A valid enrollment key matching ENROLLMENT_KEY_PATTERN: ^sfek_[A-Za-z0-9_-]{43}$
VALID_KEY = "sfek_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
FAKE_MACHINE_ID = "test-machine-id-1234"
FAKE_MACHINE_TOKEN = "mtoken_fake_test_token_value"


def _make_existing_creds(
    machine_id: str = FAKE_MACHINE_ID,
    machine_token: str = FAKE_MACHINE_TOKEN,
    enrolled_at: str = "2025-01-01T00:00:00",
) -> MachineCredentialConfig:
    return MachineCredentialConfig(
        machine_id=machine_id,
        machine_token=machine_token,
        enrolled_at=enrolled_at,
    )


@pytest.mark.unit
class TestEnrollCommand(unittest.TestCase):
    """Tests for `safety auth enroll`."""

    def setUp(self):
        self.maxDiff = None
        if Version(version("click")) >= Version("8.2.0"):
            self.runner = CliRunner()
        else:
            self.runner = CliRunner(mix_stderr=False)

        cli.commands = cli.all_commands
        self.cli = cli

    # ------------------------------------------------------------------
    # 1. Successful enrollment with CLI flags
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_successful_enrollment_with_cli_flags(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        mock_from_storage.return_value = None  # not enrolled yet
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": FAKE_MACHINE_TOKEN}

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                [
                    "auth",
                    "enroll",
                    VALID_KEY,
                    "--machine-id",
                    FAKE_MACHINE_ID,
                ],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Enrollment successful", result.output)
        self.assertIn(FAKE_MACHINE_ID, result.output)
        self.assertIn(FAKE_MACHINE_TOKEN, result.output)

        mock_resolve_machine_id.assert_called_once_with(
            override=FAKE_MACHINE_ID, skip_enrolled=True
        )
        mock_call_endpoint.assert_called_once()
        call_kwargs = mock_call_endpoint.call_args.kwargs
        self.assertEqual(call_kwargs["enrollment_key"], VALID_KEY)
        self.assertEqual(call_kwargs["machine_id"], FAKE_MACHINE_ID)
        self.assertFalse(call_kwargs["force"])
        self.assertIsNotNone(call_kwargs["platform_client"])
        mock_save.assert_called_once()

    # ------------------------------------------------------------------
    # 2. Successful enrollment with env vars
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_successful_enrollment_with_env_vars(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": FAKE_MACHINE_TOKEN}

        env = {
            "SAFETY_ENROLLMENT_KEY": VALID_KEY,
            "SAFETY_MACHINE_ID": FAKE_MACHINE_ID,
        }

        with _patch_configure_auth_session():
            result = self.runner.invoke(self.cli, ["auth", "enroll"], env=env)

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Enrollment successful", result.output)

        # SAFETY_MACHINE_ID env var is picked up by Typer's envvar= on the
        # --machine-id option, so it arrives as the override parameter.
        mock_resolve_machine_id.assert_called_once_with(
            override=FAKE_MACHINE_ID, skip_enrolled=True
        )
        mock_call_endpoint.assert_called_once()

    # ------------------------------------------------------------------
    # 3. Already enrolled without --force exits code 0 and shows status
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_already_enrolled_without_force_exits_zero(self, mock_from_storage):
        mock_from_storage.return_value = _make_existing_creds()

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", VALID_KEY],
            )

        # Explicitly assert exit code 0, NOT 73
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("already enrolled", result.output)
        self.assertIn(FAKE_MACHINE_ID, result.output)
        self.assertIn("--force", result.output)

    # ------------------------------------------------------------------
    # 4. --force re-enrollment overwrites credentials and re-resolves
    #    machine ID fresh
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_force_re_enrollment(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        # First call in configure_auth_session (mocked) / second in enroll
        mock_from_storage.return_value = _make_existing_creds()
        new_machine_id = "fresh-machine-id-9999"
        new_token = "mtoken_new_token"
        mock_resolve_machine_id.return_value = new_machine_id
        mock_call_endpoint.return_value = {"machine_token": new_token}

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                [
                    "auth",
                    "enroll",
                    VALID_KEY,
                    "--force",
                ],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Enrollment successful", result.output)
        self.assertIn(new_machine_id, result.output)
        self.assertIn(new_token, result.output)

        # Machine ID is re-resolved fresh (skip_enrolled=True)
        mock_resolve_machine_id.assert_called_once_with(
            override=None, skip_enrolled=True
        )
        mock_call_endpoint.assert_called_once()
        call_kwargs = mock_call_endpoint.call_args.kwargs
        self.assertEqual(call_kwargs["enrollment_key"], VALID_KEY)
        self.assertEqual(call_kwargs["machine_id"], new_machine_id)
        self.assertTrue(call_kwargs["force"])
        self.assertIsNotNone(call_kwargs["platform_client"])
        mock_save.assert_called_once()

    # ------------------------------------------------------------------
    # 5. Invalid enrollment key format exits 73
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_invalid_enrollment_key_format_exits_73(self, mock_from_storage):
        mock_from_storage.return_value = None

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                [
                    "auth",
                    "enroll",
                    "bad_key_format",
                ],
            )

        self.assertEqual(result.exit_code, 73, result.output)

    # ------------------------------------------------------------------
    # 6. Missing enrollment key exits 73
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_missing_enrollment_key_exits_73(self, mock_from_storage):
        mock_from_storage.return_value = None

        with _patch_configure_auth_session():
            result = self.runner.invoke(self.cli, ["auth", "enroll"])

        self.assertEqual(result.exit_code, 73, result.output)

    # ------------------------------------------------------------------
    # 7. Positional enrollment key overrides SAFETY_ENROLLMENT_KEY env var
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_cli_flag_overrides_env_var(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": FAKE_MACHINE_TOKEN}

        # The env var has a *different* valid key
        env_key = "sfek_0000000000000000000000000000000000000000000"
        cli_key = VALID_KEY

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", cli_key],
                env={"SAFETY_ENROLLMENT_KEY": env_key},
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Enrollment successful", result.output)

        # The endpoint should have been called with the CLI flag key,
        # not the env var key.
        mock_call_endpoint.assert_called_once()
        call_kwargs = mock_call_endpoint.call_args.kwargs
        self.assertEqual(call_kwargs["enrollment_key"], cli_key)
        self.assertEqual(call_kwargs["machine_id"], FAKE_MACHINE_ID)
        self.assertFalse(call_kwargs["force"])


@pytest.mark.unit
class TestCallEnrollmentEndpoint(unittest.TestCase):
    """Tests for call_enrollment_endpoint() thin adapter.

    The adapter delegates to platform_client.enroll() and wraps transient
    httpx exceptions as EnrollmentTransientFailure.  HTTP-level behavior
    (status codes, retries, payloads) is tested in test_client.py.
    """

    def setUp(self):
        self.maxDiff = None
        self.mock_client = Mock()

    # ------------------------------------------------------------------
    # 1. Delegates to platform_client.enroll with correct args
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.get_required_config_setting")
    def test_delegates_to_platform_client_enroll(self, mock_config):
        mock_config.return_value = "https://service.platformv2.safetycli.com"
        expected = {"machine_id": FAKE_MACHINE_ID, "machine_token": FAKE_MACHINE_TOKEN}
        self.mock_client.enroll.return_value = expected

        result = call_enrollment_endpoint(
            platform_client=self.mock_client,
            enrollment_key=VALID_KEY,
            machine_id=FAKE_MACHINE_ID,
        )

        self.assertEqual(result, expected)
        mock_config.assert_called_once_with("SAFETY_PLATFORM_V2_URL")
        self.mock_client.enroll.assert_called_once_with(
            enrollment_base_url="https://service.platformv2.safetycli.com",
            enrollment_key=VALID_KEY,
            machine_id=FAKE_MACHINE_ID,
            force=False,
        )

    # ------------------------------------------------------------------
    # 2. force=True forwarded to platform_client.enroll
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.get_required_config_setting")
    def test_force_forwarded(self, mock_config):
        mock_config.return_value = "https://platform.safetycli.com"
        self.mock_client.enroll.return_value = {"machine_token": FAKE_MACHINE_TOKEN}

        call_enrollment_endpoint(
            platform_client=self.mock_client,
            enrollment_key=VALID_KEY,
            machine_id=FAKE_MACHINE_ID,
            force=True,
        )

        self.assertTrue(self.mock_client.enroll.call_args.kwargs["force"])

    # ------------------------------------------------------------------
    # 3. httpx.NetworkError wrapped as EnrollmentTransientFailure
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.get_required_config_setting")
    def test_network_error_wrapped_as_transient(self, mock_config):
        mock_config.return_value = "https://platform.safetycli.com"
        self.mock_client.enroll.side_effect = httpx.ConnectError("connection refused")

        with self.assertRaises(EnrollmentTransientFailure) as ctx:
            call_enrollment_endpoint(
                platform_client=self.mock_client,
                enrollment_key=VALID_KEY,
                machine_id=FAKE_MACHINE_ID,
            )

        self.assertIn("connection refused", str(ctx.exception))

    # ------------------------------------------------------------------
    # 4. httpx.TimeoutException wrapped as EnrollmentTransientFailure
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.get_required_config_setting")
    def test_timeout_error_wrapped_as_transient(self, mock_config):
        mock_config.return_value = "https://platform.safetycli.com"
        self.mock_client.enroll.side_effect = httpx.TimeoutException(
            "request timed out"
        )

        with self.assertRaises(EnrollmentTransientFailure) as ctx:
            call_enrollment_endpoint(
                platform_client=self.mock_client,
                enrollment_key=VALID_KEY,
                machine_id=FAKE_MACHINE_ID,
            )

        self.assertIn("request timed out", str(ctx.exception))


@pytest.mark.unit
class TestEnrollCommandErrorPaths(unittest.TestCase):
    """Tests for enroll CLI error paths."""

    def setUp(self):
        self.maxDiff = None
        if Version(version("click")) >= Version("8.2.0"):
            self.runner = CliRunner()
        else:
            self.runner = CliRunner(mix_stderr=False)

        cli.commands = cli.all_commands
        self.cli = cli

    # ------------------------------------------------------------------
    # 1. Server response missing machine_token raises EnrollmentError → exit 73
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_missing_machine_token_in_response_exits_73(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        # Server returns 200 but no machine_token in body
        mock_call_endpoint.return_value = {"machine_id": FAKE_MACHINE_ID}

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", VALID_KEY],
            )

        self.assertEqual(result.exit_code, 73, result.output)
        mock_save.assert_not_called()

    # ------------------------------------------------------------------
    # 2. MachineIdUnavailableError from resolve_machine_id → exit 74
    # ------------------------------------------------------------------
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_machine_id_unavailable_exits_74(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.side_effect = MachineIdUnavailableError(
            "Could not determine machine identity"
        )

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", VALID_KEY],
            )

        self.assertEqual(result.exit_code, 74, result.output)

    # ------------------------------------------------------------------
    # 3. 401 API error propagates through CLI → exit 73
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_401_api_error_propagates_exits_73(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.side_effect = EnrollmentError(
            "Invalid or expired enrollment key"
        )

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", VALID_KEY],
            )

        self.assertEqual(result.exit_code, 73, result.output)

    # ------------------------------------------------------------------
    # 4. 409 API error propagates through CLI → exit 73
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_409_api_error_propagates_exits_73(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.side_effect = EnrollmentError(
            "Machine is already enrolled on the server. Use --force to re-enroll."
        )

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", VALID_KEY],
            )

        self.assertEqual(result.exit_code, 73, result.output)

    # ------------------------------------------------------------------
    # 5. 500 API error propagates through CLI → exit 75 (retryable)
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_500_api_error_propagates_exits_75(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.side_effect = EnrollmentTransientFailure(
            "Enrollment failed (HTTP 500): Internal server error"
        )

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", VALID_KEY],
            )

        self.assertEqual(result.exit_code, 75, result.output)

    # ------------------------------------------------------------------
    # 6. Network error after retry exhaustion → exit 75 (retryable)
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_network_error_after_retries_exits_75(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.side_effect = EnrollmentTransientFailure(
            "Enrollment failed after retries: connection refused"
        )

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                ["auth", "enroll", VALID_KEY],
            )

        self.assertEqual(result.exit_code, 75, result.output)
