"""Sensitive data protection tests for enrollment logging.

Ensures that secret values (enrollment keys, machine tokens) never
appear in log output during enrollment flows — successful or failed.
"""

import logging
from unittest.mock import patch

from click.testing import CliRunner
from importlib.metadata import version
from packaging.version import Version

import pytest

from safety.cli import cli
from safety.errors import EnrollmentError
from tests.auth.helpers import (
    patch_configure_auth_session as _patch_configure_auth_session,
)

# Realistic sensitive values following the sfek_ / sfmt_ patterns
ENROLLMENT_KEY = "sfek_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
MACHINE_TOKEN = "sfmt_SecretMachineTokenThatMustNeverAppearInLogs99"
FAKE_MACHINE_ID = "test-machine-id-logging"


def _assert_no_secrets_in_logs(caplog, enrollment_key, machine_token):
    """Assert that neither the enrollment key nor machine token appear in any log record.

    Checks the formatted message (getMessage()), exception info (exc_info),
    and traceback strings, since @handle_cmd_exception uses LOG.exception()
    which stores exc_info on the record.
    """
    import traceback

    secrets = {enrollment_key: "Enrollment key", machine_token: "Machine token"}
    for record in caplog.records:
        msg = record.getMessage()
        for secret_value, secret_name in secrets.items():
            assert secret_value not in msg, (
                f"{secret_name} leaked in log message at level "
                f"{record.levelname}: {msg}"
            )
        # LOG.exception() attaches exc_info=(type, value, traceback) to the
        # record.  getMessage() does NOT include this, so check separately.
        if record.exc_info:
            # Check exception value (exc_info[1])
            if record.exc_info[1]:
                exc_str = str(record.exc_info[1])
                for secret_value, secret_name in secrets.items():
                    assert secret_value not in exc_str, (
                        f"{secret_name} leaked in exception info at level "
                        f"{record.levelname}: {exc_str}"
                    )
            # Check traceback strings (exc_info[2])
            if record.exc_info[2]:
                tb_str = "".join(traceback.format_tb(record.exc_info[2]))
                for secret_value, secret_name in secrets.items():
                    assert secret_value not in tb_str, (
                        f"{secret_name} leaked in traceback at level {record.levelname}"
                    )


@pytest.mark.unit
class TestEnrollmentSensitiveDataProtection:
    """Verify that enrollment flows never leak secrets into log output."""

    @pytest.fixture(autouse=True)
    def _setup_runner(self):
        if Version(version("click")) >= Version("8.2.0"):
            self.runner = CliRunner()
        else:
            self.runner = CliRunner(mix_stderr=False)
        cli.commands = cli.all_commands
        self.cli = cli

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_successful_enrollment_does_not_log_secrets(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
        caplog,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": MACHINE_TOKEN}

        with caplog.at_level(logging.DEBUG):
            with _patch_configure_auth_session():
                result = self.runner.invoke(
                    self.cli,
                    [
                        "auth",
                        "enroll",
                        ENROLLMENT_KEY,
                        "--machine-id",
                        FAKE_MACHINE_ID,
                    ],
                )

        assert result.exit_code == 0, result.output

        # Anti-no-op: verify enroll-specific log messages are present.
        # The auth callback always logs "auth started" (even without enroll),
        # so checking len(records) > 0 alone would be vacuous.
        log_messages = [r.getMessage() for r in caplog.records]
        assert any("enroll started" in m for m in log_messages), (
            f"Expected 'enroll started' in logs; got: {log_messages}"
        )
        assert any("enrollment successful" in m for m in log_messages), (
            f"Expected 'enrollment successful' in logs; got: {log_messages}"
        )

        _assert_no_secrets_in_logs(caplog, ENROLLMENT_KEY, MACHINE_TOKEN)

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_successful_enrollment_stdout_token_exposure(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        """Verify that the machine token is printed to stdout on success.

        Security note: cli.py prints the raw machine token to stdout via
        console.print(f'  Machine Token: {response_token}').  The CLI also
        prints "You don't need to save these, they are automatically stored",
        which suggests the user does not need to act on the token.  Displaying
        the raw token to stdout is intentional UX for enrollment confirmation
        and transparency, but it does expand the attack surface (shell history
        scrollback, terminal logging, CI/CD build logs).  If a future decision
        is made to redact or mask the token, this test should be updated to
        assert it is NOT present in stdout.
        """
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": MACHINE_TOKEN}

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                [
                    "auth",
                    "enroll",
                    ENROLLMENT_KEY,
                    "--machine-id",
                    FAKE_MACHINE_ID,
                ],
            )

        assert result.exit_code == 0, result.output

        # The machine token currently appears in stdout — this is intentional
        # UX so the user can confirm enrollment succeeded.  See security note
        # in the docstring above for trade-off discussion.
        assert MACHINE_TOKEN in result.output, (
            "Expected machine token in stdout for enrollment confirmation, "
            f"but it was not found.  stdout was:\n{result.output}"
        )

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_enrollment_key_not_in_success_stdout(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        """Verify that enrollment key never appears in stdout, even on success.

        Machine token is intentionally printed for transparency, but enrollment
        key should never be displayed to the user - it's a secret input that
        should only be used internally.
        """
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": MACHINE_TOKEN}

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                [
                    "auth",
                    "enroll",
                    ENROLLMENT_KEY,
                    "--machine-id",
                    FAKE_MACHINE_ID,
                ],
            )

        assert result.exit_code == 0, result.output

        # Machine token should appear (intentional UX)
        assert MACHINE_TOKEN in result.output, (
            "Expected machine token in stdout for enrollment confirmation"
        )

        # Enrollment key should NEVER appear
        assert ENROLLMENT_KEY not in result.output, (
            f"Enrollment key leaked in success stdout! This is a security issue. "
            f"Output:\n{result.output}"
        )

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_token_printed_exactly_once_in_stdout(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        """Verify that the machine token appears exactly once in stdout.

        Multiple appearances would increase exposure risk (e.g., if token appears
        in different sections of output, it's more likely to be captured in logs,
        screenshots, or copied by accident).
        """
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": MACHINE_TOKEN}

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                [
                    "auth",
                    "enroll",
                    ENROLLMENT_KEY,
                    "--machine-id",
                    FAKE_MACHINE_ID,
                ],
            )

        assert result.exit_code == 0, result.output

        # Count occurrences of the machine token in the output
        token_count = result.output.count(MACHINE_TOKEN)
        assert token_count == 1, (
            f"Expected machine token to appear exactly once in stdout, "
            f"but it appeared {token_count} times. This increases exposure risk. "
            f"Output:\n{result.output}"
        )

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_token_not_in_error_output(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        """Verify that tokens never appear in error output.

        When enrollment fails, neither the enrollment key nor any machine token
        should appear in stdout or stderr. This test uses EnrollmentError, but
        the same principle applies to any error path.
        """
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.side_effect = EnrollmentError(
            "Invalid or expired enrollment key"
        )

        with _patch_configure_auth_session():
            result = self.runner.invoke(
                self.cli,
                [
                    "auth",
                    "enroll",
                    ENROLLMENT_KEY,
                    "--machine-id",
                    FAKE_MACHINE_ID,
                ],
            )

        # EnrollmentError is caught by @handle_cmd_exception -> exit code 73
        assert result.exit_code == 73, result.output

        # Neither the enrollment key nor machine token should appear in output
        assert ENROLLMENT_KEY not in result.output, (
            f"Enrollment key leaked in error output! Output:\n{result.output}"
        )
        assert MACHINE_TOKEN not in result.output, (
            f"Machine token leaked in error output! Output:\n{result.output}"
        )

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_token_redacted_in_telemetry_command_params(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
        caplog,
    ):
        """Verify that enrollment keys are redacted in telemetry events.

        The events system uses clean_parameter() and scrub_sensitive_value() to
        redact sensitive data before sending to observability systems. This test
        verifies that enrollment keys (which match the "key" pattern) are properly
        scrubbed from CommandExecutedPayload parameters.

        NOTE: This test verifies the scrubbing functions work correctly in isolation
        and that secrets don't appear in logs during the CLI flow. It does NOT
        directly verify that scrubbing is applied to telemetry event payloads before
        emission, as that would require mocking the events system and capturing
        emitted events. The current coverage provides reasonable confidence that
        secrets are properly redacted, but leaves a gap between unit test (scrubbing
        functions) and integration test (full events flow). Future work could add
        an integration test that mocks event emission and verifies CommandExecutedPayload
        contains scrubbed parameters.
        """
        from safety.events.utils.data import clean_parameter, scrub_sensitive_value

        # Test the scrubbing functions directly
        # enrollment_key parameter should be scrubbed because param name contains "key"
        scrubbed_param = clean_parameter("enrollment_key", ENROLLMENT_KEY)
        assert scrubbed_param == "-", (
            f"clean_parameter should redact enrollment_key parameter, "
            f"but got: {scrubbed_param}"
        )

        # Test that scrub_sensitive_value catches token-like patterns
        # MACHINE_TOKEN is >20 chars alphanumeric, should be caught by pattern
        scrubbed_token = scrub_sensitive_value(MACHINE_TOKEN)
        assert scrubbed_token != MACHINE_TOKEN, (
            f"scrub_sensitive_value should redact machine token pattern, "
            f"but returned original value: {scrubbed_token}"
        )
        assert MACHINE_TOKEN not in scrubbed_token, (
            f"scrub_sensitive_value output still contains original token: "
            f"{scrubbed_token}"
        )

        # Now test the actual CLI flow to ensure these functions are applied
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": MACHINE_TOKEN}

        with caplog.at_level(logging.DEBUG):
            with _patch_configure_auth_session():
                result = self.runner.invoke(
                    self.cli,
                    [
                        "auth",
                        "enroll",
                        ENROLLMENT_KEY,
                        "--machine-id",
                        FAKE_MACHINE_ID,
                    ],
                )

        assert result.exit_code == 0, result.output

        # Verify secrets don't appear in logs
        _assert_no_secrets_in_logs(caplog, ENROLLMENT_KEY, MACHINE_TOKEN)

    @pytest.mark.xfail(
        reason="BUG: error_handlers.py logs exception messages that may contain secrets. "
        "LOG.exception() at line 76 logs SafetyError.__str__() which can include "
        "enrollment keys. This test documents the security issue and should pass "
        "once the bug is fixed by sanitizing exception messages before logging.",
        strict=True,
    )
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_token_not_in_exception_tracebacks_generic_error(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
        caplog,
    ):
        """Verify tokens don't leak via exception messages that contain them.

        This tests a scenario where an exception message itself contains a token.
        The @handle_cmd_exception decorator logs via LOG.exception(), which
        captures exc_info. We verify that even when an exception message contains
        the enrollment key or token, it's caught by our secret detection.

        CURRENTLY FAILS: This test is marked xfail because it exposes a real
        security bug. When an exception message contains a secret (e.g.,
        "Failed to validate enrollment key sfek_ABC..."), error_handlers.py:76
        logs it directly via LOG.exception("Expected SafetyError happened: %s", e).
        This leaks the secret into logs. The bug should be fixed by sanitizing
        exception messages before logging them.
        """
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID

        # Simulate an error where the exception message includes the key
        # (e.g., "Failed to validate enrollment key sfek_ABC...")
        error_msg = f"Failed to validate enrollment key {ENROLLMENT_KEY}"
        mock_call_endpoint.side_effect = EnrollmentError(error_msg)

        with caplog.at_level(logging.DEBUG):
            with _patch_configure_auth_session():
                result = self.runner.invoke(
                    self.cli,
                    [
                        "auth",
                        "enroll",
                        ENROLLMENT_KEY,
                        "--machine-id",
                        FAKE_MACHINE_ID,
                    ],
                )

        assert result.exit_code == 73, result.output

        # Verify the enrollment key doesn't leak in logs (including exc_info)
        # This WILL FAIL until the bug in error_handlers.py is fixed
        _assert_no_secrets_in_logs(caplog, ENROLLMENT_KEY, MACHINE_TOKEN)

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_token_not_in_http_error_tracebacks(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
        caplog,
    ):
        """Verify tokens don't leak when HTTP errors include request details.

        This tests a more realistic scenario: an HTTP error that might include
        the request URL or headers in its traceback/error message. We want to
        ensure that even if the token was part of the request, it doesn't leak
        through error reporting.
        """
        import httpx

        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID

        # Simulate an HTTP error that might include request details
        # httpx exceptions typically don't include body, but we test the principle
        mock_call_endpoint.side_effect = httpx.HTTPStatusError(
            "Server error response",
            request=httpx.Request("POST", "https://api.example.com/enroll"),
            response=httpx.Response(
                500, request=httpx.Request("POST", "https://api.example.com/enroll")
            ),
        )

        with caplog.at_level(logging.DEBUG):
            with _patch_configure_auth_session():
                result = self.runner.invoke(
                    self.cli,
                    [
                        "auth",
                        "enroll",
                        ENROLLMENT_KEY,
                        "--machine-id",
                        FAKE_MACHINE_ID,
                    ],
                )

        # HTTP errors are caught by @handle_cmd_exception
        assert result.exit_code != 0, result.output

        # Anti-no-op: verify HTTP error was actually logged
        log_messages = [r.getMessage() for r in caplog.records]
        assert any(
            "Exception" in m or "HTTPStatusError" in m or "Server error" in m
            for m in log_messages
        ), f"Expected HTTP error in logs; got: {log_messages}"

        # Verify secrets don't appear in logs or exception info
        _assert_no_secrets_in_logs(caplog, ENROLLMENT_KEY, MACHINE_TOKEN)

    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    def test_failed_enrollment_does_not_log_secrets(
        self,
        mock_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
        caplog,
    ):
        mock_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.side_effect = EnrollmentError(
            "Invalid or expired enrollment key"
        )

        with caplog.at_level(logging.DEBUG):
            with _patch_configure_auth_session():
                result = self.runner.invoke(
                    self.cli,
                    [
                        "auth",
                        "enroll",
                        ENROLLMENT_KEY,
                        "--machine-id",
                        FAKE_MACHINE_ID,
                    ],
                )

        # EnrollmentError is caught by @handle_cmd_exception -> exit code 73
        assert result.exit_code == 73, result.output

        # Anti-no-op: verify enroll-specific log messages are present.
        log_messages = [r.getMessage() for r in caplog.records]
        assert any("enroll started" in m for m in log_messages), (
            f"Expected 'enroll started' in logs; got: {log_messages}"
        )
        # The error handler logs the caught SafetyError via LOG.exception()
        assert any("SafetyError" in m for m in log_messages), (
            f"Expected SafetyError exception log; got: {log_messages}"
        )

        _assert_no_secrets_in_logs(caplog, ENROLLMENT_KEY, MACHINE_TOKEN)
