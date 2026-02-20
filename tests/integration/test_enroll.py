"""
Integration tests for ``safety auth enroll`` against a real platform API.

Usage:
    # Against local dev server (http://localhost:8000)
    SAFETY_PLATFORM_V2_URL=http://localhost:8000 \\
      hatch run test tests/integration/test_enroll.py \\
      --enrollment-key sfek_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq

    # Against beta
    SAFETY_PLATFORM_V2_URL=https://beta.safetycli.com \\
      hatch run test tests/integration/test_enroll.py \\
      --enrollment-key sfek_YOUR_KEY_HERE

Prerequisites:
    - Platform API server running and reachable (tests auto-skip otherwise)
    - Valid enrollment key (create via admin API or UI, tests auto-skip if not provided)

What gets tested:
    - Full enrollment flow: CLI -> HTTP -> server -> credential storage
    - Error paths: invalid keys (401), already enrolled (409)
    - Force re-enrollment
    - Credential persistence to disk
"""

from uuid import uuid4

import httpx
import pytest

from safety.config.auth import MachineCredentialConfig
from tests.integration.conftest import LOCAL_API_URL, requires_platform


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def enrollment_key(request):
    """Get enrollment key from --enrollment-key option; skip if absent."""
    key = request.config.getoption("--enrollment-key")
    if not key:
        pytest.skip("--enrollment-key not provided")
    return key


@pytest.fixture
def unique_machine_id():
    """Generate a unique machine ID to avoid server-side 409 conflicts."""
    return f"inttest-{uuid4().hex[:16]}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@requires_platform
@pytest.mark.integration
class TestEnrollIntegration:
    """Integration tests for the enrollment flow against a live server."""

    def test_server_health(self):
        """Sanity: dev server is reachable and healthy."""
        resp = httpx.get(f"{LOCAL_API_URL}/health/", timeout=5.0)
        assert resp.status_code == 200

    def test_enroll_new_machine(
        self,
        cli_runner,
        isolated_auth_storage,
        enrollment_key,
        unique_machine_id,
        monkeypatch,
    ):
        """Happy path: enroll a new machine, verify exit 0 and creds saved."""
        monkeypatch.setenv("SAFETY_PLATFORM_V2_URL", LOCAL_API_URL)
        runner, cli = cli_runner

        result = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                enrollment_key,
                "--machine-id",
                unique_machine_id,
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Enrollment successful" in result.output
        assert unique_machine_id in result.output

    def test_enroll_already_enrolled_without_force(
        self,
        cli_runner,
        isolated_auth_storage,
        enrollment_key,
        unique_machine_id,
        monkeypatch,
    ):
        """Re-enrolling the same machine without --force shows 'already enrolled'."""
        monkeypatch.setenv("SAFETY_PLATFORM_V2_URL", LOCAL_API_URL)
        runner, cli = cli_runner

        # First enrollment
        result1 = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                enrollment_key,
                "--machine-id",
                unique_machine_id,
            ],
        )
        assert result1.exit_code == 0, result1.output

        # Second enrollment without --force: local short-circuit
        result2 = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                enrollment_key,
                "--machine-id",
                unique_machine_id,
            ],
        )
        assert result2.exit_code == 0, result2.output
        assert "already enrolled" in result2.output

    def test_enroll_force_re_enrollment(
        self,
        cli_runner,
        isolated_auth_storage,
        enrollment_key,
        unique_machine_id,
        monkeypatch,
    ):
        """--force re-enrolls a previously enrolled machine."""
        monkeypatch.setenv("SAFETY_PLATFORM_V2_URL", LOCAL_API_URL)
        runner, cli = cli_runner

        # Initial enrollment
        result1 = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                enrollment_key,
                "--machine-id",
                unique_machine_id,
            ],
        )
        assert result1.exit_code == 0, result1.output

        # Force re-enrollment
        result2 = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                enrollment_key,
                "--machine-id",
                unique_machine_id,
                "--force",
            ],
        )
        assert result2.exit_code == 0, result2.output
        assert "Enrollment successful" in result2.output

    def test_enroll_invalid_key_rejected(
        self,
        cli_runner,
        isolated_auth_storage,
        unique_machine_id,
        monkeypatch,
    ):
        """Server rejects invalid enrollment key -> exit 73."""
        monkeypatch.setenv("SAFETY_PLATFORM_V2_URL", LOCAL_API_URL)
        runner, cli = cli_runner

        # A syntactically valid but server-unknown key
        bad_key = "sfek_0000000000000000000000000000000000000000000"

        result = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                bad_key,
                "--machine-id",
                unique_machine_id,
            ],
        )

        assert result.exit_code == 73, result.output

    def test_enroll_with_env_var(
        self,
        cli_runner,
        isolated_auth_storage,
        enrollment_key,
        unique_machine_id,
        monkeypatch,
    ):
        """SAFETY_ENROLLMENT_KEY env var works as an alternative to the positional argument."""
        monkeypatch.setenv("SAFETY_PLATFORM_V2_URL", LOCAL_API_URL)
        runner, cli = cli_runner

        result = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                "--machine-id",
                unique_machine_id,
            ],
            env={
                "SAFETY_ENROLLMENT_KEY": enrollment_key,
            },
        )

        assert result.exit_code == 0, result.output
        assert "Enrollment successful" in result.output

    def test_saved_credentials_readable(
        self,
        cli_runner,
        isolated_auth_storage,
        enrollment_key,
        unique_machine_id,
        monkeypatch,
    ):
        """After enrollment, MachineCredentialConfig.from_storage() returns valid creds."""
        monkeypatch.setenv("SAFETY_PLATFORM_V2_URL", LOCAL_API_URL)
        runner, cli = cli_runner

        result = runner.invoke(
            cli,
            [
                "auth",
                "enroll",
                enrollment_key,
                "--machine-id",
                unique_machine_id,
            ],
        )
        assert result.exit_code == 0, result.output

        creds = MachineCredentialConfig.from_storage(path=isolated_auth_storage)
        assert creds is not None
        assert creds.machine_id == unique_machine_id
        assert creds.machine_token  # non-empty
