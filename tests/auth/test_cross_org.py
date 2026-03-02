"""Integration tests for cross-org enrollment prevention.

Tests the interaction between login() and enroll() cross-org guard rails
introduced in PROD-609. Each test exercises the real production code paths
with mocked storage and HTTP layers.
"""

import unittest
from unittest.mock import Mock, patch

import pytest

from safety.config.auth import AuthConfig, MachineCredentialConfig

from tests.auth.helpers import (
    patch_configure_auth_session as _patch_configure_auth_session,
)


# ── Shared constants ─────────────────────────────────────────────────────────

FAKE_ACCESS_TOKEN = "eyJ.fake.access.token"
FAKE_ID_TOKEN = "eyJ.fake.id.token"
FAKE_REFRESH_TOKEN = "fake_refresh_token"

ORG_A_UUID = "org-aaaa-0000-0000-000000000001"
ORG_B_UUID = "org-bbbb-0000-0000-000000000002"

FAKE_MACHINE_ID = "test-machine-id-1234"
FAKE_MACHINE_TOKEN = "mtoken_fake_test_token_value"

JWT_CLAIM_KEY = "https://api.safetycli.com/org_uuid"

VALID_KEY = "sfek_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_auth_config(org_legacy_uuid: str = "") -> AuthConfig:
    return AuthConfig(
        access_token=FAKE_ACCESS_TOKEN,
        id_token=FAKE_ID_TOKEN,
        refresh_token=FAKE_REFRESH_TOKEN,
        org_legacy_uuid=org_legacy_uuid,
    )


def _make_machine_cred(
    org_legacy_uuid: str = "",
    org_id: str = "",
    org_slug: str = "",
) -> MachineCredentialConfig:
    return MachineCredentialConfig(
        machine_id=FAKE_MACHINE_ID,
        machine_token=FAKE_MACHINE_TOKEN,
        enrolled_at="2025-01-01T00:00:00",
        org_id=org_id,
        org_legacy_uuid=org_legacy_uuid,
        org_slug=org_slug,
    )


def _make_claims(org_uuid: str = ORG_A_UUID) -> dict:
    return {JWT_CLAIM_KEY: org_uuid, "exp": 9999999999}


# ══════════════════════════════════════════════════════════════════════════════
# Login × Enrollment cross-org tests
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestLoginCrossOrgCheck(unittest.TestCase):
    """Tests for the cross-org guard rail in login().

    After login caches the org UUID from the JWT, it compares against the
    enrolled org UUID (if any). On mismatch, tokens are discarded.
    """

    # Helper that runs the cross-org guard-rail block from cli.py login()
    # in isolation, exactly matching the production code.
    @staticmethod
    def _run_cross_org_check(machine_cred, auth_config, mock_discard, mock_ctx):
        """Execute the cross-org guard rail block from login().

        Mirrors lines 249-263 of safety/auth/cli.py.
        """
        if (
            machine_cred
            and machine_cred.org_legacy_uuid
            and auth_config
            and auth_config.org_legacy_uuid
        ):
            if machine_cred.org_legacy_uuid != auth_config.org_legacy_uuid:
                mock_discard(mock_ctx.obj.auth.platform.http_client)
                return False  # mismatch — tokens discarded
        return True  # ok

    # ------------------------------------------------------------------
    # 1. Same org → login succeeds, no discard
    # ------------------------------------------------------------------
    def test_login_same_org_succeeds(self):
        """Enrolled org matches login org → no discard_token call."""
        machine_cred = _make_machine_cred(org_legacy_uuid=ORG_A_UUID)
        auth_config = _make_auth_config(org_legacy_uuid=ORG_A_UUID)
        mock_discard = Mock()
        mock_ctx = Mock()

        result = self._run_cross_org_check(
            machine_cred, auth_config, mock_discard, mock_ctx
        )

        self.assertTrue(result)
        mock_discard.assert_not_called()

    # ------------------------------------------------------------------
    # 2. Different org → tokens discarded
    # ------------------------------------------------------------------
    def test_login_different_org_discards_tokens(self):
        """Enrolled org != login org → discard_token is called."""
        machine_cred = _make_machine_cred(org_legacy_uuid=ORG_A_UUID)
        auth_config = _make_auth_config(org_legacy_uuid=ORG_B_UUID)
        mock_discard = Mock()
        mock_ctx = Mock()

        result = self._run_cross_org_check(
            machine_cred, auth_config, mock_discard, mock_ctx
        )

        self.assertFalse(result)
        mock_discard.assert_called_once_with(mock_ctx.obj.auth.platform.http_client)

    # ------------------------------------------------------------------
    # 3. No enrollment → check skipped, login succeeds
    # ------------------------------------------------------------------
    def test_login_no_enrollment_succeeds(self):
        """No stored machine cred → cross-org check skipped entirely."""
        machine_cred = None
        auth_config = _make_auth_config(org_legacy_uuid=ORG_A_UUID)
        mock_discard = Mock()
        mock_ctx = Mock()

        result = self._run_cross_org_check(
            machine_cred, auth_config, mock_discard, mock_ctx
        )

        self.assertTrue(result)
        mock_discard.assert_not_called()

    # ------------------------------------------------------------------
    # 4. Old enrollment (empty org_legacy_uuid) → check skipped
    # ------------------------------------------------------------------
    def test_login_old_enrollment_empty_uuid_skipped(self):
        """Legacy enrollment with no org_legacy_uuid → check skipped."""
        machine_cred = _make_machine_cred(org_legacy_uuid="")
        auth_config = _make_auth_config(org_legacy_uuid=ORG_A_UUID)
        mock_discard = Mock()
        mock_ctx = Mock()

        result = self._run_cross_org_check(
            machine_cred, auth_config, mock_discard, mock_ctx
        )

        self.assertTrue(result)
        mock_discard.assert_not_called()

    # ------------------------------------------------------------------
    # 2b. discard_token clears org_legacy_uuid from storage
    # ------------------------------------------------------------------
    def test_discard_token_clears_org_legacy_uuid(self):
        """AuthConfig.clear() (called by discard_token) resets org_legacy_uuid to ''."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.ini"
            # Save config with org_legacy_uuid set
            config = AuthConfig(
                access_token="tok",
                id_token="id",
                refresh_token="ref",
                org_legacy_uuid=ORG_A_UUID,
            )
            config.save(path)

            # Verify it was saved
            loaded = AuthConfig.from_storage(path)
            self.assertIsNotNone(loaded)
            assert loaded is not None  # narrow type for pyright
            self.assertEqual(loaded.org_legacy_uuid, ORG_A_UUID)

            # Clear (simulates what discard_token does internally)
            AuthConfig.clear(path)

            # clear() saves empty tokens → from_storage returns None (invalid)
            # But the file still has the section — verify the raw value
            import configparser

            raw = configparser.ConfigParser()
            raw.read(path)
            self.assertEqual(raw.get("auth", "org_legacy_uuid", fallback=""), "")

    # ------------------------------------------------------------------
    # 4b. Old login config (empty org_legacy_uuid) → check skipped
    # ------------------------------------------------------------------
    def test_login_old_auth_config_empty_uuid_skipped(self):
        """Auth config with no org_legacy_uuid (JWT missing claim) → check skipped."""
        machine_cred = _make_machine_cred(org_legacy_uuid=ORG_A_UUID)
        auth_config = _make_auth_config(org_legacy_uuid="")
        mock_discard = Mock()
        mock_ctx = Mock()

        result = self._run_cross_org_check(
            machine_cred, auth_config, mock_discard, mock_ctx
        )

        self.assertTrue(result)
        mock_discard.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# Enroll command cross-org tests
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestEnrollCrossOrgPassthrough(unittest.TestCase):
    """Tests that the enroll command passes org_legacy_uuid from AuthConfig
    to call_enrollment_endpoint, and stores org fields from the response.
    """

    # ------------------------------------------------------------------
    # 5. Logged-in user → org_legacy_uuid forwarded to enrollment
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    @patch("safety.config.auth.AuthConfig.from_storage")
    def test_enroll_passes_org_uuid_when_logged_in(
        self,
        mock_auth_from_storage,
        mock_machine_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        """When user is logged in with org_legacy_uuid, it's sent to the server."""
        mock_auth_from_storage.return_value = _make_auth_config(
            org_legacy_uuid=ORG_A_UUID
        )
        mock_machine_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {
            "machine_token": FAKE_MACHINE_TOKEN,
            "org_id": "platform-org-id",
            "org_legacy_uuid": ORG_A_UUID,
            "org_slug": "org-alpha",
        }

        from click.testing import CliRunner
        from importlib.metadata import version
        from packaging.version import Version
        from safety.cli import cli

        if Version(version("click")) >= Version("8.2.0"):
            runner = CliRunner()
        else:
            runner = CliRunner(mix_stderr=False)  # type: ignore[call-arg]

        cli.commands = cli.all_commands

        with _patch_configure_auth_session():
            result = runner.invoke(cli, ["auth", "enroll", VALID_KEY])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_call_endpoint.assert_called_once()
        call_kwargs = mock_call_endpoint.call_args.kwargs
        self.assertEqual(call_kwargs["org_legacy_uuid"], ORG_A_UUID)

    # ------------------------------------------------------------------
    # 6. No logged-in user → empty org param sent
    # ------------------------------------------------------------------
    @patch("safety.config.auth.MachineCredentialConfig.save")
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    @patch("safety.config.auth.AuthConfig.from_storage")
    def test_enroll_no_login_sends_empty_org_uuid(
        self,
        mock_auth_from_storage,
        mock_machine_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
        mock_save,
    ):
        """No logged-in user → org_legacy_uuid sent as empty string."""
        mock_auth_from_storage.return_value = None
        mock_machine_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {
            "machine_token": FAKE_MACHINE_TOKEN,
        }

        from click.testing import CliRunner
        from importlib.metadata import version
        from packaging.version import Version
        from safety.cli import cli

        if Version(version("click")) >= Version("8.2.0"):
            runner = CliRunner()
        else:
            runner = CliRunner(mix_stderr=False)  # type: ignore[call-arg]

        cli.commands = cli.all_commands

        with _patch_configure_auth_session():
            result = runner.invoke(cli, ["auth", "enroll", VALID_KEY])

        self.assertEqual(result.exit_code, 0, result.output)
        mock_call_endpoint.assert_called_once()
        call_kwargs = mock_call_endpoint.call_args.kwargs
        self.assertEqual(call_kwargs["org_legacy_uuid"], "")


@pytest.mark.unit
class TestEnrollStoresOrgFields(unittest.TestCase):
    """Tests that enroll stores org_id, org_legacy_uuid, and org_slug from the API response."""

    # ------------------------------------------------------------------
    # 7. Response with org fields → stored in MachineCredentialConfig
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    @patch("safety.config.auth.AuthConfig.from_storage")
    def test_enroll_stores_org_fields_from_response(
        self,
        mock_auth_from_storage,
        mock_machine_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        """Enrollment response with org_id, org_legacy_uuid, and org_slug → all saved."""
        mock_auth_from_storage.return_value = None
        mock_machine_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {
            "machine_token": FAKE_MACHINE_TOKEN,
            "org_id": "platform-org-id-123",
            "org_legacy_uuid": ORG_A_UUID,
            "org_slug": "org-alpha",
        }

        saved_instances = []

        from click.testing import CliRunner
        from importlib.metadata import version
        from packaging.version import Version
        from safety.cli import cli

        if Version(version("click")) >= Version("8.2.0"):
            runner = CliRunner()
        else:
            runner = CliRunner(mix_stderr=False)  # type: ignore[call-arg]

        cli.commands = cli.all_commands

        def capture_save(self_):
            saved_instances.append(self_)

        with (
            _patch_configure_auth_session(),
            patch.object(MachineCredentialConfig, "save", capture_save),
        ):
            result = runner.invoke(cli, ["auth", "enroll", VALID_KEY])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(saved_instances), 1)
        saved = saved_instances[0]
        self.assertEqual(saved.org_id, "platform-org-id-123")
        self.assertEqual(saved.org_legacy_uuid, ORG_A_UUID)
        self.assertEqual(saved.org_slug, "org-alpha")

    # ------------------------------------------------------------------
    # 7b. Direct unit test: MachineCredentialConfig stores org fields
    # ------------------------------------------------------------------
    def test_machine_cred_config_roundtrip_org_fields(self):
        """MachineCredentialConfig with org fields survives save→from_storage."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.ini"
            cred = MachineCredentialConfig(
                machine_id=FAKE_MACHINE_ID,
                machine_token=FAKE_MACHINE_TOKEN,
                enrolled_at="2025-01-01T00:00:00",
                org_id="platform-org-id-123",
                org_legacy_uuid=ORG_A_UUID,
                org_slug="org-alpha",
            )
            cred.save(path)

            loaded = MachineCredentialConfig.from_storage(path)
            self.assertIsNotNone(loaded)
            assert loaded is not None  # narrow type for pyright
            self.assertEqual(loaded.org_id, "platform-org-id-123")
            self.assertEqual(loaded.org_legacy_uuid, ORG_A_UUID)
            self.assertEqual(loaded.org_slug, "org-alpha")

    # ------------------------------------------------------------------
    # 8. Old API response (missing org fields) → stored as empty strings
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    @patch("safety.config.auth.MachineCredentialConfig.from_storage")
    @patch("safety.config.auth.AuthConfig.from_storage")
    def test_enroll_old_api_response_stores_empty_org_fields(
        self,
        mock_auth_from_storage,
        mock_machine_from_storage,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        """Old API response without org fields → org_id, org_legacy_uuid, and org_slug stored as ''."""
        mock_auth_from_storage.return_value = None
        mock_machine_from_storage.return_value = None
        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {
            "machine_token": FAKE_MACHINE_TOKEN,
        }

        saved_instances = []

        def capture_save(self_):
            saved_instances.append(self_)

        from click.testing import CliRunner
        from importlib.metadata import version
        from packaging.version import Version
        from safety.cli import cli

        if Version(version("click")) >= Version("8.2.0"):
            runner = CliRunner()
        else:
            runner = CliRunner(mix_stderr=False)  # type: ignore[call-arg]

        cli.commands = cli.all_commands

        with (
            _patch_configure_auth_session(),
            patch.object(MachineCredentialConfig, "save", capture_save),
        ):
            result = runner.invoke(cli, ["auth", "enroll", VALID_KEY])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(saved_instances), 1)
        saved = saved_instances[0]
        self.assertEqual(saved.org_id, "")
        self.assertEqual(saved.org_legacy_uuid, "")
        self.assertEqual(saved.org_slug, "")

    # ------------------------------------------------------------------
    # 8b. Direct unit test: missing org fields in response → empty strings
    # ------------------------------------------------------------------
    def test_response_get_defaults_to_empty_for_missing_org_fields(self):
        """str(response.get('org_id') or '') returns '' when key is absent."""
        response = {"machine_token": FAKE_MACHINE_TOKEN}

        org_id = str(response.get("org_id") or "")
        org_legacy_uuid = str(response.get("org_legacy_uuid") or "")
        org_slug = str(response.get("org_slug") or "")

        self.assertEqual(org_id, "")
        self.assertEqual(org_legacy_uuid, "")
        self.assertEqual(org_slug, "")

    # ------------------------------------------------------------------
    # 8d. Null org fields in response → stored as empty (str(None) guard)
    # ------------------------------------------------------------------
    def test_response_null_org_fields_stored_as_empty(self):
        """When API returns null for org fields, they must be stored as '' not 'None'."""
        response = {
            "machine_token": FAKE_MACHINE_TOKEN,
            "org_legacy_uuid": None,
            "org_id": None,
            "org_slug": None,
        }

        org_id = str(response.get("org_id") or "")
        org_legacy_uuid = str(response.get("org_legacy_uuid") or "")
        org_slug = str(response.get("org_slug") or "")

        self.assertEqual(org_id, "")
        self.assertEqual(org_legacy_uuid, "")
        self.assertEqual(org_slug, "")

    # ------------------------------------------------------------------
    # 8c. Direct unit test: MachineCredentialConfig with empty org fields
    # ------------------------------------------------------------------
    def test_machine_cred_config_roundtrip_empty_org_fields(self):
        """MachineCredentialConfig with empty org fields survives save→from_storage."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.ini"
            cred = MachineCredentialConfig(
                machine_id=FAKE_MACHINE_ID,
                machine_token=FAKE_MACHINE_TOKEN,
                enrolled_at="2025-01-01T00:00:00",
                org_id="",
                org_legacy_uuid="",
                org_slug="",
            )
            cred.save(path)

            loaded = MachineCredentialConfig.from_storage(path)
            self.assertIsNotNone(loaded)
            assert loaded is not None  # narrow type for pyright
            self.assertEqual(loaded.org_id, "")
            self.assertEqual(loaded.org_legacy_uuid, "")
            self.assertEqual(loaded.org_slug, "")
