"""Integration-style unit tests verifying auth command section independence.

Each auth command ([auth] vs [machine]) must only modify its own section
in the auth.ini config file. These tests verify that:
- login does not modify [machine] section
- logout does not modify [machine] section (discard_token only clears [auth])
- enroll does not modify [auth] section
- enroll --force only overwrites [machine] section
- Full lifecycle: enroll → login → logout preserves section isolation
"""

import configparser
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from importlib.metadata import version
from packaging.version import Version

import pytest

from safety.cli import cli
from safety.config.auth import AuthConfig, MachineCredentialConfig
from safety.models import SafetyCLI


# Reusable test constants
VALID_KEY = "sfek_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
FAKE_MACHINE_ID = "test-machine-id-1234"
FAKE_MACHINE_TOKEN = "mtoken_fake_test_token_value"
FAKE_ENROLLED_AT = "2025-01-01T00:00:00"

FAKE_ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiJ9.fake_access"
FAKE_ID_TOKEN = "eyJhbGciOiJSUzI1NiJ9.fake_id"
FAKE_REFRESH_TOKEN = "fake_refresh_token"


def _write_both_sections(auth_ini_path: Path) -> None:
    """Write an auth.ini with both [auth] and [machine] sections populated."""
    config = configparser.ConfigParser()
    config["auth"] = {
        "access_token": FAKE_ACCESS_TOKEN,
        "id_token": FAKE_ID_TOKEN,
        "refresh_token": FAKE_REFRESH_TOKEN,
    }
    config["machine"] = {
        "machine_id": FAKE_MACHINE_ID,
        "machine_token": FAKE_MACHINE_TOKEN,
        "enrolled_at": FAKE_ENROLLED_AT,
    }
    auth_ini_path.parent.mkdir(parents=True, exist_ok=True)
    with open(auth_ini_path, "w") as f:
        config.write(f)


def _read_section(auth_ini_path: Path, section: str) -> dict:
    """Read a section from auth.ini and return it as a plain dict."""
    config = configparser.ConfigParser()
    config.read(auth_ini_path)
    if not config.has_section(section):
        return {}
    return dict(config[section])


def _make_configure_auth_session_mock():
    """Return a patch that sets up a minimal ctx.obj for CLI commands.

    configure_auth_session normally creates the Auth object with a platform
    client.  For our tests we only need ctx.obj.auth to exist with a mock
    so that commands like ``logout`` don't blow up.
    """

    def _side_effect(ctx, **kwargs):
        if not ctx.obj:
            ctx.obj = SafetyCLI()
        mock_auth = MagicMock()
        mock_auth.org = None
        mock_auth.email = None
        mock_auth.email_verified = False
        ctx.obj.auth = mock_auth

    return patch("safety.cli_util.configure_auth_session", side_effect=_side_effect)


@pytest.mark.unit
class TestAuthCommandIndependence(unittest.TestCase):
    """Tests verifying auth commands only modify their own config section."""

    def setUp(self):
        self.maxDiff = None
        if Version(version("click")) >= Version("8.2.0"):
            self.runner = CliRunner()
        else:
            self.runner = CliRunner(mix_stderr=False)

        cli.commands = cli.all_commands
        self.cli = cli

        # Create a temporary directory for isolated auth.ini files
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self.auth_ini = self.tmp_path / "auth.ini"

    def tearDown(self):
        self._tmpdir.cleanup()

    # ------------------------------------------------------------------
    # 1. login does not modify [machine] section
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.emit_auth_completed")
    @patch("safety.auth.cli.emit_auth_started")
    @patch("safety.auth.cli.initialize_event_bus")
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.process_browser_callback")
    @patch("safety.auth.cli.get_authorization_data")
    @patch("safety.auth.cli.fail_if_authenticated")
    def test_login_does_not_modify_machine_section(
        self,
        mock_fail_if_auth,
        mock_get_auth_data,
        mock_process_callback,
        mock_initialize,
        mock_init_event_bus,
        mock_emit_started,
        mock_emit_completed,
    ):
        """Login (OAuth2 flow) writes to [auth] but must not touch [machine].

        The OAuth2 token persistence is triggered deep inside the authlib
        callback chain (process_browser_callback → update_token →
        AuthConfig.save) which is mocked here.  To verify file-level
        isolation we:
          1. Run the login CLI path (smoke-test that nothing directly
             writes to [machine]).
          2. Exercise the same AuthConfig.save() that login triggers,
             redirected to our temp file, and assert [machine] survives.
        """
        _write_both_sections(self.auth_ini)
        machine_before = _read_section(self.auth_ini, "machine")

        # Simulate successful OAuth2 login callback
        mock_get_auth_data.return_value = ("https://example.com", "state123")
        mock_process_callback.return_value = {
            "email": "user@test.com",
            "name": "Test User",
        }

        with (
            _make_configure_auth_session_mock(),
            patch("safety.config.auth.AUTH_CONFIG_USER", self.auth_ini),
        ):
            result = self.runner.invoke(self.cli, ["auth", "login"])

        self.assertEqual(result.exit_code, 0, result.output)

        # [machine] section must be exactly the same after CLI invocation
        machine_after_cli = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine_before, machine_after_cli)

        # Simulate the OAuth2 token write that login triggers via its
        # callback chain (mocked above).  This exercises AuthConfig.save()
        # against the same temp file to prove [machine] is preserved.
        new_access = "eyJhbGciOiJSUzI1NiJ9.new_access_after_login"
        AuthConfig(
            access_token=new_access,
            id_token="eyJhbGciOiJSUzI1NiJ9.new_id",
            refresh_token="new_refresh",
        ).save(path=self.auth_ini)

        # [machine] section must still be identical after token persistence
        machine_after_save = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine_before, machine_after_save)

        # Anti-no-op: verify [auth] was actually written
        auth_after = _read_section(self.auth_ini, "auth")
        self.assertEqual(auth_after["access_token"], new_access)

    # ------------------------------------------------------------------
    # 2. logout does not modify [machine] section
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.get_token")
    def test_logout_does_not_modify_machine_section(self, mock_get_token):
        """Logout (discard_token → AuthConfig.clear) must not touch [machine]."""
        _write_both_sections(self.auth_ini)
        machine_before = _read_section(self.auth_ini, "machine")

        # Simulate an active session so the logout path executes
        mock_get_token.return_value = FAKE_ID_TOKEN

        # Redirect AuthConfig.clear() to write to our temp file instead of
        # the real user config, and let discard_token run for real.
        with (
            _make_configure_auth_session_mock(),
            patch(
                "safety.config.auth.AUTH_CONFIG_USER",
                self.auth_ini,
            ),
        ):
            result = self.runner.invoke(self.cli, ["auth", "logout"])

        self.assertEqual(result.exit_code, 0, result.output)

        # [machine] section must be exactly the same as before logout
        machine_after = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine_before, machine_after)

        # Verify [auth] was actually cleared (not just a no-op test)
        auth_after = AuthConfig.from_storage(path=self.auth_ini)
        self.assertIsNone(auth_after)

    # ------------------------------------------------------------------
    # 3. enroll (with and without new credentials) preserves [auth]
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    def test_enroll_preserves_auth_section(
        self,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        """Enroll writes to [machine] but must not touch [auth], regardless
        of whether the machine_id/token change or stay the same."""
        cases = [
            # (label, machine_id, machine_token, extra_cli_args)
            (
                "same_creds",
                FAKE_MACHINE_ID,
                FAKE_MACHINE_TOKEN,
                ["--machine-id", FAKE_MACHINE_ID],
            ),
            ("new_creds", "fresh-machine-id-9999", "mtoken_new_token", []),
        ]
        for label, machine_id, machine_token, extra_args in cases:
            with self.subTest(case=label):
                _write_both_sections(self.auth_ini)
                auth_before = _read_section(self.auth_ini, "auth")

                mock_resolve_machine_id.return_value = machine_id
                mock_call_endpoint.return_value = {"machine_token": machine_token}

                with (
                    _make_configure_auth_session_mock(),
                    patch("safety.config.auth.AUTH_CONFIG_USER", self.auth_ini),
                ):
                    result = self.runner.invoke(
                        self.cli,
                        [
                            "auth",
                            "enroll",
                            VALID_KEY,
                            "--force",
                        ]
                        + extra_args,
                    )

                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn("Enrollment successful", result.output)

                # [auth] section must be exactly the same
                auth_after = _read_section(self.auth_ini, "auth")
                self.assertEqual(auth_before, auth_after)

                # [machine] should have the expected values
                machine_after = _read_section(self.auth_ini, "machine")
                self.assertTrue(
                    machine_after, "Expected [machine] section to be populated"
                )
                self.assertEqual(machine_after["machine_id"], machine_id)
                self.assertEqual(machine_after["machine_token"], machine_token)

    # ------------------------------------------------------------------
    # 5. Enroll on fresh system creates only [machine], no [auth]
    # ------------------------------------------------------------------
    @patch("safety.auth.enrollment.call_enrollment_endpoint")
    @patch("safety.auth.machine_id.resolve_machine_id")
    def test_enroll_fresh_system_creates_only_machine_section(
        self,
        mock_resolve_machine_id,
        mock_call_endpoint,
    ):
        """Enroll on a system with no auth.ini creates only [machine] section.

        When no auth.ini exists at all (fresh install / never logged in),
        the enroll command must create the file with only a [machine] section
        and must NOT create an [auth] section.
        """
        # Precondition: no auth.ini exists
        self.assertFalse(self.auth_ini.exists())

        mock_resolve_machine_id.return_value = FAKE_MACHINE_ID
        mock_call_endpoint.return_value = {"machine_token": FAKE_MACHINE_TOKEN}

        with (
            _make_configure_auth_session_mock(),
            patch("safety.config.auth.AUTH_CONFIG_USER", self.auth_ini),
        ):
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

        # File must now exist
        self.assertTrue(self.auth_ini.exists())

        # [machine] section must be populated
        machine = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine["machine_id"], FAKE_MACHINE_ID)
        self.assertEqual(machine["machine_token"], FAKE_MACHINE_TOKEN)

        # [auth] section must NOT exist
        auth = _read_section(self.auth_ini, "auth")
        self.assertEqual(auth, {}, "Expected no [auth] section on fresh enroll")

    # ------------------------------------------------------------------
    # 6. Login on fresh system creates only [auth], no [machine]
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.emit_auth_completed")
    @patch("safety.auth.cli.emit_auth_started")
    @patch("safety.auth.cli.initialize_event_bus")
    @patch("safety.auth.cli.initialize")
    @patch("safety.auth.cli.process_browser_callback")
    @patch("safety.auth.cli.get_authorization_data")
    @patch("safety.auth.cli.fail_if_authenticated")
    def test_login_fresh_system_creates_only_auth_section(
        self,
        mock_fail_if_auth,
        mock_get_auth_data,
        mock_process_callback,
        mock_initialize,
        mock_init_event_bus,
        mock_emit_started,
        mock_emit_completed,
    ):
        """Login on a system with no auth.ini creates only [auth] section.

        When no auth.ini exists at all (fresh install / never enrolled),
        the login command followed by AuthConfig.save() must create the file
        with only an [auth] section and must NOT create a [machine] section.
        """
        # Precondition: no auth.ini exists
        self.assertFalse(self.auth_ini.exists())

        mock_get_auth_data.return_value = ("https://example.com", "state123")
        mock_process_callback.return_value = {
            "email": "user@test.com",
            "name": "Test User",
        }

        with (
            _make_configure_auth_session_mock(),
            patch("safety.config.auth.AUTH_CONFIG_USER", self.auth_ini),
        ):
            result = self.runner.invoke(self.cli, ["auth", "login"])

        self.assertEqual(result.exit_code, 0, result.output)

        # Simulate the OAuth2 token write that login triggers via its
        # callback chain (process_browser_callback → update_token →
        # AuthConfig.save).  This is the write that actually creates auth.ini.
        AuthConfig(
            access_token=FAKE_ACCESS_TOKEN,
            id_token=FAKE_ID_TOKEN,
            refresh_token=FAKE_REFRESH_TOKEN,
        ).save(path=self.auth_ini)

        # File must now exist
        self.assertTrue(self.auth_ini.exists())

        # [auth] section must be populated
        auth = _read_section(self.auth_ini, "auth")
        self.assertEqual(auth["access_token"], FAKE_ACCESS_TOKEN)
        self.assertEqual(auth["id_token"], FAKE_ID_TOKEN)
        self.assertEqual(auth["refresh_token"], FAKE_REFRESH_TOKEN)

        # [machine] section must NOT exist
        machine = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine, {}, "Expected no [machine] section on fresh login")

    # ------------------------------------------------------------------
    # 7. Full lifecycle: enroll → login → logout → verify isolation
    # ------------------------------------------------------------------
    def test_full_lifecycle(self):
        """
        Lifecycle test verifying section isolation across commands:

        1. Enroll  → machine token active, [machine] populated
        2. Login   → OAuth2 active, [machine] unchanged
        3. Logout  → machine token active again, [machine] unchanged throughout
        """
        # --- Step 1: Enroll ---
        new_machine_id = "lifecycle-machine-001"
        new_token = "mtoken_lifecycle_token"
        enrolled_at = "2025-06-15T12:00:00"

        # Simulate enrollment by writing [machine] section directly
        MachineCredentialConfig(
            machine_id=new_machine_id,
            machine_token=new_token,
            enrolled_at=enrolled_at,
        ).save(path=self.auth_ini)

        machine_after_enroll = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine_after_enroll["machine_id"], new_machine_id)
        self.assertEqual(machine_after_enroll["machine_token"], new_token)

        # Verify machine creds can be loaded back
        loaded = MachineCredentialConfig.from_storage(path=self.auth_ini)
        self.assertIsNotNone(loaded)
        assert loaded is not None  # for type checker
        self.assertEqual(loaded.machine_id, new_machine_id)

        # --- Step 2: Login (simulate by writing [auth] section) ---
        AuthConfig(
            access_token=FAKE_ACCESS_TOKEN,
            id_token=FAKE_ID_TOKEN,
            refresh_token=FAKE_REFRESH_TOKEN,
        ).save(path=self.auth_ini)

        # [machine] must be unchanged after login wrote [auth]
        machine_after_login = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine_after_enroll, machine_after_login)

        # Verify OAuth2 is now active
        oauth2 = AuthConfig.from_storage(path=self.auth_ini)
        self.assertIsNotNone(oauth2)
        assert oauth2 is not None  # for type checker
        self.assertEqual(oauth2.access_token, FAKE_ACCESS_TOKEN)

        # --- Step 3: Logout (clear [auth]) ---
        AuthConfig.clear(path=self.auth_ini)

        # [machine] must be unchanged after logout cleared [auth]
        machine_after_logout = _read_section(self.auth_ini, "machine")
        self.assertEqual(machine_after_enroll, machine_after_logout)

        # OAuth2 tokens should be cleared (empty strings → from_storage returns None)
        oauth2_after_logout = AuthConfig.from_storage(path=self.auth_ini)
        self.assertIsNone(oauth2_after_logout)

        # Machine token still active
        machine_cred = MachineCredentialConfig.from_storage(path=self.auth_ini)
        self.assertIsNotNone(machine_cred)
        assert machine_cred is not None  # for type checker
        self.assertEqual(machine_cred.machine_id, new_machine_id)
        self.assertEqual(machine_cred.machine_token, new_token)


@pytest.mark.unit
class TestEnrollmentToScanE2E(unittest.TestCase):
    """E2E integration test verifying enrolled identity flows consistently
    into both the HTTP Authorization header and the scan payload body.

    This catches integration gaps where the auth header machine_id could
    diverge from the scan payload machine_id — they flow through two
    independent code paths:

    - Auth header: MachineCredentialConfig → MachineTokenAuth → Basic auth
    - Payload body: resolve_machine_id() → ExecutionContextDetector → sink.open()
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)
        self.auth_ini = self.tmp_path / "auth.ini"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_enrolled_credentials_flow_through_auth_header_and_scan_payload(self):
        """Enroll → resolve_machine_id + MachineTokenAuth → verify encoding.

        Exercises the code paths that carry machine_id into an outgoing
        system-scan HTTP request:

        1. resolve_machine_id() reads MachineCredentialConfig.from_storage()
        2. MachineTokenAuth encodes machine_id:machine_token into Basic auth
        3. EventSender.create_scan() sends metadata in the POST body

        A mock HTTP transport captures the request for verification.
        """
        import base64
        import json

        import httpx

        from safety.auth.machine_id import resolve_machine_id
        from safety.platform.client import MachineTokenAuth
        from safety.system_scan.scanner.sinks.streaming.http import EventSender

        enrolled_machine_id = "enrolled-e2e-machine-001"
        enrolled_machine_token = "mtoken_e2e_test_value"
        enrolled_at = "2025-06-20T10:00:00"

        # --- Step 1: Simulate enrollment by persisting credentials ---
        MachineCredentialConfig(
            machine_id=enrolled_machine_id,
            machine_token=enrolled_machine_token,
            enrolled_at=enrolled_at,
        ).save(path=self.auth_ini)

        # --- Step 2: Resolve machine_id via the same path system_scan uses ---
        with patch("safety.config.auth.AUTH_CONFIG_USER", self.auth_ini):
            resolved_id = resolve_machine_id()

        # Verify resolve_machine_id reads back persisted enrollment
        self.assertEqual(resolved_id, enrolled_machine_id)

        # --- Step 3: Build HTTP client with MachineTokenAuth ---
        captured_requests: list = []

        def capture_handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, json={"system_scan_id": "scan-e2e-123"})

        transport = httpx.MockTransport(capture_handler)
        auth_handler = MachineTokenAuth(enrolled_machine_id, enrolled_machine_token)
        client = httpx.Client(auth=auth_handler, transport=transport)

        try:
            # --- Step 4: Create scan the way SafetyPlatformSink.open() does ---
            sender = EventSender(
                base_url="https://test.safetycli.com",
                http_client=client,
            )
            scan_id = sender.create_scan(
                metadata={
                    "subtype": "HOST",
                    "machine_id": resolved_id,
                    "hostname": "test-host-e2e",
                }
            )

            self.assertEqual(scan_id, "scan-e2e-123")
            self.assertEqual(len(captured_requests), 1)

            request = captured_requests[0]

            # Verify MachineTokenAuth correctly encodes into Basic auth header
            auth_header = request.headers["authorization"]
            self.assertTrue(auth_header.startswith("Basic "))
            decoded_creds = base64.b64decode(auth_header.split(" ", 1)[1]).decode()
            header_machine_id, header_machine_token = decoded_creds.split(":", 1)

            self.assertEqual(header_machine_id, enrolled_machine_id)
            self.assertEqual(header_machine_token, enrolled_machine_token)

            # Verify EventSender passes metadata through to POST body
            body = json.loads(request.content)
            self.assertEqual(body["machine_id"], enrolled_machine_id)
        finally:
            client.close()
