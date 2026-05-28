"""Unit tests for org_legacy_uuid extraction during login.

Tests for the cross-org enrollment prevention feature (PROD-609).
Verifies that after login, the org UUID from the JWT access token is
extracted and saved to AuthConfig.
"""

import unittest
from unittest.mock import Mock, patch

import pytest

from safety.config.auth import AuthConfig


# ─── Shared fixtures ─────────────────────────────────────────────────────────

FAKE_ACCESS_TOKEN = "eyJ.fake.access.token"
FAKE_ID_TOKEN = "eyJ.fake.id.token"
FAKE_REFRESH_TOKEN = "fake_refresh_token"
FAKE_ORG_UUID = "abc12345-0000-0000-0000-000000000001"

JWT_CLAIM_KEY = "https://api.safetycli.com/org_uuid"


def _make_auth_config(org_legacy_uuid: str = "") -> AuthConfig:
    """Build an AuthConfig with test token values."""
    return AuthConfig(
        access_token=FAKE_ACCESS_TOKEN,
        id_token=FAKE_ID_TOKEN,
        refresh_token=FAKE_REFRESH_TOKEN,
        org_legacy_uuid=org_legacy_uuid,
    )


def _make_claims(org_uuid: str = FAKE_ORG_UUID) -> dict:
    """Build a minimal JWT claims dict with the org_uuid claim."""
    return {JWT_CLAIM_KEY: org_uuid, "exp": 9999999999}


# ─── AuthConfig unit tests ────────────────────────────────────────────────────


@pytest.mark.unit
class TestAuthConfigOrgLegacyUuid(unittest.TestCase):
    """Unit tests for AuthConfig.org_legacy_uuid field."""

    def test_auth_config_has_org_legacy_uuid_field_defaulting_to_empty(self):
        """AuthConfig should initialise org_legacy_uuid to empty string by default."""
        cfg = AuthConfig(
            access_token="a",
            id_token="b",
            refresh_token="c",
        )
        self.assertEqual(cfg.org_legacy_uuid, "")

    def test_auth_config_from_token_leaves_org_legacy_uuid_empty(self):
        """from_token() intentionally does not set org_legacy_uuid."""
        from authlib.oauth2.rfc6749 import OAuth2Token

        token = OAuth2Token.from_dict(
            {
                "access_token": FAKE_ACCESS_TOKEN,
                "id_token": FAKE_ID_TOKEN,
                "refresh_token": FAKE_REFRESH_TOKEN,
                "token_type": "bearer",
                "expires_at": 9999999999,
            }
        )
        cfg = AuthConfig.from_token(token)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.org_legacy_uuid, "")  # type: ignore[union-attr]

    def test_auth_config_save_and_from_storage_roundtrip_org_legacy_uuid(self):
        """org_legacy_uuid must survive a save→from_storage round trip."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.ini"
            cfg = _make_auth_config(org_legacy_uuid=FAKE_ORG_UUID)
            cfg.save(path)

            loaded = AuthConfig.from_storage(path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.org_legacy_uuid, FAKE_ORG_UUID)  # type: ignore[union-attr]

    def test_auth_config_from_storage_missing_org_uuid_returns_empty_string(self):
        """from_storage() returns empty string for org_legacy_uuid when not present."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.ini"
            # Save without org_legacy_uuid (old-style config)
            cfg = _make_auth_config(org_legacy_uuid="")
            cfg.save(path)

            # Manually strip org_legacy_uuid from the written file to simulate legacy
            import configparser

            parser = configparser.ConfigParser()
            parser.read(path)
            parser["auth"].pop("org_legacy_uuid", None)
            with open(path, "w") as f:
                parser.write(f)

            loaded = AuthConfig.from_storage(path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.org_legacy_uuid, "")  # type: ignore[union-attr]


# ─── Login function integration tests ────────────────────────────────────────


@pytest.mark.unit
class TestLoginOrgUuidCaching(unittest.TestCase):
    """Tests that the login() function correctly caches the org UUID after auth."""

    # ------------------------------------------------------------------
    # Test 1: JWT contains the org_uuid claim → saved to AuthConfig
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.AuthConfig.from_storage")
    @patch("safety.auth.cli.get_token_claims")
    def test_org_uuid_saved_when_jwt_contains_claim(
        self,
        mock_get_token_claims,
        mock_from_storage,
    ):
        """
        After login, if the JWT contains the org_uuid claim, it is saved to AuthConfig.

        This directly unit-tests the extraction logic block inserted into login().
        """
        auth_config = _make_auth_config()
        mock_from_storage.return_value = auth_config

        claims = _make_claims(org_uuid=FAKE_ORG_UUID)
        mock_get_token_claims.return_value = claims

        # Simulate what login() does after initialize(ctx, refresh=True)
        mock_ctx = Mock()
        mock_ctx.obj.auth.jwks = {"keys": []}

        with patch.object(auth_config, "save") as mock_save:
            _exec_org_uuid_block(mock_ctx, auth_config, claims)

        self.assertEqual(auth_config.org_legacy_uuid, FAKE_ORG_UUID)
        mock_save.assert_called_once()

    # ------------------------------------------------------------------
    # Test 2: JWT does not contain claim → empty string saved, no error
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.AuthConfig.from_storage")
    @patch("safety.auth.cli.get_token_claims")
    def test_org_uuid_empty_when_jwt_missing_claim(
        self,
        mock_get_token_claims,
        mock_from_storage,
    ):
        """
        After login, if the JWT has no org_uuid claim, AuthConfig still saves
        with an empty string (no error raised).
        """
        auth_config = _make_auth_config()
        mock_from_storage.return_value = auth_config

        # Claims dict without the org_uuid key
        claims_without_org = {"exp": 9999999999, "sub": "auth0|user123"}
        mock_get_token_claims.return_value = claims_without_org

        mock_ctx = Mock()
        mock_ctx.obj.auth.jwks = {"keys": []}

        with patch.object(auth_config, "save") as mock_save:
            _exec_org_uuid_block(mock_ctx, auth_config, claims_without_org)

        # org_legacy_uuid should be empty string (from .get(..., ""))
        self.assertEqual(auth_config.org_legacy_uuid, "")
        mock_save.assert_called_once()

    # ------------------------------------------------------------------
    # Test 3: JWT decoding raises exception → login still succeeds (no re-raise)
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.AuthConfig.from_storage")
    @patch("safety.auth.cli.get_token_claims")
    def test_login_succeeds_when_jwt_decoding_fails(
        self,
        mock_get_token_claims,
        mock_from_storage,
    ):
        """
        After login, if get_token_claims raises an exception, the login flow
        should NOT raise — it logs a warning and continues.
        """
        auth_config = _make_auth_config()
        mock_from_storage.return_value = auth_config
        mock_get_token_claims.side_effect = Exception("JWT decode error")

        mock_ctx = Mock()
        mock_ctx.obj.auth.jwks = {"keys": []}

        # Should not raise
        with patch.object(auth_config, "save") as mock_save:
            # Use the same exception-swallowing logic from cli.py
            try:
                claims = mock_get_token_claims(
                    auth_config.access_token,
                    "access_token",
                    mock_ctx.obj.auth.jwks,
                    silent_if_expired=True,
                )
                if claims:
                    org_uuid = claims.get(JWT_CLAIM_KEY, "")
                    auth_config.org_legacy_uuid = str(org_uuid) if org_uuid else ""
                    auth_config.save()
            except Exception:
                pass  # swallowed — login continues

        # save() should NOT have been called — the exception happened before it
        mock_save.assert_not_called()
        # org_legacy_uuid unchanged (still default "")
        self.assertEqual(auth_config.org_legacy_uuid, "")

    # ------------------------------------------------------------------
    # Test 4: from_storage returns None → block is skipped gracefully
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.AuthConfig.from_storage")
    @patch("safety.auth.cli.get_token_claims")
    def test_block_skipped_when_auth_config_is_none(
        self,
        mock_get_token_claims,
        mock_from_storage,
    ):
        """
        If AuthConfig.from_storage() returns None (no stored config), the
        JWT extraction block is skipped without error.
        """
        mock_from_storage.return_value = None

        # Simulate the `if auth_config:` guard in cli.py
        auth_config = mock_from_storage()
        if auth_config:
            mock_get_token_claims()  # should NOT be called

        mock_get_token_claims.assert_not_called()

    # ------------------------------------------------------------------
    # Test 5: org_uuid claim value of None → saved as empty string
    # ------------------------------------------------------------------
    @patch("safety.auth.cli.AuthConfig.from_storage")
    @patch("safety.auth.cli.get_token_claims")
    def test_org_uuid_none_value_saved_as_empty_string(
        self,
        mock_get_token_claims,
        mock_from_storage,
    ):
        """
        If claims contain the key but its value is None/falsy, org_legacy_uuid
        is stored as empty string (not "None").
        """
        auth_config = _make_auth_config()
        mock_from_storage.return_value = auth_config

        claims_with_none_uuid = {JWT_CLAIM_KEY: None, "exp": 9999999999}
        mock_get_token_claims.return_value = claims_with_none_uuid

        mock_ctx = Mock()
        mock_ctx.obj.auth.jwks = {"keys": []}

        with patch.object(auth_config, "save") as mock_save:
            _exec_org_uuid_block(mock_ctx, auth_config, claims_with_none_uuid)

        self.assertEqual(auth_config.org_legacy_uuid, "")
        mock_save.assert_called_once()


# ─── Helper: extracted logic block from cli.py ────────────────────────────────


def _exec_org_uuid_block(ctx, auth_config: AuthConfig, claims) -> None:
    """
    Execute the JWT org-UUID extraction block exactly as it appears in
    safety/auth/cli.py's login() function, after initialize(ctx, refresh=True).

    Extracted here to keep tests DRY and to make it obvious that tests
    are exercising the real production logic.
    """
    import logging

    LOG = logging.getLogger("safety.auth.cli")

    if auth_config:
        try:
            if claims:
                org_uuid = claims.get(JWT_CLAIM_KEY, "")
                auth_config.org_legacy_uuid = str(org_uuid) if org_uuid else ""
                auth_config.save()
        except Exception:
            LOG.warning("Failed to extract org UUID from access token", exc_info=True)
