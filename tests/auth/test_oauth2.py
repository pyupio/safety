"""
Tests for safety.auth.oauth2.update_token().

Focuses on the org_legacy_uuid preservation behaviour introduced in
PROD-609 (Cross-Organization Enrollment Prevention).
"""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Dict, Optional
from unittest.mock import patch

import pytest
from authlib.oauth2.rfc6749 import OAuth2Token

from safety.auth.oauth2 import update_token
from safety.config.auth import AuthConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_oauth2_token(
    access_token: str = "new_access",
    id_token: str = "new_id",
    refresh_token: str = "new_refresh",
) -> OAuth2Token:
    """Build a minimal OAuth2Token dict-like object."""
    return OAuth2Token.from_dict(
        {
            "access_token": access_token,
            "id_token": id_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_at": 9999999999,
        }
    )


def _write_auth_config(
    path: Path,
    access_token: str = "old_access",
    id_token: str = "old_id",
    refresh_token: str = "old_refresh",
    org_legacy_uuid: str = "",
) -> None:
    """Write a minimal auth config .ini to *path*."""
    config = configparser.ConfigParser()
    section: Dict[str, str] = {
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
    }
    if org_legacy_uuid:
        section["org_legacy_uuid"] = org_legacy_uuid
    config["auth"] = section
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        config.write(fh)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUpdateTokenPreservesOrgLegacyUuid:
    """update_token() must carry org_legacy_uuid from the stored config."""

    @pytest.mark.unit
    def test_preserves_org_legacy_uuid_from_existing_stored_config(
        self, tmp_path: Path
    ) -> None:
        """
        When the stored config contains a non-empty org_legacy_uuid and a
        token refresh occurs, the UUID must survive into the newly saved config.

        This is the primary use-case: the update_token() callback cannot decode
        the new JWT (no JWKS available), so it reads the UUID from the existing
        AuthConfig on disk and copies it to the refreshed AuthConfig before
        saving.
        """
        config_path = tmp_path / "auth.ini"
        _write_auth_config(
            config_path,
            org_legacy_uuid="legacy-org-uuid-123",
        )

        new_token = _make_oauth2_token()

        with (
            patch("safety.auth.oauth2.AuthConfig.from_storage") as mock_from_storage,
            patch("safety.auth.oauth2.AuthConfig.from_token") as mock_from_token,
        ):
            # Existing stored config carries the UUID
            existing = AuthConfig(
                access_token="old_access",
                id_token="old_id",
                refresh_token="old_refresh",
                org_legacy_uuid="legacy-org-uuid-123",
            )
            mock_from_storage.return_value = existing

            # Freshly parsed token has no UUID (from_token never sets it)
            saved_config: Optional[AuthConfig] = None

            def capture_save(self_: AuthConfig, path: Optional[Path] = None) -> None:
                nonlocal saved_config
                saved_config = AuthConfig(
                    access_token=self_.access_token,
                    id_token=self_.id_token,
                    refresh_token=self_.refresh_token,
                    org_legacy_uuid=self_.org_legacy_uuid,
                )

            fresh = AuthConfig(
                access_token="new_access",
                id_token="new_id",
                refresh_token="new_refresh",
                org_legacy_uuid="",
            )
            mock_from_token.return_value = fresh

            with patch.object(AuthConfig, "save", capture_save):
                update_token(new_token)

        assert saved_config is not None
        assert saved_config.org_legacy_uuid == "legacy-org-uuid-123"

    @pytest.mark.unit
    def test_no_existing_config_org_legacy_uuid_stays_empty(
        self, tmp_path: Path
    ) -> None:
        """
        Fresh install: AuthConfig.from_storage() returns None (no stored config).
        The new config should have an empty org_legacy_uuid rather than raising.
        """
        new_token = _make_oauth2_token()

        with (
            patch("safety.auth.oauth2.AuthConfig.from_storage") as mock_from_storage,
            patch("safety.auth.oauth2.AuthConfig.from_token") as mock_from_token,
        ):
            mock_from_storage.return_value = None  # fresh install — nothing stored

            saved_config: Optional[AuthConfig] = None

            def capture_save(self_: AuthConfig, path: Optional[Path] = None) -> None:
                nonlocal saved_config
                saved_config = AuthConfig(
                    access_token=self_.access_token,
                    id_token=self_.id_token,
                    refresh_token=self_.refresh_token,
                    org_legacy_uuid=self_.org_legacy_uuid,
                )

            fresh = AuthConfig(
                access_token="new_access",
                id_token="new_id",
                refresh_token="new_refresh",
                org_legacy_uuid="",
            )
            mock_from_token.return_value = fresh

            with patch.object(AuthConfig, "save", capture_save):
                update_token(new_token)

        assert saved_config is not None
        assert saved_config.org_legacy_uuid == ""

    @pytest.mark.unit
    def test_existing_config_with_empty_org_legacy_uuid_stays_empty(
        self, tmp_path: Path
    ) -> None:
        """
        Existing config exists but has an empty org_legacy_uuid (e.g. user
        enrolled before the field was introduced).  After a token refresh the
        new config should also have an empty org_legacy_uuid.
        """
        new_token = _make_oauth2_token()

        with (
            patch("safety.auth.oauth2.AuthConfig.from_storage") as mock_from_storage,
            patch("safety.auth.oauth2.AuthConfig.from_token") as mock_from_token,
        ):
            existing = AuthConfig(
                access_token="old_access",
                id_token="old_id",
                refresh_token="old_refresh",
                org_legacy_uuid="",  # field present but empty
            )
            mock_from_storage.return_value = existing

            saved_config: Optional[AuthConfig] = None

            def capture_save(self_: AuthConfig, path: Optional[Path] = None) -> None:
                nonlocal saved_config
                saved_config = AuthConfig(
                    access_token=self_.access_token,
                    id_token=self_.id_token,
                    refresh_token=self_.refresh_token,
                    org_legacy_uuid=self_.org_legacy_uuid,
                )

            fresh = AuthConfig(
                access_token="new_access",
                id_token="new_id",
                refresh_token="new_refresh",
                org_legacy_uuid="",
            )
            mock_from_token.return_value = fresh

            with patch.object(AuthConfig, "save", capture_save):
                update_token(new_token)

        assert saved_config is not None
        assert saved_config.org_legacy_uuid == ""

    @pytest.mark.unit
    def test_raises_when_token_is_invalid(self) -> None:
        """
        update_token() must raise ValueError when the token cannot be parsed
        into a valid AuthConfig (missing required fields).
        """
        # A token that is missing id_token and refresh_token
        bad_token = OAuth2Token.from_dict(
            {
                "access_token": "only_access",
                "token_type": "bearer",
                "expires_at": 9999999999,
            }
        )

        with patch("safety.auth.oauth2.AuthConfig.from_storage") as mock_from_storage:
            mock_from_storage.return_value = None

            with pytest.raises(ValueError, match="Invalid authentication token"):
                update_token(bad_token)
