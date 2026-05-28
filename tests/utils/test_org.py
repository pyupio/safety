"""
Unit tests for safety.utils.org.resolve_org_slug().
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from safety.config.auth import MachineCredentialConfig
from safety.utils.auth_session import AuthenticationType
from safety.utils.org import resolve_org_slug


def _make_machine_creds(
    machine_id: str = "test-machine-id",
    machine_token: str = "test-machine-token",
    enrolled_at: str = "2025-01-01T00:00:00Z",
) -> MachineCredentialConfig:
    return MachineCredentialConfig(
        machine_id=machine_id,
        machine_token=machine_token,
        enrolled_at=enrolled_at,
    )


def _make_auth(
    *,
    auth_type: AuthenticationType = AuthenticationType.token,
    is_using_creds: bool = True,
    initialize_return: dict | None = None,
    initialize_raises: bool = False,
):
    """
    Build a mocked auth object for resolve_org_slug tests.
    """
    mock_platform = MagicMock()
    mock_platform.is_using_auth_credentials.return_value = is_using_creds
    mock_platform.get_authentication_type.return_value = auth_type

    if initialize_raises:
        mock_platform.initialize.side_effect = Exception("network error")
    else:
        mock_platform.initialize.return_value = initialize_return or {}

    mock_auth = MagicMock()
    mock_auth.platform = mock_platform
    return mock_auth


class TestResolveOrgSlug:
    """
    Tests for resolve_org_slug() utility.
    """

    @pytest.mark.unit
    def test_returns_none_when_no_auth(self) -> None:
        """
        No auth object -> None.
        """
        assert resolve_org_slug(None) is None

    @pytest.mark.unit
    def test_returns_none_when_no_credentials(self) -> None:
        """
        Auth exists but is_using_auth_credentials() is False -> None.
        """
        auth = _make_auth(is_using_creds=False)
        assert resolve_org_slug(auth) is None

    @pytest.mark.unit
    def test_mdm_returns_org_slug_from_stored_creds(self) -> None:
        """
        MDM auth reads org_slug from MachineCredentialConfig.
        """
        auth = _make_auth(auth_type=AuthenticationType.machine_token)
        creds = _make_machine_creds()
        creds.org_slug = "my-org"

        with patch(
            "safety.utils.org.MachineCredentialConfig.from_storage", return_value=creds
        ):
            assert resolve_org_slug(auth) == "my-org"

    @pytest.mark.unit
    def test_mdm_returns_none_when_org_slug_empty(self) -> None:
        """
        MDM auth with empty org_slug in stored creds -> None.
        """
        auth = _make_auth(auth_type=AuthenticationType.machine_token)
        creds = _make_machine_creds()
        creds.org_slug = ""

        with patch(
            "safety.utils.org.MachineCredentialConfig.from_storage", return_value=creds
        ):
            assert resolve_org_slug(auth) is None

    @pytest.mark.unit
    def test_mdm_returns_none_when_no_stored_creds(self) -> None:
        """
        MDM auth but MachineCredentialConfig.from_storage() returns None -> None.
        """
        auth = _make_auth(auth_type=AuthenticationType.machine_token)

        with patch(
            "safety.utils.org.MachineCredentialConfig.from_storage", return_value=None
        ):
            assert resolve_org_slug(auth) is None

    @pytest.mark.unit
    def test_oauth2_returns_org_slug_from_initialize(self) -> None:
        """
        OAuth2 auth calls platform.initialize() and extracts slug.
        """
        auth = _make_auth(
            auth_type=AuthenticationType.token,
            initialize_return={"organization-data": {"slug": "acme-corp"}},
        )
        assert resolve_org_slug(auth) == "acme-corp"

    @pytest.mark.unit
    def test_api_key_returns_org_slug_from_initialize(self) -> None:
        """
        API key auth calls platform.initialize() and extracts slug.
        """
        auth = _make_auth(
            auth_type=AuthenticationType.api_key,
            initialize_return={"organization-data": {"slug": "api-org"}},
        )
        assert resolve_org_slug(auth) == "api-org"

    @pytest.mark.unit
    def test_returns_none_when_initialize_fails(self) -> None:
        """
        platform.initialize() raises -> None (graceful failure).
        """
        auth = _make_auth(
            auth_type=AuthenticationType.token,
            initialize_raises=True,
        )
        assert resolve_org_slug(auth) is None
