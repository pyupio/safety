"""Unit tests for safety.auth.models (Auth, etc.)."""

from unittest.mock import MagicMock

import pytest

from safety.auth.models import Auth


# ---------------------------------------------------------------------------
# Auth.get_auth_method() returns correct method string
# ---------------------------------------------------------------------------


class TestGetAuthMethod:
    """Auth.get_auth_method() returns correct method string."""

    @pytest.mark.unit
    def test_get_auth_method_returns_machine_token(self) -> None:
        """When platform has machine token, get_auth_method returns 'Machine Token'."""
        mock_platform = MagicMock()
        mock_platform.api_key = None
        mock_platform.has_machine_token = True
        mock_platform.token = None

        auth = Auth(
            org=None,
            platform=mock_platform,
            code_verifier="test",
            client_id="test-client",
            jwks=None,
        )

        assert auth.get_auth_method() == "Machine Token"

    @pytest.mark.unit
    def test_get_auth_method_returns_api_key_over_machine_token(self) -> None:
        """API Key takes precedence over machine token in get_auth_method."""
        mock_platform = MagicMock()
        mock_platform.api_key = "my-key"
        mock_platform.has_machine_token = True

        auth = Auth(
            org=None,
            platform=mock_platform,
            code_verifier="test",
            client_id="test-client",
        )

        assert auth.get_auth_method() == "API Key"

    @pytest.mark.unit
    def test_get_auth_method_returns_token_when_no_machine(self) -> None:
        """OAuth2 token returns 'Token' when no machine token."""
        mock_platform = MagicMock(spec=[])
        mock_platform.api_key = None
        mock_platform.token = {"access_token": "abc"}
        mock_platform.has_machine_token = False

        auth = Auth(
            org=None,
            platform=mock_platform,
            code_verifier="test",
            client_id="test-client",
        )

        assert auth.get_auth_method() == "Token"

    @pytest.mark.unit
    def test_get_auth_method_returns_none_when_unauthenticated(self) -> None:
        """Returns 'None' string when no auth is configured."""
        mock_platform = MagicMock(spec=[])
        mock_platform.api_key = None
        mock_platform.token = None
        mock_platform.has_machine_token = False

        auth = Auth(
            org=None,
            platform=mock_platform,
            code_verifier="test",
            client_id="test-client",
        )

        assert auth.get_auth_method() == "None"
