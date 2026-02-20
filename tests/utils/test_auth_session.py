from unittest.mock import MagicMock, patch

import httpx
import pytest

from safety.utils.auth_session import AuthenticationType, discard_token
from safety_schemas.models import Stage


class TestAuthenticationTypeMachineToken:
    """Tests for AuthenticationType.machine_token stage checks."""

    @pytest.mark.unit
    def test_machine_token_allowed_in_all_stages(self) -> None:
        for stage in Stage:
            assert AuthenticationType.machine_token.is_allowed_in(stage) is True, (
                f"machine_token should be allowed in {stage}"
            )


class TestAuthenticationTypeExistingBehavior:
    """Regression tests for existing authentication type stage rules."""

    @pytest.mark.unit
    def test_is_allowed_in_defaults_to_development(self) -> None:
        """Calling is_allowed_in() with no args uses Stage.development default."""
        assert AuthenticationType.token.is_allowed_in() is True
        assert AuthenticationType.api_key.is_allowed_in() is False

    @pytest.mark.unit
    def test_token_allowed_in_development(self) -> None:
        assert AuthenticationType.token.is_allowed_in(Stage.development) is True

    @pytest.mark.unit
    def test_token_rejected_in_cicd(self) -> None:
        assert AuthenticationType.token.is_allowed_in(Stage.cicd) is False

    @pytest.mark.unit
    def test_token_rejected_in_production(self) -> None:
        assert AuthenticationType.token.is_allowed_in(Stage.production) is False

    @pytest.mark.unit
    def test_api_key_rejected_in_development(self) -> None:
        assert AuthenticationType.api_key.is_allowed_in(Stage.development) is False

    @pytest.mark.unit
    def test_api_key_allowed_in_cicd(self) -> None:
        assert AuthenticationType.api_key.is_allowed_in(Stage.cicd) is True

    @pytest.mark.unit
    def test_api_key_allowed_in_production(self) -> None:
        assert AuthenticationType.api_key.is_allowed_in(Stage.production) is True

    @pytest.mark.unit
    def test_none_rejected_in_all_stages(self) -> None:
        for stage in Stage:
            assert AuthenticationType.none.is_allowed_in(stage) is False, (
                f"unauthenticated should be rejected in {stage}"
            )


class TestDiscardToken:
    """Tests for discard_token() function."""

    @pytest.mark.unit
    @patch("safety.utils.auth_session.AuthConfig.clear")
    def test_discard_token_with_non_oauth2_client_returns_true(
        self, mock_clear: MagicMock
    ) -> None:
        """discard_token() with a plain httpx.Client (no .token attr) returns True."""
        client = httpx.Client()
        try:
            result = discard_token(client)  # type: ignore[arg-type]
            assert result is True
            mock_clear.assert_called_once()
        finally:
            client.close()

    @pytest.mark.unit
    @patch("safety.utils.auth_session.AuthConfig.clear")
    def test_discard_token_with_oauth2_client_clears_token(
        self, mock_clear: MagicMock
    ) -> None:
        """discard_token() with an OAuth2-like client sets token to None."""
        mock_oauth2 = MagicMock()
        mock_oauth2.token = {"access_token": "abc123"}

        result = discard_token(mock_oauth2)

        assert result is True
        assert mock_oauth2.token is None
        mock_clear.assert_called_once()

    @pytest.mark.unit
    @patch("safety.utils.auth_session.AuthConfig.clear")
    def test_discard_token_always_clears_auth_config(
        self, mock_clear: MagicMock
    ) -> None:
        """AuthConfig.clear() is called regardless of client type."""
        mock_client = MagicMock(spec=[])  # spec=[] means no attributes
        result = discard_token(mock_client)
        assert result is True
        mock_clear.assert_called_once()
