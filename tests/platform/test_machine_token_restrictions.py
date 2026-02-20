"""Unit tests for machine token endpoint restriction (403 handling).

Verifies that the parse_response decorator differentiates between
machine-token-authenticated 403s (which get MSG_MACHINE_TOKEN_NOT_ACCEPTED)
and non-machine-token 403s (which get the generic forbidden error).
"""

import ssl
from unittest.mock import MagicMock, patch

import httpx
import pytest

from safety.auth.constants import MSG_MACHINE_TOKEN_NOT_ACCEPTED
from safety.errors import InvalidCredentialError
from safety.platform.client import SafetyPlatformClient
from safety.utils.tls_probe import TLSProbeResult


def _make_tls_config():
    """Create a minimal TLSConfig-like object for testing."""
    tls = MagicMock()
    tls.verify_context = ssl.create_default_context()
    tls.mode = "default"
    return tls


def _stub_probe(probe_url, tls_config, **kwargs):
    """Return a no-op TLSProbeResult matching the input config."""
    return TLSProbeResult(tls_config=tls_config, fell_back=False)


_PATCH_META = patch("safety.platform.client.get_meta_http_headers", return_value={})
_PATCH_PROBE = patch(
    "safety.platform.client.probe_tls_connectivity", side_effect=_stub_probe
)


def _build_machine_token_client():
    """Build a SafetyPlatformClient using machine token auth."""
    with _PATCH_PROBE:
        return SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )


def _build_api_key_client():
    """Build a SafetyPlatformClient using API key auth (non-machine-token)."""
    with patch.object(SafetyPlatformClient, "_initialize_with_tls_fallback"):
        return SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            api_key="test-api-key-123",
        )


def _mock_403_response(detail_msg="Forbidden", auth_header=""):
    """Create a mock 403 httpx.Response.

    Args:
        detail_msg: The detail message in the JSON body.
        auth_header: The Authorization header value on the original request.
            Used by parse_response to distinguish machine-token (Basic) from
            other auth types.
    """
    response = MagicMock(spec=httpx.Response)
    response.status_code = 403
    response.is_success = False
    response.is_client_error = True
    response.is_server_error = False
    response.text = detail_msg
    response.json.return_value = {"detail": detail_msg}
    # Mock the request object so parse_response can inspect the Authorization header
    mock_request = MagicMock()
    mock_request.headers = {"authorization": auth_header}
    response.request = mock_request
    return response


@pytest.mark.unit
class TestMachineTokenEndpointRestriction:
    """Tests for 403 handling when using machine token authentication."""

    @_PATCH_META
    def test_machine_token_403_raises_with_specific_message_and_credential(
        self, _mock_meta
    ):
        """Machine token auth + 403 should raise InvalidCredentialError
        with MSG_MACHINE_TOKEN_NOT_ACCEPTED and credential='machine token'."""
        client = _build_machine_token_client()
        forbidden_response = _mock_403_response(
            auth_header="Basic bWFjaGluZS0wMDE6c2ZtdF9hYmMxMjM="
        )

        with patch.object(client._http_client, "get", return_value=forbidden_response):
            with pytest.raises(InvalidCredentialError) as exc_info:
                client.initialize()

            # Verify the error contains the machine-token-specific message
            assert MSG_MACHINE_TOKEN_NOT_ACCEPTED in str(exc_info.value)
            assert "not accepted for this operation" in str(exc_info.value)
            # Verify credential field
            assert exc_info.value.credential == "machine token"

    @_PATCH_META
    def test_machine_token_403_on_post_endpoint(self, _mock_meta):
        """Machine token auth + 403 on a POST endpoint should also raise
        with MSG_MACHINE_TOKEN_NOT_ACCEPTED."""
        client = _build_machine_token_client()
        forbidden_response = _mock_403_response(
            auth_header="Basic bWFjaGluZS0wMDE6c2ZtdF9hYmMxMjM="
        )

        with patch.object(client._http_client, "post", return_value=forbidden_response):
            with pytest.raises(InvalidCredentialError) as exc_info:
                client.check_project(
                    scan_stage="dev",
                    safety_source="cli",
                    project_slug="test-project",
                )

            assert MSG_MACHINE_TOKEN_NOT_ACCEPTED in str(exc_info.value)


@pytest.mark.unit
class TestNonMachineToken403Handling:
    """Tests for 403 handling when NOT using machine token authentication."""

    @_PATCH_META
    def test_api_key_403_raises_generic_error_with_credential(self, _mock_meta):
        """API key auth + 403 should raise InvalidCredentialError with
        generic 'Failed authentication' credential, NOT MSG_MACHINE_TOKEN_NOT_ACCEPTED,
        and include the server detail in the error message."""
        client = _build_api_key_client()
        detail_text = "API key does not have access"
        forbidden_response = _mock_403_response(detail_msg=detail_text)

        with patch.object(client._http_client, "get", return_value=forbidden_response):
            with pytest.raises(InvalidCredentialError) as exc_info:
                client.initialize()

            error_str = str(exc_info.value)
            # Credential field should be the generic message, not machine token
            assert exc_info.value.credential == "Failed authentication."
            assert exc_info.value.credential != "machine token"
            # Should NOT contain the machine token message
            assert MSG_MACHINE_TOKEN_NOT_ACCEPTED not in error_str
            # Server detail should be included in the error
            assert detail_text in error_str
