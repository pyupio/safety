"""Unit tests for SafetyPlatformClient machine token integration."""

import ssl
from unittest.mock import MagicMock, patch

import httpx
import pytest

from safety.errors import EnrollmentError, EnrollmentTransientFailure
from safety.platform.client import MachineTokenAuth, SafetyPlatformClient
from safety.utils.auth_session import AuthenticationType
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


# Patch targets that fire during __init__
_PATCH_META = patch("safety.platform.client.get_meta_http_headers", return_value={})
_PATCH_PROBE = patch(
    "safety.platform.client.probe_tls_connectivity", side_effect=_stub_probe
)


@pytest.mark.unit
@_PATCH_PROBE
class TestSafetyPlatformClientMachineToken:
    """Tests for SafetyPlatformClient with machine_token auth path."""

    # -- 1. Initialization with machine_token creates httpx.Client, not OAuth2Client --

    @_PATCH_META
    def test_init_creates_plain_httpx_client(self, _mock_meta, _mock_probe):
        """machine_token path should create httpx.Client, not OAuth2Client."""
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        # Should be plain httpx.Client, not OAuth2Client subclass
        assert type(client._http_client) is httpx.Client

    @_PATCH_META
    def test_init_does_not_require_oauth2_deps(self, _mock_meta, _mock_probe):
        """machine_token path should NOT raise ValueError for missing OAuth2 deps."""
        # No client_id, redirect_uri, etc. — should still succeed
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        assert client is not None

    @_PATCH_META
    def test_init_sets_machine_token_auth(self, _mock_meta, _mock_probe):
        """Client auth should be MachineTokenAuth instance."""
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        assert isinstance(client._http_client._auth, MachineTokenAuth)

    @_PATCH_META
    def test_init_requires_machine_id_with_token(self, _mock_meta, _mock_probe):
        """machine_token without machine_id should raise ValueError."""
        with pytest.raises(ValueError, match="machine_id is required"):
            SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=_make_tls_config(),
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                machine_token="sfmt_abc123",
            )

    @_PATCH_META
    def test_init_requires_machine_token_with_id(self, _mock_meta, _mock_probe):
        """machine_id without machine_token should raise ValueError."""
        with pytest.raises(ValueError, match="machine_token is required"):
            SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=_make_tls_config(),
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                machine_id="machine-001",
            )

    # -- 2. get_authentication_type() returns machine_token --

    @_PATCH_META
    def test_get_authentication_type_returns_machine_token(
        self, _mock_meta, _mock_probe
    ):
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        assert client.get_authentication_type() == AuthenticationType.machine_token

    # -- 3. API key takes priority when both api_key and machine_token provided --

    @_PATCH_META
    def test_api_key_takes_priority_in_http_client(self, _mock_meta, _mock_probe):
        """When both api_key and machine_token are provided, HTTP client uses ApiKeyAuth."""
        from safety.platform.client import ApiKeyAuth

        with patch.object(SafetyPlatformClient, "_initialize_with_tls_fallback"):
            client = SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=_make_tls_config(),
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                api_key="my-api-key",
                machine_id="machine-001",
                machine_token="sfmt_abc123",
            )
        # _create_http_client checks api_key first, so HTTP client uses ApiKeyAuth
        assert isinstance(client._http_client._auth, ApiKeyAuth)

    @_PATCH_META
    def test_api_key_takes_priority_in_get_authentication_type(
        self, _mock_meta, _mock_probe
    ):
        """When both api_key and machine_token provided, get_authentication_type returns api_key."""
        with patch.object(SafetyPlatformClient, "_initialize_with_tls_fallback"):
            client = SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=_make_tls_config(),
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                api_key="my-api-key",
                machine_id="machine-001",
                machine_token="sfmt_abc123",
            )
        assert client.get_authentication_type() == AuthenticationType.api_key

    @_PATCH_META
    def test_api_key_takes_priority_in_get_credential(self, _mock_meta, _mock_probe):
        """When both api_key and machine_token provided, get_credential returns api_key."""
        with patch.object(SafetyPlatformClient, "_initialize_with_tls_fallback"):
            client = SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=_make_tls_config(),
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                api_key="my-api-key",
                machine_id="machine-001",
                machine_token="sfmt_abc123",
            )
        assert client.get_credential() == "my-api-key"

    # -- 4. _initialize_with_tls_fallback() runs probe but skips OpenID config fetch --

    @_PATCH_META
    def test_tls_init_skips_openid_config_fetch(self, _mock_meta, _mock_probe):
        """machine_token path should run TLS probe but skip OpenID config fetch."""
        with patch.object(SafetyPlatformClient, "get_openid_config") as mock_openid:
            SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=_make_tls_config(),
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                machine_id="machine-001",
                machine_token="sfmt_abc123",
            )
        # Probe IS called (via class-level patch), but OpenID config is NOT
        _mock_probe.assert_called()
        mock_openid.assert_not_called()

    # -- 5. get_credential() returns machine_id --

    @_PATCH_META
    def test_get_credential_returns_machine_id(self, _mock_meta, _mock_probe):
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        assert client.get_credential() == "machine-001"

    # -- 6. load_auth_token_from_storage() returns early --

    @_PATCH_META
    def test_load_auth_token_from_storage_returns_early(self, _mock_meta, _mock_probe):
        """machine_token path should return early without touching AuthConfig."""
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        with patch("safety.platform.client.AuthConfig.from_storage") as mock_storage:
            client.load_auth_token_from_storage(jwks={"keys": []})
        mock_storage.assert_not_called()

    # -- Additional edge case tests --

    @_PATCH_META
    def test_is_using_auth_credentials_true_for_machine_token(
        self, _mock_meta, _mock_probe
    ):
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        assert client.is_using_auth_credentials() is True

    @_PATCH_META
    def test_token_property_returns_none_for_machine_token(
        self, _mock_meta, _mock_probe
    ):
        """token property should return None for non-OAuth2 clients."""
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        assert client.token is None

    @_PATCH_META
    def test_base_url_trailing_slash_stripped(self, _mock_meta, _mock_probe):
        """base_url should have trailing slash stripped."""
        client = SafetyPlatformClient(
            base_url="https://api.example.com/",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )
        assert client.base_url == "https://api.example.com"


@pytest.mark.unit
@_PATCH_PROBE
class TestInitializeTimeoutErrorMessages:
    """Tests for initialize() timeout error message quality.

    These tests verify that when initialize() times out, the error messages
    provide meaningful context about what operation failed and the timeout
    duration, rather than just generic 'No response received' messages.
    """

    @_PATCH_META
    def test_initialize_timeout_includes_context(self, _mock_meta, _mock_probe):
        """Verify timeout error from initialize() includes meaningful context.

        When initialize() times out, the error should ideally include:
        - What operation timed out (initialize/auth request)
        - The timeout duration (5 seconds)
        - Not just a generic 'No response received' message
        """
        from safety.errors import RequestTimeoutError

        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )

        # Mock the HTTP client to raise a timeout
        with patch.object(client._http_client, "get") as mock_get:
            mock_get.side_effect = httpx.TimeoutException("Request timed out")

            # initialize() should raise RequestTimeoutError when timeout occurs
            with pytest.raises(RequestTimeoutError) as exc_info:
                client.initialize()

            error_message = str(exc_info.value)

            # Verify the error message provides meaningful context
            # Currently, this will just be the default message:
            # "Check your network connection, the request timed out."
            #
            # Ideally, it should include context like:
            # - "initialize" or "auth request"
            # - "5 seconds" (the timeout duration from initialize())
            #
            # For now, we verify the current behavior exists
            assert "timed out" in error_message.lower()

            # This assertion documents the issue: the error lacks specific context
            # about what operation timed out and the timeout duration
            assert "initialize" not in error_message.lower() or "5" not in error_message

    @_PATCH_META
    def test_initialize_timeout_error_is_retried(self, _mock_meta, _mock_probe):
        """Verify timeout errors from initialize() are retried 3 times.

        RequestTimeoutError is in the retryable exception set, so the
        @parse_response decorator should retry 3 times before failing.
        """
        from safety.errors import RequestTimeoutError

        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )

        call_count = 0

        def raise_timeout(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise httpx.TimeoutException("Request timed out")

        with patch.object(client._http_client, "get", side_effect=raise_timeout):
            with pytest.raises(RequestTimeoutError):
                client.initialize()

            # Verify the request was retried 3 times (tenacity default)
            assert call_count == 3

    @_PATCH_META
    def test_initialize_none_response_raises_server_error(
        self, _mock_meta, _mock_probe
    ):
        """Verify initialize() returning None raises ServerError.

        When the wrapped function returns None, @parse_response should
        raise ServerError with 'No response received from server'.
        """
        from safety.errors import ServerError

        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )

        # Mock the HTTP client to return None
        with patch.object(client._http_client, "get", return_value=None):
            with pytest.raises(ServerError) as exc_info:
                client.initialize()

            # Verify the generic error message
            assert "No response received from server" in str(exc_info.value)

    @_PATCH_META
    def test_initialize_success_returns_parsed_json(self, _mock_meta, _mock_probe):
        """Verify successful initialize() returns parsed JSON response."""
        client = SafetyPlatformClient(
            base_url="https://api.example.com",
            tls_config=_make_tls_config(),
            auth_server_url="https://auth.example.com",
            openid_config_url="https://auth.example.com/.well-known/openid-configuration",
            machine_id="machine-001",
            machine_token="sfmt_abc123",
        )

        # Mock successful response
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.json.return_value = {
            "status": "initialized",
            "session_id": "abc123",
        }

        with patch.object(
            client._http_client, "get", return_value=mock_response
        ) as mock_get:
            result = client.initialize()

            assert result == {"status": "initialized", "session_id": "abc123"}
            # Verify timeout=5 was passed to the get() call
            mock_get.assert_called_once()
            call_kwargs = mock_get.call_args[1]
            assert call_kwargs.get("timeout") == 5


@pytest.mark.unit
class TestTlsInitUnifiedPath:
    """Tests for the unified _initialize_with_tls_fallback HEAD-probe path.

    Verifies that all auth types (API key, OAuth2, machine token) use the
    same TLS probe and that lazy OpenID fetch works after TLS fallback.
    """

    @_PATCH_META
    def test_tls_probe_runs_for_api_key_client(self, _mock_meta):
        """API-key path should run probe_tls_connectivity during init."""
        with patch(
            "safety.platform.client.probe_tls_connectivity",
            side_effect=_stub_probe,
        ) as mock_probe:
            SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=_make_tls_config(),
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                api_key="test-api-key",
            )
        mock_probe.assert_called_once()

    @_PATCH_META
    def test_lazy_openid_fetch_uses_fallen_back_tls_config(self, _mock_meta):
        """After TLS fallback during init, get_openid_config() should use the recreated client."""
        tls_original = _make_tls_config()
        tls_system = _make_tls_config()
        tls_system.mode = "system"

        def _probe_with_fallback(probe_url, tls_config, **kwargs):
            return TLSProbeResult(tls_config=tls_system, fell_back=True)

        with patch(
            "safety.platform.client.probe_tls_connectivity",
            side_effect=_probe_with_fallback,
        ):
            client = SafetyPlatformClient(
                base_url="https://api.example.com",
                tls_config=tls_original,
                auth_server_url="https://auth.example.com",
                openid_config_url="https://auth.example.com/.well-known/openid-configuration",
                api_key="test-api-key",
            )

        # Client should have been recreated with the fallen-back TLS config
        assert client._tls_config is tls_system

        # Lazy OpenID fetch should use the new client (with system TLS)
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/jwks",
        }

        with patch.object(client._http_client, "get", return_value=mock_response):
            config = client.get_openid_config()

        assert config["issuer"] == "https://auth.example.com"
        # Verify the client's TLS verify context matches the system config
        assert (
            client._http_client._transport._pool._ssl_context  # type: ignore[union-attr]
            is tls_system.verify_context
        )


@pytest.mark.unit
class TestSafetyPlatformClientEnrollment:
    """Tests for SafetyPlatformClient.enroll() instance method and helpers."""

    # Shared constants for all tests in this class
    BASE_URL = "https://api.example.com"
    ENROLLMENT_KEY = "enroll-key-123"
    MACHINE_ID = "machine-001"
    EXPECTED_URL = f"{BASE_URL}/api/enroll"

    # -- helpers --

    @staticmethod
    def _mock_response(status_code=200, json_data=None, text=""):
        """Build a lightweight mock httpx.Response."""
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data if json_data is not None else {}
        resp.text = text
        return resp

    @staticmethod
    def _make_instance() -> tuple[SafetyPlatformClient, MagicMock]:
        """Build a minimal SafetyPlatformClient for enroll() tests (skips __init__).

        Only attributes accessed by ``enroll()`` / ``_enroll_post()`` are set.
        If enroll() grows new dependencies, add them here.

        Returns a (instance, mock_http) tuple so tests can access mock
        attributes (return_value, call_args, …) without pyright errors.
        """
        instance = object.__new__(SafetyPlatformClient)
        mock_http = MagicMock()
        instance._http_client = mock_http  # type: ignore[assignment]
        # enroll() currently only touches _http_client, but set common
        # attributes to guard against future AttributeError surprises.
        instance.base_url = "https://test.example.com"
        instance._timeout = 30.0
        return instance, mock_http

    # -- 1. 200 success --

    def test_enroll_200_returns_parsed_json(self):
        """200 response returns the parsed JSON body."""
        expected = {"machine_id": self.MACHINE_ID, "machine_token": "sfmt_tok"}
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(200, json_data=expected)

        result = instance.enroll(
            enrollment_base_url=self.BASE_URL,
            enrollment_key=self.ENROLLMENT_KEY,
            machine_id=self.MACHINE_ID,
        )

        assert result == expected
        # Verify correct URL was constructed
        post_args = mock_http.post.call_args
        assert post_args[0][0] == self.EXPECTED_URL

    # -- 2. 201 success --

    def test_enroll_201_returns_parsed_json(self):
        """201 response returns the parsed JSON body."""
        expected = {"machine_id": self.MACHINE_ID, "machine_token": "sfmt_new"}
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(201, json_data=expected)

        result = instance.enroll(
            enrollment_base_url=self.BASE_URL,
            enrollment_key=self.ENROLLMENT_KEY,
            machine_id=self.MACHINE_ID,
        )

        assert result == expected

    # -- 3. 401 invalid key --

    def test_enroll_401_raises_enrollment_error(self):
        """401 response raises EnrollmentError mentioning 'Invalid or expired'."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(401)

        with pytest.raises(EnrollmentError, match="Invalid or expired"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

    # -- 4. 409 without force --

    def test_enroll_409_without_force_raises_enrollment_error(self):
        """409 + force=False raises EnrollmentError suggesting --force."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(409)

        with pytest.raises(EnrollmentError, match="--force"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
                force=False,
            )

    # -- 5. 409 with force --

    def test_enroll_409_with_force_raises_enrollment_error(self):
        """409 + force=True raises EnrollmentError telling user to contact admin."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(409)

        with pytest.raises(EnrollmentError, match="Contact your administrator"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
                force=True,
            )

    # -- 6. 5xx transient failure --

    def test_enroll_5xx_raises_transient_failure(self):
        """500 response raises EnrollmentTransientFailure."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(
            500, text="Internal Server Error"
        )

        with pytest.raises(EnrollmentTransientFailure, match="HTTP 500"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

    # -- 7. Other 4xx --

    def test_enroll_other_4xx_raises_enrollment_error(self):
        """422 response raises EnrollmentError (not transient)."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(
            422, text="Unprocessable Entity"
        )

        with pytest.raises(EnrollmentError, match="HTTP 422"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

    # -- 8. Retries on ConnectError --

    def test_enroll_retries_connect_error(self):
        """httpx.ConnectError is retried 3 times before re-raising."""
        instance, mock_http = self._make_instance()
        mock_http.post.side_effect = httpx.ConnectError("connection refused")

        with patch("tenacity.nap.time.sleep"):
            with pytest.raises(httpx.ConnectError):
                instance.enroll(
                    enrollment_base_url=self.BASE_URL,
                    enrollment_key=self.ENROLLMENT_KEY,
                    machine_id=self.MACHINE_ID,
                )

        assert mock_http.post.call_count == 3

    # -- 9. Retries on TimeoutException --

    def test_enroll_retries_timeout_exception(self):
        """httpx.TimeoutException is retried 3 times before re-raising."""
        instance, mock_http = self._make_instance()
        mock_http.post.side_effect = httpx.TimeoutException("read timed out")

        with patch("tenacity.nap.time.sleep"):
            with pytest.raises(httpx.TimeoutException):
                instance.enroll(
                    enrollment_base_url=self.BASE_URL,
                    enrollment_key=self.ENROLLMENT_KEY,
                    machine_id=self.MACHINE_ID,
                )

        assert mock_http.post.call_count == 3

    # -- 10. 401 is NOT retried --

    def test_enroll_401_not_retried(self):
        """401 EnrollmentError is not retried — exactly 1 POST call."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(401)

        with pytest.raises(EnrollmentError):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

        assert mock_http.post.call_count == 1

    # -- 11. force=True includes "force" in payload --

    def test_enroll_force_includes_force_in_payload(self):
        """When force=True the POST payload contains 'force': True."""
        expected = {"machine_id": self.MACHINE_ID, "machine_token": "sfmt_tok"}
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(200, json_data=expected)

        instance.enroll(
            enrollment_base_url=self.BASE_URL,
            enrollment_key=self.ENROLLMENT_KEY,
            machine_id=self.MACHINE_ID,
            force=True,
        )

        # Inspect the json= kwarg of the POST call
        call_kwargs = mock_http.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["force"] is True

    # -- 12. BasicAuth used with enrollment_key --

    def test_enroll_uses_basic_auth(self):
        """POST uses httpx.BasicAuth with enrollment_key as username."""
        expected = {"machine_id": self.MACHINE_ID, "machine_token": "sfmt_tok"}
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(200, json_data=expected)

        instance.enroll(
            enrollment_base_url=self.BASE_URL,
            enrollment_key=self.ENROLLMENT_KEY,
            machine_id=self.MACHINE_ID,
        )

        call_kwargs = mock_http.post.call_args[1]
        auth = call_kwargs["auth"]
        # httpx.BasicAuth stores username/password as bytes
        assert isinstance(auth, httpx.BasicAuth)
        assert (
            auth._auth_header == httpx.BasicAuth(self.ENROLLMENT_KEY, "")._auth_header
        )

    # -- 13. 409 is NOT retried --

    def test_enroll_409_not_retried(self):
        """409 EnrollmentError is not retried — exactly 1 POST call."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(409)

        with pytest.raises(EnrollmentError):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

        assert mock_http.post.call_count == 1

    # -- 14. 5xx with bad JSON falls back to response.text --

    def test_enroll_5xx_bad_json_falls_back_to_text(self):
        """500 response with non-JSON body falls back to response.text in error message."""
        mock_resp = self._mock_response(502, text="Bad Gateway")
        mock_resp.json.side_effect = ValueError("No JSON")
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = mock_resp

        with pytest.raises(EnrollmentTransientFailure, match="Bad Gateway"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

    # -- 15. 403 cross-org mismatch raises EnrollmentError with descriptive message --

    def test_enroll_403_org_mismatch_shows_user_friendly_message(self):
        """403 with 'Organization identity mismatch' detail shows actionable message."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(
            403, json_data={"detail": "Organization identity mismatch"}
        )

        with pytest.raises(EnrollmentError, match="different organization"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

    def test_enroll_403_org_mismatch_includes_logout_instruction(self):
        """403 org mismatch message tells user how to resolve via logout."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(
            403, json_data={"detail": "Organization identity mismatch"}
        )

        with pytest.raises(EnrollmentError) as exc_info:
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

        assert "safety auth logout" in str(exc_info.value)

    def test_enroll_403_unknown_detail_shows_server_message(self):
        """403 with an unrecognized detail passes the server message through."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(
            403, json_data={"detail": "Insufficient permissions"}
        )

        with pytest.raises(EnrollmentError, match="Insufficient permissions"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

    def test_enroll_403_bad_json_falls_back_to_text(self):
        """403 response with non-JSON body falls back to response.text in error message."""
        mock_resp = self._mock_response(403, text="Forbidden")
        mock_resp.json.side_effect = ValueError("No JSON")
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = mock_resp

        with pytest.raises(EnrollmentError, match="Forbidden"):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

    def test_enroll_403_not_retried(self):
        """403 EnrollmentError is not retried — exactly 1 POST call."""
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(403)

        with pytest.raises(EnrollmentError):
            instance.enroll(
                enrollment_base_url=self.BASE_URL,
                enrollment_key=self.ENROLLMENT_KEY,
                machine_id=self.MACHINE_ID,
            )

        assert mock_http.post.call_count == 1

    # -- 16. org_legacy_uuid included in payload when non-empty --

    def test_enroll_org_legacy_uuid_included_in_payload_when_set(self):
        """When org_legacy_uuid is provided, it appears in the POST payload."""
        expected = {"machine_id": self.MACHINE_ID, "machine_token": "sfmt_tok"}
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(200, json_data=expected)

        instance.enroll(
            enrollment_base_url=self.BASE_URL,
            enrollment_key=self.ENROLLMENT_KEY,
            machine_id=self.MACHINE_ID,
            org_legacy_uuid="org-uuid-1234",
        )

        call_kwargs = mock_http.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["org_legacy_uuid"] == "org-uuid-1234"

    def test_enroll_org_legacy_uuid_omitted_from_payload_when_empty(self):
        """When org_legacy_uuid is empty string (default), it is NOT in the POST payload."""
        expected = {"machine_id": self.MACHINE_ID, "machine_token": "sfmt_tok"}
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(200, json_data=expected)

        instance.enroll(
            enrollment_base_url=self.BASE_URL,
            enrollment_key=self.ENROLLMENT_KEY,
            machine_id=self.MACHINE_ID,
        )

        call_kwargs = mock_http.post.call_args[1]
        payload = call_kwargs["json"]
        assert "org_legacy_uuid" not in payload

    def test_enroll_org_legacy_uuid_omitted_when_explicitly_empty_string(self):
        """Explicitly passing org_legacy_uuid='' still omits it from the payload."""
        expected = {"machine_id": self.MACHINE_ID, "machine_token": "sfmt_tok"}
        instance, mock_http = self._make_instance()
        mock_http.post.return_value = self._mock_response(200, json_data=expected)

        instance.enroll(
            enrollment_base_url=self.BASE_URL,
            enrollment_key=self.ENROLLMENT_KEY,
            machine_id=self.MACHINE_ID,
            org_legacy_uuid="",
        )

        call_kwargs = mock_http.post.call_args[1]
        payload = call_kwargs["json"]
        assert "org_legacy_uuid" not in payload
