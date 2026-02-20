import json
from unittest.mock import Mock, MagicMock

import httpx
import pytest
from authlib.integrations.base_client.errors import OAuthError

from safety.errors import (
    InvalidCredentialError,
    NetworkConnectionError,
    RequestTimeoutError,
    SafetyError,
    ServerError,
    SSLCertificateError,
    TooManyRequestsError,
)
from safety.platform.http_utils import (
    extract_detail,
    parse_response,
    is_ca_certificate_error,
    _handle_client_error,
    _handle_server_error,
    _handle_forbidden,
    _handle_rate_limit,
    _parse_successful_response,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    status_code: int = 200,
    json_data=None,
    text: str = "",
    reason_phrase: str = "OK",
    auth_header: str = "",
    json_raises=None,
):
    """Build a mock httpx.Response with the given properties."""
    resp = Mock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    resp.reason_phrase = reason_phrase

    # httpx.Response properties for status categories
    resp.is_success = 200 <= status_code < 300
    resp.is_client_error = 400 <= status_code < 500
    resp.is_server_error = 500 <= status_code < 600

    if json_raises:
        resp.json.side_effect = json_raises
    elif json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.return_value = {}

    # request object for authorization header checks (used by 403 branch)
    request = Mock()
    request.headers = {"authorization": auth_header} if auth_header else {}
    request.headers = MagicMock()
    request.headers.get = Mock(return_value=auth_header)
    resp.request = request

    return resp


# ---------------------------------------------------------------------------
# extract_detail tests
# ---------------------------------------------------------------------------


def test_extract_detail_valid_json_with_detail():
    response = Mock()
    response.json.return_value = {"detail": "Error message"}
    assert extract_detail(response) == "Error message"


def test_extract_detail_valid_json_without_detail():
    response = Mock()
    response.json.return_value = {"message": "Something else"}
    assert extract_detail(response) is None


def test_extract_detail_invalid_json():
    response = Mock()
    response.json.side_effect = ValueError()
    assert extract_detail(response) is None


def test_extract_detail_json_decode_error():
    response = Mock()
    response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
    assert extract_detail(response) is None


def test_extract_detail_attribute_error():
    response = Mock()
    response.json.side_effect = AttributeError()
    assert extract_detail(response) is None


def test_extract_detail_empty_response():
    response = Mock()
    response.json.return_value = {}
    assert extract_detail(response) is None


# ---------------------------------------------------------------------------
# is_ca_certificate_error tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIsCaCertificateError:
    """Tests for is_ca_certificate_error helper."""

    @pytest.mark.parametrize(
        "msg",
        [
            "SSL: certificate_verify_failed",
            "unable to get local issuer certificate",
            "self signed certificate in chain",
            "certificate has expired for host example.com",
            "unable to get issuer cert locally",
        ],
    )
    def test_returns_true_for_cert_errors(self, msg):
        assert is_ca_certificate_error(Exception(msg)) is True

    @pytest.mark.parametrize(
        "msg",
        [
            "Connection refused",
            "Name or service not known",
            "Network is unreachable",
            "",
        ],
    )
    def test_returns_false_for_non_cert_errors(self, msg):
        assert is_ca_certificate_error(Exception(msg)) is False

    def test_case_insensitive(self):
        assert is_ca_certificate_error(Exception("CERTIFICATE_VERIFY_FAILED")) is True


# ---------------------------------------------------------------------------
# TestParseResponseNoneHandling (existing — kept as-is)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseNoneHandling:
    """Tests for parse_response handling None returns from wrapped functions."""

    def test_parse_response_raises_server_error_on_none_return(self):
        """parse_response should raise ServerError when wrapped func returns None."""

        @parse_response  # type: ignore[arg-type]
        def returns_none():
            return None

        with pytest.raises(ServerError, match="No response received from server"):
            returns_none()

    def test_parse_response_succeeds_with_valid_response(self):
        """parse_response should work normally with a valid response."""

        @parse_response  # type: ignore[arg-type]
        def returns_response():
            response = Mock()
            response.is_success = True
            response.json.return_value = {"status": "ok"}
            return response

        result = returns_response()
        assert result == {"status": "ok"}


# ---------------------------------------------------------------------------
# parse_response decorator — success paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseSuccess:
    """Tests for successful response parsing through the decorator."""

    def test_200_returns_parsed_json(self):
        resp = _make_response(status_code=200, json_data={"key": "value"})

        @parse_response
        def api_call():
            return resp

        assert api_call() == {"key": "value"}

    def test_200_returns_list_json(self):
        resp = _make_response(status_code=200, json_data=[1, 2, 3])

        @parse_response
        def api_call():
            return resp

        assert api_call() == [1, 2, 3]

    def test_200_returns_empty_dict(self):
        resp = _make_response(status_code=200, json_data={})

        @parse_response
        def api_call():
            return resp

        assert api_call() == {}

    def test_201_created_is_success(self):
        resp = _make_response(status_code=201, json_data={"id": 42})
        resp.is_success = True

        @parse_response
        def api_call():
            return resp

        assert api_call() == {"id": 42}

    def test_passes_args_and_kwargs_to_wrapped_func(self):
        resp = _make_response(status_code=200, json_data={"ok": True})

        @parse_response
        def api_call(a, b, key=None):
            assert a == 1
            assert b == 2
            assert key == "val"
            return resp

        assert api_call(1, 2, key="val") == {"ok": True}


# ---------------------------------------------------------------------------
# parse_response decorator — invalid JSON on success
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseInvalidJson:
    """200 OK but body is not valid JSON → ServerError."""

    def test_200_with_invalid_json_raises_server_error(self):
        resp = _make_response(
            status_code=200,
            json_raises=json.JSONDecodeError("Expecting value", "", 0),
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(ServerError, match="Bad JSON response from server"):
            api_call()


# ---------------------------------------------------------------------------
# parse_response decorator — 403 Forbidden
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseForbidden:
    """Tests for 403 handling — machine token vs normal auth."""

    def test_403_with_basic_auth_raises_machine_token_error(self):
        """403 + Basic auth header → InvalidCredentialError with machine-token message."""
        resp = _make_response(
            status_code=403,
            auth_header="Basic dXNlcjpwYXNz",
            json_data={"detail": "Forbidden"},
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(
            InvalidCredentialError, match="Machine token authentication is not accepted"
        ):
            api_call()

    def test_403_without_basic_auth_raises_credential_error(self):
        """403 without Basic auth → InvalidCredentialError via _handle_forbidden."""
        resp = _make_response(
            status_code=403,
            auth_header="Bearer some-token",
            json_data={"detail": "Subscription expired"},
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(
            InvalidCredentialError, match="Failed authentication"
        ) as exc_info:
            api_call()
        assert "Subscription expired" in str(exc_info.value)

    def test_403_without_auth_header_raises_credential_error(self):
        """403 with no auth header at all → _handle_forbidden path."""
        resp = _make_response(
            status_code=403, auth_header="", json_data={"detail": "No access"}
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(InvalidCredentialError, match="Failed authentication"):
            api_call()


# ---------------------------------------------------------------------------
# parse_response decorator — 429 Rate Limit
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseRateLimit:
    """429 → TooManyRequestsError (retryable)."""

    def test_429_raises_too_many_requests_error(self):
        resp = _make_response(
            status_code=429, text="Rate limit exceeded. Retry after 60s."
        )

        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            return resp

        with pytest.raises(TooManyRequestsError, match="Rate limit exceeded"):
            api_call()

        # TooManyRequestsError is retryable, so tenacity retries 3 times
        assert call_count == 3


# ---------------------------------------------------------------------------
# parse_response decorator — 4xx Client Errors (non-403)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseClientError:
    """4xx (non-403, non-429) → SafetyError via _handle_client_error."""

    def test_400_with_json_detail_raises_safety_error(self):
        resp = _make_response(
            status_code=400,
            json_data={"detail": "Invalid request body", "error_code": 1001},
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(SafetyError, match="Invalid request body") as exc_info:
            api_call()
        assert exc_info.value.error_code == 1001

    def test_404_with_json_no_error_code(self):
        resp = _make_response(
            status_code=404,
            json_data={"detail": "Not found"},
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(SafetyError, match="Not found") as exc_info:
            api_call()
        assert exc_info.value.error_code is None

    def test_422_with_invalid_json_falls_back_to_reason_phrase(self):
        resp = _make_response(
            status_code=422,
            reason_phrase="Unprocessable Entity",
            json_raises=json.JSONDecodeError("", "", 0),
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(SafetyError, match="Unprocessable Entity"):
            api_call()

    def test_400_without_detail_uses_default_message(self):
        """JSON body present but no 'detail' key → default message."""
        resp = _make_response(
            status_code=400,
            json_data={"error": "something"},
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(SafetyError, match="Client error occurred"):
            api_call()

    def test_client_error_is_not_retried(self):
        """SafetyError from 4xx is NOT in the retryable set → no retry."""
        resp = _make_response(status_code=400, json_data={"detail": "bad"})
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            return resp

        with pytest.raises(SafetyError):
            api_call()

        assert call_count == 1  # no retries


# ---------------------------------------------------------------------------
# parse_response decorator — 5xx Server Errors
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseServerError:
    """5xx → ServerError (retryable)."""

    def test_500_raises_server_error_with_detail(self):
        resp = _make_response(
            status_code=500,
            json_data={"detail": "Internal server error"},
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(ServerError, match="Reason: Internal server error"):
            api_call()

    def test_502_raises_server_error_without_detail(self):
        resp = _make_response(
            status_code=502,
            json_data={},
        )

        @parse_response
        def api_call():
            return resp

        with pytest.raises(ServerError):
            api_call()

    def test_server_error_is_retried_three_times(self):
        resp = _make_response(status_code=500, json_data={"detail": "oops"})
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            return resp

        with pytest.raises(ServerError):
            api_call()

        assert call_count == 3


# ---------------------------------------------------------------------------
# parse_response decorator — Connection Errors
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseConnectionError:
    """httpx.ConnectError → NetworkConnectionError or SSLCertificateError."""

    def test_connect_error_raises_network_connection_error(self):
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            raise httpx.ConnectError("Connection refused")

        with pytest.raises(NetworkConnectionError):
            api_call()

        # NetworkConnectionError is retryable
        assert call_count == 3

    def test_ssl_certificate_error_raises_ssl_error(self):
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            raise httpx.ConnectError("SSL: certificate_verify_failed")

        with pytest.raises(SSLCertificateError):
            api_call()

        # SSLCertificateError is a subclass of NetworkConnectionError → retryable
        assert call_count == 3

    def test_self_signed_cert_error(self):
        @parse_response
        def api_call():
            raise httpx.ConnectError("self signed certificate in chain")

        with pytest.raises(SSLCertificateError):
            api_call()


# ---------------------------------------------------------------------------
# parse_response decorator — Timeout Errors
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseTimeout:
    """httpx.TimeoutException → RequestTimeoutError (retryable)."""

    def test_timeout_raises_request_timeout_error(self):
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            raise httpx.TimeoutException("timed out")

        with pytest.raises(RequestTimeoutError):
            api_call()

        assert call_count == 3

    def test_read_timeout_raises_request_timeout_error(self):
        @parse_response
        def api_call():
            raise httpx.ReadTimeout("read timed out")

        with pytest.raises(RequestTimeoutError):
            api_call()


# ---------------------------------------------------------------------------
# parse_response decorator — OAuthError
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseOAuthError:
    """OAuthError → InvalidCredentialError (NOT retryable)."""

    def test_oauth_error_raises_invalid_credential_error(self):
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            raise OAuthError(error="invalid_grant", description="Token expired")

        with pytest.raises(
            InvalidCredentialError, match="token authentication expired"
        ):
            api_call()

        # InvalidCredentialError is NOT in the retryable set
        assert call_count == 1


# ---------------------------------------------------------------------------
# parse_response decorator — Retry Behavior
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseResponseRetryBehavior:
    """Verify that transient errors are retried and permanent errors are not."""

    def test_transient_failure_then_success(self):
        """Succeed on 2nd attempt after a transient 500."""
        good_resp = _make_response(status_code=200, json_data={"recovered": True})
        bad_resp = _make_response(status_code=500, json_data={"detail": "transient"})
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return bad_resp
            return good_resp

        result = api_call()
        assert result == {"recovered": True}
        assert call_count == 2

    def test_connection_error_then_success(self):
        """Succeed on 2nd attempt after a transient connection error."""
        good_resp = _make_response(status_code=200, json_data={"ok": True})
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("Connection refused")
            return good_resp

        result = api_call()
        assert result == {"ok": True}
        assert call_count == 2

    def test_forbidden_is_not_retried(self):
        """InvalidCredentialError from 403 is not in the retryable set."""
        resp = _make_response(status_code=403, auth_header="", json_data={})
        call_count = 0

        @parse_response
        def api_call():
            nonlocal call_count
            call_count += 1
            return resp

        with pytest.raises(InvalidCredentialError):
            api_call()

        assert call_count == 1


# ---------------------------------------------------------------------------
# _handle_client_error / _handle_server_error / _handle_forbidden / _handle_rate_limit
# Unit tests for the internal helpers directly
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestHandleClientError:
    """Direct tests for _handle_client_error."""

    def test_json_with_detail_and_error_code(self):
        resp = _make_response(
            status_code=400, json_data={"detail": "bad input", "error_code": 42}
        )
        with pytest.raises(SafetyError, match="bad input") as exc_info:
            _handle_client_error(resp)
        assert exc_info.value.error_code == 42

    def test_json_without_detail_uses_default(self):
        resp = _make_response(status_code=400, json_data={"other": "field"})
        with pytest.raises(SafetyError, match="Client error occurred"):
            _handle_client_error(resp)

    def test_invalid_json_uses_reason_phrase(self):
        resp = _make_response(
            status_code=400,
            reason_phrase="Bad Request",
            json_raises=ValueError("no json"),
        )
        with pytest.raises(SafetyError, match="Bad Request") as exc_info:
            _handle_client_error(resp)
        assert exc_info.value.error_code is None

    def test_invalid_json_no_reason_phrase_uses_fallback(self):
        resp = _make_response(
            status_code=400,
            reason_phrase="",
            json_raises=json.JSONDecodeError("", "", 0),
        )
        with pytest.raises(SafetyError, match="Client error"):
            _handle_client_error(resp)


@pytest.mark.unit
class TestHandleServerError:
    """Direct tests for _handle_server_error."""

    def test_with_detail(self):
        resp = _make_response(status_code=500, json_data={"detail": "DB down"})
        with pytest.raises(ServerError, match="Reason: DB down"):
            _handle_server_error(resp)

    def test_without_detail(self):
        resp = _make_response(status_code=500, json_data={})
        with pytest.raises(ServerError):
            _handle_server_error(resp)
        # No "Reason:" when detail is None


@pytest.mark.unit
class TestHandleForbidden:
    """Direct tests for _handle_forbidden."""

    def test_with_detail(self):
        resp = _make_response(
            status_code=403, json_data={"detail": "Account suspended"}
        )
        with pytest.raises(InvalidCredentialError, match="Account suspended"):
            _handle_forbidden(resp)

    def test_without_detail(self):
        resp = _make_response(status_code=403, json_data={})
        with pytest.raises(InvalidCredentialError, match="Failed authentication"):
            _handle_forbidden(resp)


@pytest.mark.unit
class TestHandleRateLimit:
    """Direct tests for _handle_rate_limit."""

    def test_includes_response_text(self):
        resp = _make_response(status_code=429, text="slow down")
        with pytest.raises(TooManyRequestsError, match="slow down"):
            _handle_rate_limit(resp)


@pytest.mark.unit
class TestParseSuccessfulResponse:
    """Direct tests for _parse_successful_response."""

    def test_valid_json(self):
        resp = _make_response(status_code=200, json_data={"a": 1})
        assert _parse_successful_response(resp) == {"a": 1}

    def test_invalid_json(self):
        resp = _make_response(
            status_code=200,
            json_raises=json.JSONDecodeError("Expecting value", "", 0),
        )
        with pytest.raises(ServerError, match="Bad JSON response"):
            _parse_successful_response(resp)
