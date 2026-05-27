from types import SimpleNamespace

import httpx

from safety.httpx_compat import (
    httpx_network_error_types,
    httpx_retry_error_types,
    httpx_transient_error_types,
)


class FakeNetworkError(Exception):
    pass


class FakeConnectError(Exception):
    pass


class FakeReadError(Exception):
    pass


class FakeWriteError(Exception):
    pass


class FakeCloseError(Exception):
    pass


class FakeTimeoutException(Exception):
    pass


class FakeHTTPStatusError(Exception):
    pass


class FakeRequestError(Exception):
    pass


def test_httpx_network_error_types_prefers_network_error():
    fake_httpx = SimpleNamespace(
        NetworkError=FakeNetworkError,
        ConnectError=FakeConnectError,
        TimeoutException=FakeTimeoutException,
        HTTPStatusError=FakeHTTPStatusError,
        RequestError=FakeRequestError,
    )

    assert httpx_network_error_types(fake_httpx) == (FakeNetworkError,)


def test_httpx_network_error_types_falls_back_to_concrete_errors():
    fake_httpx = SimpleNamespace(
        ConnectError=FakeConnectError,
        ReadError=FakeReadError,
        WriteError=FakeWriteError,
        CloseError=FakeCloseError,
        TimeoutException=FakeTimeoutException,
        HTTPStatusError=FakeHTTPStatusError,
        RequestError=FakeRequestError,
    )

    assert httpx_network_error_types(fake_httpx) == (
        FakeConnectError,
        FakeReadError,
        FakeWriteError,
        FakeCloseError,
    )


def test_httpx_network_error_types_omits_missing_request_error():
    fake_httpx = SimpleNamespace(
        TimeoutException=FakeTimeoutException,
        HTTPStatusError=FakeHTTPStatusError,
    )

    assert httpx_network_error_types(fake_httpx) == ()


def test_httpx_transient_error_types_include_timeout():
    fake_httpx = SimpleNamespace(
        ConnectError=FakeConnectError,
        TimeoutException=FakeTimeoutException,
        HTTPStatusError=FakeHTTPStatusError,
        RequestError=FakeRequestError,
    )

    assert httpx_transient_error_types(fake_httpx) == (
        FakeConnectError,
        FakeTimeoutException,
    )


def test_httpx_transient_error_types_handles_missing_request_error():
    fake_httpx = SimpleNamespace(
        TimeoutException=FakeTimeoutException,
        HTTPStatusError=FakeHTTPStatusError,
    )

    assert httpx_transient_error_types(fake_httpx) == (FakeTimeoutException,)


def test_httpx_retry_error_types_include_http_status_error():
    fake_httpx = SimpleNamespace(
        ConnectError=FakeConnectError,
        TimeoutException=FakeTimeoutException,
        HTTPStatusError=FakeHTTPStatusError,
        RequestError=FakeRequestError,
    )

    assert httpx_retry_error_types(fake_httpx) == (
        FakeConnectError,
        FakeTimeoutException,
        FakeHTTPStatusError,
    )


def test_httpx_retry_error_types_works_with_installed_httpx():
    retry_types = httpx_retry_error_types()

    assert httpx.TimeoutException in retry_types
    assert httpx.HTTPStatusError in retry_types
