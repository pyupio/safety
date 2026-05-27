from typing import Any, Tuple, Type

import httpx


def _httpx_exception_type(
    httpx_module: Any,
    name: str,
) -> Tuple[Type[BaseException], ...]:
    exception_type = getattr(httpx_module, name, None)
    return (exception_type,) if exception_type is not None else ()


def httpx_network_error_types(
    httpx_module: Any = httpx,
) -> Tuple[Type[BaseException], ...]:
    """Return httpx network exception classes across httpx versions."""
    network_error = getattr(httpx_module, "NetworkError", None)
    if network_error is not None:
        return (network_error,)

    concrete_error_names = ("ConnectError", "ReadError", "WriteError", "CloseError")
    concrete_errors = tuple(
        getattr(httpx_module, name)
        for name in concrete_error_names
        if hasattr(httpx_module, name)
    )
    if concrete_errors:
        return concrete_errors

    transport_error = getattr(httpx_module, "TransportError", None)
    if transport_error is not None:
        return (transport_error,)

    return _httpx_exception_type(httpx_module, "RequestError")


def httpx_transient_error_types(
    httpx_module: Any = httpx,
) -> Tuple[Type[BaseException], ...]:
    return (
        *httpx_network_error_types(httpx_module),
        *_httpx_exception_type(httpx_module, "TimeoutException"),
    )


def httpx_retry_error_types(
    httpx_module: Any = httpx,
) -> Tuple[Type[BaseException], ...]:
    return (
        *httpx_transient_error_types(httpx_module),
        *_httpx_exception_type(httpx_module, "HTTPStatusError"),
    )
