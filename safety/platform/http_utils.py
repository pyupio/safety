import logging
import json
from typing import Callable, Optional, Any, TypeVar
import httpx
from authlib.integrations.base_client.errors import OAuthError
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential_jitter,
    retry_if_exception_type,
    before_sleep_log,
)

from safety.errors import (
    InvalidCredentialError,
    NetworkConnectionError,
    RequestTimeoutError,
    SafetyError,
    ServerError,
    TooManyRequestsError,
    SSLCertificateError,
)

F = TypeVar("F", bound=Callable[..., httpx.Response])
logger = logging.getLogger(__name__)


def extract_detail(response: httpx.Response) -> Optional[str]:
    """
    Extract error detail from HTTP response.

    Args:
        response: The HTTP response to extract detail from

    Returns:
        The extracted detail message, or None if extraction fails
    """
    try:
        data = response.json()
        return data.get("detail")
    except (json.JSONDecodeError, ValueError, AttributeError):
        return None


def parse_response(func: F) -> F:
    """
    Decorator for HTTP response parsing with retry logic and error handling.

    Handles authentication, rate limiting, and server errors with automatic
    retries for transient failures.

    Args:
        func: HTTP method to wrap (should return httpx.Response)

    Returns:
        Decorated function that returns parsed JSON data
    """

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=0.2, max=8.0, exp_base=3, jitter=0.3),
        reraise=True,
        retry=retry_if_exception_type(
            (
                NetworkConnectionError,
                RequestTimeoutError,
                TooManyRequestsError,
                ServerError,
            )
        ),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    def wrapper(*args, **kwargs) -> Any:
        try:
            response = func(*args, **kwargs)

            if response.is_success:
                return _parse_successful_response(response)

            if response.status_code == 403:
                return _handle_forbidden(response)
            elif response.status_code == 429:
                return _handle_rate_limit(response)
            elif response.is_client_error:
                return _handle_client_error(response)
            elif response.is_server_error:
                return _handle_server_error(response)

            # Fallback for unexpected status codes
            response.raise_for_status()

        except OAuthError as e:
            logger.warning(f"OAuth authentication failed: {e}")
            raise InvalidCredentialError(
                message="Your token authentication expired, try login again."
            ) from e

        except httpx.ConnectError as e:
            if _is_ca_certificate_error(e):
                raise SSLCertificateError() from e

            raise NetworkConnectionError() from e

        except httpx.TimeoutException as e:
            raise RequestTimeoutError() from e

    return wrapper  # type: ignore


def _parse_successful_response(response: httpx.Response) -> Any:
    """
    Parse successful JSON response.
    """
    try:
        return response.json()
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in successful response: {e}")
        raise ServerError(message=f"Bad JSON response from server: {e}") from e


def _handle_forbidden(response: httpx.Response) -> None:
    """
    Handle 403 Forbidden responses.
    """
    detail = extract_detail(response)
    raise InvalidCredentialError(credential="Failed authentication.", reason=detail)


def _handle_rate_limit(response: httpx.Response) -> None:
    """
    Handle 429 Too Many Requests.
    """
    logger.warning("Rate limit exceeded")
    raise TooManyRequestsError(reason=response.text)


def _handle_client_error(response: httpx.Response) -> None:
    """
    Handle 4xx client errors.
    """
    try:
        data = response.json()
        reason = data.get("detail", "Client error occurred")
        error_code = data.get("error_code")
    except (json.JSONDecodeError, ValueError):
        reason = response.reason_phrase or "Client error"
        error_code = None

    raise SafetyError(message=reason, error_code=error_code)


def _handle_server_error(response: httpx.Response) -> None:
    """
    Handle 5xx server errors.
    """
    detail = extract_detail(response)
    logger.warning(f"Server error {response.status_code}: {detail}")
    raise ServerError(reason=detail)


def _is_ca_certificate_error(exception: Exception) -> bool:
    """
    Check if the exception is a CA/certificate verification error
    that might be resolved by switching trust stores.

    Returns True for certificate issues, False for other issues.
    """
    error_message = str(exception).lower()
    ca_error_indicators = [
        "certificate_verify_failed",
        "unable to get local issuer certificate",
        "self signed certificate",
        "certificate has expired",
        "unable to get issuer cert",
    ]
    if any(indicator in error_message for indicator in ca_error_indicators):
        return True

    return False
