"""Enrollment HTTP helper for MDM machine enrollment.

Thin adapter that loads config and delegates to the platform client's
``enroll()`` method for the actual HTTP work.
"""

import logging
from typing import TYPE_CHECKING

import httpx

from safety.constants import get_required_config_setting
from safety.errors import EnrollmentTransientFailure

if TYPE_CHECKING:
    from safety.platform.client import SafetyPlatformClient

logger = logging.getLogger(__name__)


def call_enrollment_endpoint(
    platform_client: "SafetyPlatformClient",
    enrollment_key: str,
    machine_id: str,
    force: bool = False,
) -> dict:
    """Public wrapper — delegates to platform_client.enroll().

    Catches transient network errors (httpx.NetworkError, httpx.TimeoutException)
    that tenacity re-raises after retry exhaustion and wraps them in
    EnrollmentTransientFailure (exit code 75) so MDM orchestrators can
    distinguish retryable failures from permanent ones.

    Args:
        platform_client: The already-configured SafetyPlatformClient instance.
        enrollment_key: The enrollment key provided by the MDM administrator.
        machine_id: The machine identity to enroll.
        force: When True, request re-enrollment for an already-enrolled machine.

    Returns:
        dict with keys 'machine_id' and 'machine_token' on success.

    Raises:
        EnrollmentError: On non-retryable failures (401, 409, invalid key).
        EnrollmentTransientFailure: On transient failures (5xx, network errors).
    """
    platform_url = get_required_config_setting("SAFETY_PLATFORM_V2_URL")

    try:
        return platform_client.enroll(
            enrollment_base_url=platform_url,
            enrollment_key=enrollment_key,
            machine_id=machine_id,
            force=force,
        )
    # Broader than @retry's types: also wraps ReadError/WriteError/CloseError
    # (transient, but not retried) as exit-code 75 for MDM orchestrators.
    # Excludes ProtocolError / UnsupportedProtocol (non-transient config bugs).
    except (httpx.NetworkError, httpx.TimeoutException) as exc:
        raise EnrollmentTransientFailure(
            f"Enrollment failed after retries: {exc}"
        ) from exc
