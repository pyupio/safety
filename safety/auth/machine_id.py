"""Machine ID resolution for MDM enrollment authentication."""

from __future__ import annotations

import configparser
import logging
import os
import platform
from typing import Optional

from safety.auth.constants import MACHINE_ID_MAX_LENGTH
from safety.config.auth import MachineCredentialConfig
from safety.errors import MachineIdUnavailableError
from safety.utils.machine_id import (
    get_linux_machine_id,
    get_macos_machine_id,
    get_windows_machine_id,
)

logger = logging.getLogger(__name__)


def _validate_machine_id(value: Optional[str]) -> Optional[str]:
    """
    Strip whitespace and validate a candidate machine ID.

    Returns:
        The stripped value if valid, or None.
    """
    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    if len(value) > MACHINE_ID_MAX_LENGTH:
        return None

    return value


def resolve_machine_id(
    skip_enrolled: bool = False,
    override: Optional[str] = None,
) -> str:
    """
    Resolve the machine identity using a layered strategy.

    Resolution order:
        1. Explicit override (highest priority)
        2. Enrolled value from auth.ini ``[machine]`` section
           (skipped when *skip_enrolled* is True)
        3. ``SAFETY_MACHINE_ID`` environment variable
        4. Platform-specific hardware ID detection

    Args:
        skip_enrolled: When True, skip reading the enrolled machine ID
            from persistent storage.  Useful during initial enrollment
            to avoid a chicken-and-egg loop.
        override: An explicit machine ID that takes absolute priority
            over every other source.

    Returns:
        A validated, non-empty machine ID string.

    Raises:
        MachineIdUnavailableError: If no source yields a valid ID.
    """

    # 1. Explicit override
    if override is not None:
        validated = _validate_machine_id(override)
        if validated:
            return validated
        raise MachineIdUnavailableError(
            message="Provided machine ID override is invalid"
        )

    # 2. Enrolled value from persistent storage
    if not skip_enrolled:
        try:
            cred = MachineCredentialConfig.from_storage()
            if cred is not None:
                validated = _validate_machine_id(cred.machine_id)
                if validated:
                    return validated
        except (OSError, ValueError, configparser.Error):
            logger.debug("Failed to read enrolled machine ID", exc_info=True)

    # 3. Environment variable
    env_value = os.environ.get("SAFETY_MACHINE_ID")
    validated = _validate_machine_id(env_value)
    if validated:
        return validated

    # 4. Platform detection
    system = platform.system().lower()
    detector = {
        "linux": get_linux_machine_id,
        "darwin": get_macos_machine_id,
        "windows": get_windows_machine_id,
    }.get(system)

    if detector is not None:
        try:
            platform_id = detector()
            validated = _validate_machine_id(platform_id)
            if validated:
                return validated
        except (OSError, ValueError, configparser.Error):
            logger.debug("Platform machine ID detection failed", exc_info=True)

    raise MachineIdUnavailableError()
