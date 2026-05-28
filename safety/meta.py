from importlib.metadata import PackageNotFoundError, version
import logging
import os
import platform
from typing import Dict, Optional


LOG = logging.getLogger(__name__)


def get_version() -> Optional[str]:
    """
    Get the version of the Safety package.

    Returns:
      Optional[str]: The Safety version if found, otherwise None.
    """
    try:
        return version("safety")
    except PackageNotFoundError:
        LOG.exception("Unable to get Safety version.")
        return None


def get_identifier() -> str:
    """
    Get the identifier of the source type.

    Returns:
      str: The source type identifier.
    """

    if source := os.environ.get("SAFETY_SOURCE_TYPE", None):
        return source

    from safety_schemas.models.events.types import SourceType

    return SourceType.SAFETY_CLI_PYPI.value


def get_user_agent() -> str:
    """
    Get the user agent string for HTTP requests.

    Returns:
      str: The user agent string in the format: safety-cli/{version} ({os} {arch}; Python/{python_version})
    """
    safety_version = get_version() or "unknown"
    os_name = platform.system()

    # Get architecture
    machine = platform.machine()
    # Normalize architecture names
    if machine in ("x86_64", "AMD64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm_64"
    elif machine == "i386":
        arch = "x86"
    else:
        arch = machine or "unknown"

    python_version = platform.python_version()

    return f"safety-cli/{safety_version} ({os_name} {arch}; Python/{python_version})"


def get_meta_http_headers() -> Dict[str, str]:
    """
    Get the metadata headers for the client.

    Returns:
      Dict[str, str]: The metadata headers.
    """

    from safety_schemas.models.events.constants import SAFETY_NAMESPACE

    namespace = SAFETY_NAMESPACE.title()

    return {
        f"{namespace}-Client-Version": get_version() or "",
        f"{namespace}-Client-Id": get_identifier(),
        "User-Agent": get_user_agent(),
    }
