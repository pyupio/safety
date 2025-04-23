from importlib.metadata import PackageNotFoundError, version
import logging
import os
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
    }
