from importlib.metadata import PackageNotFoundError, version
import logging
from typing import Optional


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
