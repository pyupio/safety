import os
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


def get_path() -> Optional[str]:
    """
    Get the PATH environment variable with pyapp-related paths filtered out.

    This is necessary when running as a pyapp binary to prevent the bundled
    Python from interfering with system tools.

    Returns:
        str or None: The filtered PATH string (or original PATH if not in PYAPP environment),
                     or None if PATH is not set
    """
    # If not in PYAPP environment, return original PATH
    if "PYAPP" not in os.environ:
        return os.environ.get("PATH")

    # If PATH is not set, return None
    if "PATH" not in os.environ:
        return None

    logger.debug(
        "Binary environment detected, filtering internal Python path from PATH"
    )

    original_path = os.environ["PATH"]
    path_parts = original_path.split(os.pathsep)

    filtered_paths = []
    removed_paths = []

    for path in path_parts:
        path_lower = path.lower()
        if "pyapp" in path_lower and "safety" in path_lower:
            removed_paths.append(path)
            logger.debug(f"Removing internal Python path from PATH: {path}")
        else:
            filtered_paths.append(path)

    if removed_paths:
        filtered_path = os.pathsep.join(filtered_paths)
        logger.info(f"Filtered {len(removed_paths)} internal Python path(s) from PATH")
        logger.debug(
            f"Original PATH entries: {len(path_parts)}, Filtered PATH entries: {len(filtered_paths)}"
        )
        return filtered_path

    return original_path


def get_env() -> Dict[str, str]:
    """
    Get a copy of the environment with pyapp-related paths filtered from PATH.

    This is useful for subprocess calls to prevent the bundled Python from
    interfering with system tools.

    Returns:
        dict: A copy of os.environ with filtered PATH
    """
    env = os.environ.copy()
    filtered_path = get_path()

    if filtered_path is not None:
        env["PATH"] = filtered_path

    return env
