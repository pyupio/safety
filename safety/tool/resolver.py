import sys
import subprocess
import shutil
import logging

from safety.utils.pyapp_utils import get_path, get_env

logger = logging.getLogger(__name__)


def get_unwrapped_command(name: str) -> str:
    """
    Find the true executable for a command, skipping wrappers/aliases/.bat files.

    Args:
        command: The command to resolve (e.g. 'pip', 'python')

    Returns:
        Path to the actual executable
    """
    logger.debug(f"get_unwrapped_command called with name: {name}")

    if sys.platform in ["win32"]:
        for lookup_term in [f"{name}.exe", name]:
            logger.debug(f"Windows platform detected, looking for: {lookup_term}")

            where_result = subprocess.run(
                ["where.exe", lookup_term],
                capture_output=True,
                text=True,
                env=get_env(),
            )

            logger.debug(f"where.exe returncode: {where_result.returncode}")
            logger.debug(f"where.exe stdout: {where_result.stdout}")
            logger.debug(f"where.exe stderr: {where_result.stderr}")

            if where_result.returncode == 0:
                for path in where_result.stdout.splitlines():
                    path = path.strip()
                    if not path:
                        continue

                    logger.debug(f"Checking path: {path}")
                    path_lower = path.lower()

                    if not path_lower.endswith((".exe", ".bat", ".cmd")):
                        logger.debug(f"Skipping non-executable path: {path}")
                        continue

                    if "\\safety\\" in path_lower and path_lower.endswith(
                        f"{name}.bat"
                    ):
                        logger.debug(f"Skipping Safety wrapper: {path}")
                        continue

                    return path

        logger.debug(
            f"No unwrapped command found on Windows, returning bare name: {name}"
        )
        return name

    fallback = shutil.which(name, path=get_path()) or name
    logger.debug(f"Using fallback (shutil.which or name): {fallback}")
    return fallback
