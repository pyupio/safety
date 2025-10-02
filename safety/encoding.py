from pathlib import Path
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def detect_encoding(file_path: Path) -> str:
    """
    UTF-8 is the most common encoding standard, this is a simple
    way to improve the support for related Windows based files.

    Handles the most common cases efficiently.
    """
    try:
        with open(file_path, "rb") as f:
            # Read first 3 bytes for BOM detection
            bom = f.read(3)

        # Check most common Windows patterns first
        if bom[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return "utf-16"
        elif bom.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"

        return "utf-8"
    except Exception:
        logger.exception("Error detecting encoding")
        return "utf-8"


def safe_read_file(file_path: Path, ignore_errors: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    Safely reads a file with multiple encoding fallbacks.

    Args:
        file_path (Path): The path to the file to read.
        ignore_errors (bool): If True, returns None on error instead of raising.

    Returns:
        Tuple[Optional[str], Optional[str]]: A tuple of (content, error_message).
            - If successful: (content, None)
            - If failed and ignore_errors=True: (None, error_message)
            - If failed and ignore_errors=False: raises exception

    Raises:
        UnicodeDecodeError: If the file cannot be decoded and ignore_errors is False.
        IOError: If the file cannot be read and ignore_errors is False.
    """
    # Try encodings in order of likelihood
    encodings = [
        detect_encoding(file_path),
        "utf-8",
        "latin-1",  # Accepts any byte sequence
        "cp1252",   # Windows encoding
        "iso-8859-1",
    ]

    last_error = None

    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding, errors="strict") as f:
                content = f.read()
                return (content, None)
        except UnicodeDecodeError as e:
            last_error = f"UnicodeDecodeError with {encoding}: {str(e)}"
            logger.debug(f"Failed to read {file_path} with encoding {encoding}: {e}")
            continue
        except Exception as e:
            last_error = f"Error reading file: {str(e)}"
            logger.debug(f"Error reading {file_path} with encoding {encoding}: {e}")
            continue

    # All encodings failed
    error_msg = f"Unable to read file {file_path}: {last_error}"

    if ignore_errors:
        logger.warning(error_msg)
        return (None, error_msg)
    else:
        logger.error(error_msg)
        raise UnicodeDecodeError("utf-8", b"", 0, 1, last_error or "All encodings failed")
