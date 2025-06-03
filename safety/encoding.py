from pathlib import Path
import logging

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
