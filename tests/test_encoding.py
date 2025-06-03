import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from safety.encoding import detect_encoding


class TestDetectEncoding:
    """
    Tests for the detect_encoding function.
    """

    def test_utf16_le_detection(self):
        """
        Test that UTF-16 LE (Little Endian) encoding is correctly detected.
        """
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # UTF-16 LE BOM: \xff\xfe
            f.write(b"\xff\xfe" + "Hello, world!".encode("utf-16-le")[2:])

        try:
            encoding = detect_encoding(Path(f.name))
            assert encoding == "utf-16"
        finally:
            os.unlink(f.name)

    def test_utf16_be_detection(self):
        """
        Test that UTF-16 BE (Big Endian) encoding is correctly detected.
        """
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # UTF-16 BE BOM: \xfe\xff
            f.write(b"\xfe\xff" + "Hello, world!".encode("utf-16-be")[2:])

        try:
            encoding = detect_encoding(Path(f.name))
            assert encoding == "utf-16"
        finally:
            os.unlink(f.name)

    def test_utf8_sig_detection(self):
        """
        Test that UTF-8 with signature (BOM) is correctly detected.
        """
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # UTF-8 with signature BOM: \xef\xbb\xbf
            f.write(b"\xef\xbb\xbf" + "Hello, world!".encode("utf-8"))

        try:
            encoding = detect_encoding(Path(f.name))
            assert encoding == "utf-8-sig"
        finally:
            os.unlink(f.name)

    def test_utf8_detection(self):
        """
        Test that regular UTF-8 (without BOM) is correctly detected.
        """
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Regular UTF-8 (no BOM)
            f.write("Hello, world!".encode("utf-8"))

        try:
            encoding = detect_encoding(Path(f.name))
            assert encoding == "utf-8"
        finally:
            os.unlink(f.name)

    def test_error_handling(self):
        """
        Test that errors are properly handled and default encoding is returned.
        """
        # Test with a non-existent file
        non_existent_file = Path("non_existent_file.txt")

        encoding = detect_encoding(non_existent_file)
        assert encoding == "utf-8"

    def test_exception_logging(self):
        """
        Test that exceptions are properly logged.
        """
        non_existent_file = Path("non_existent_file.txt")

        with patch("safety.encoding.logger") as mock_logger:
            encoding = detect_encoding(non_existent_file)

            assert encoding == "utf-8"
            mock_logger.exception.assert_called_once_with("Error detecting encoding")
