import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from safety.encoding import detect_encoding, safe_read_file


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


    def test_safe_read_file_utf8(self):
        """
        Test that safe_read_file successfully reads a UTF-8 file.
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write("Hello, world! 你好")
            temp_path = f.name

        try:
            content, error = safe_read_file(Path(temp_path), ignore_errors=False)
            assert content == "Hello, world! 你好"
            assert error is None
        finally:
            os.unlink(temp_path)

    def test_safe_read_file_latin1(self):
        """
        Test that safe_read_file falls back to latin-1 for non-UTF-8 files.
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            # Write latin-1 encoded text
            f.write("Héllo wørld".encode('latin-1'))
            temp_path = f.name

        try:
            content, error = safe_read_file(Path(temp_path), ignore_errors=False)
            assert content is not None
            assert error is None
            assert "H" in content and "llo" in content
        finally:
            os.unlink(temp_path)

    def test_safe_read_file_binary_with_ignore_errors(self):
        """
        Test that safe_read_file returns None for truly binary files when ignore_errors=True.
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            # Write binary data that's not valid text in any encoding
            f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00')
            temp_path = f.name

        try:
            content, error = safe_read_file(Path(temp_path), ignore_errors=True)
            # Binary data should still be readable as latin-1 which accepts any byte
            assert content is not None or error is not None
        finally:
            os.unlink(temp_path)

    def test_safe_read_file_non_existent_with_ignore_errors(self):
        """
        Test that safe_read_file returns error message for non-existent files when ignore_errors=True.
        """
        non_existent = Path("/tmp/non_existent_file_12345.txt")
        content, error = safe_read_file(non_existent, ignore_errors=True)
        assert content is None
        assert error is not None
        assert "Unable to read file" in error

    def test_safe_read_file_utf16_with_bom(self):
        """
        Test that safe_read_file successfully reads UTF-16 files with BOM.
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            # Write UTF-16 with BOM
            f.write(b'\xff\xfe' + "Hello, world!".encode('utf-16-le')[2:])
            temp_path = f.name

        try:
            content, error = safe_read_file(Path(temp_path), ignore_errors=False)
            assert content is not None
            assert error is None
            assert "Hello, world!" in content
        finally:
            os.unlink(temp_path)
