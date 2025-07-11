import unittest
from unittest.mock import patch

from safety.meta import get_user_agent, get_meta_http_headers


class TestMeta(unittest.TestCase):
    """Test cases for the meta module."""

    def test_get_user_agent_format(self):
        """Test that get_user_agent returns the expected format."""
        user_agent = get_user_agent()

        # Check that it starts with "safety-cli/"
        self.assertTrue(user_agent.startswith("safety-cli/"))

        # Check that it contains the OS and architecture in parentheses
        self.assertIn("(", user_agent)
        self.assertIn(")", user_agent)

        # Check that it contains Python version
        self.assertIn("Python/", user_agent)

    @patch("safety.meta.platform.system")
    @patch("safety.meta.platform.machine")
    @patch("safety.meta.platform.python_version")
    @patch("safety.meta.get_version")
    def test_get_user_agent_values(
        self, mock_get_version, mock_python_version, mock_machine, mock_system
    ):
        """Test get_user_agent with specific platform values."""
        # Test Linux x86_64
        mock_get_version.return_value = "3.0.1"
        mock_system.return_value = "Linux"
        mock_machine.return_value = "x86_64"
        mock_python_version.return_value = "3.10.0"

        user_agent = get_user_agent()
        self.assertEqual(user_agent, "safety-cli/3.0.1 (Linux x86_64; Python/3.10.0)")

        # Test macOS (Darwin) arm64
        mock_system.return_value = "Darwin"
        mock_machine.return_value = "arm64"

        user_agent = get_user_agent()
        self.assertEqual(user_agent, "safety-cli/3.0.1 (Darwin arm_64; Python/3.10.0)")

        # Test Windows AMD64
        mock_system.return_value = "Windows"
        mock_machine.return_value = "AMD64"

        user_agent = get_user_agent()
        self.assertEqual(user_agent, "safety-cli/3.0.1 (Windows x86_64; Python/3.10.0)")

        # Test unknown architecture
        mock_machine.return_value = "unknown_arch"

        user_agent = get_user_agent()
        self.assertEqual(
            user_agent, "safety-cli/3.0.1 (Windows unknown_arch; Python/3.10.0)"
        )

        # Test with no version
        mock_get_version.return_value = None

        user_agent = get_user_agent()
        self.assertEqual(
            user_agent, "safety-cli/unknown (Windows unknown_arch; Python/3.10.0)"
        )

    @patch("safety.meta.platform.machine")
    def test_get_user_agent_architecture_normalization(self, mock_machine):
        """Test that architecture names are properly normalized."""
        test_cases = [
            ("x86_64", "x86_64"),
            ("AMD64", "x86_64"),
            ("arm64", "arm_64"),
            ("aarch64", "arm_64"),
            ("i386", "x86"),
            ("custom_arch", "custom_arch"),
            ("", "unknown"),
            (None, "unknown"),
        ]

        for machine_value, expected_arch in test_cases:
            mock_machine.return_value = machine_value
            user_agent = get_user_agent()
            # Extract the architecture from the user agent string
            # Format: safety-cli/version (OS arch; Python/version)
            parts = user_agent.split(" ")
            arch = parts[2].rstrip(";")
            self.assertEqual(
                arch,
                expected_arch,
                f"Expected {expected_arch} for machine={machine_value}",
            )

    @patch("safety.meta.get_version")
    @patch("safety.meta.get_identifier")
    def test_get_meta_http_headers_includes_user_agent(
        self, mock_get_identifier, mock_get_version
    ):
        """Test that get_meta_http_headers includes User-Agent header."""
        mock_get_version.return_value = "3.0.1"
        mock_get_identifier.return_value = "safety_cli_pypi"

        headers = get_meta_http_headers()

        # Check that User-Agent is included
        self.assertIn("User-Agent", headers)

        # Check that it starts with "safety-cli/"
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

        # Check other headers are still present
        self.assertIn("Safetycli-Client-Version", headers)
        self.assertIn("Safetycli-Client-Id", headers)
        self.assertEqual(headers["Safetycli-Client-Version"], "3.0.1")
        self.assertEqual(headers["Safetycli-Client-Id"], "safety_cli_pypi")

    def test_get_meta_http_headers_complete(self):
        """Test that get_meta_http_headers returns all expected headers."""
        headers = get_meta_http_headers()

        # All required headers should be present
        required_headers = [
            "User-Agent",
            "Safetycli-Client-Version",
            "Safetycli-Client-Id",
        ]
        for header in required_headers:
            self.assertIn(header, headers, f"Missing required header: {header}")

        # Verify User-Agent format
        user_agent = headers["User-Agent"]
        self.assertTrue(user_agent.startswith("safety-cli/"))
        self.assertIn("Python/", user_agent)


if __name__ == "__main__":
    unittest.main()
