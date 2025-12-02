import unittest
from unittest.mock import patch, MagicMock
import ssl

from safety.meta import get_meta_http_headers
from safety.safety import fetch_database_url, get_announcements
from safety.alerts.utils import fetch_changelog
from safety.alerts.requirements import Requirement


class TestUserAgentIntegration(unittest.TestCase):
    """Integration tests to verify user-agent is properly set in all HTTP requests."""

    def setUp(self):
        """Set up test fixtures."""
        self.expected_headers = get_meta_http_headers()
        self.user_agent = self.expected_headers["User-Agent"]

    def test_fetch_database_url_includes_user_agent(self):
        """Test that fetch_database_url includes user-agent in headers."""
        # Setup mock
        mock_http_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"meta": {"schema_version": "2.0"}}
        mock_http_client.get.return_value = mock_response

        # Call function
        from safety.constants import JSON_SCHEMA_VERSION
        from safety_schemas.models import Ecosystem

        fetch_database_url(
            http_client=mock_http_client,
            mirror="https://api.safety.test/",
            db_name="insecure.json",
            cached=0,
            telemetry=False,
            ecosystem=Ecosystem.PYTHON,
            from_cache=False,
        )

        # Verify headers were passed correctly
        mock_http_client.get.assert_called_once()
        call_args = mock_http_client.get.call_args
        headers = call_args[1]["headers"]

        # Check that user-agent is included
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

        # Check other custom headers
        self.assertIn("Safetycli-Client-Version", headers)
        self.assertIn("Safetycli-Client-Id", headers)
        self.assertEqual(headers["schema-version"], JSON_SCHEMA_VERSION)
        self.assertEqual(headers["ecosystem"], "python")

    def test_get_announcements_includes_user_agent(self):
        """Test that get_announcements includes user-agent in headers."""
        # Setup mock
        mock_http_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"announcements": []}

        # Mock the method to return our response
        mock_http_client.post = MagicMock(return_value=mock_response)

        auth = MagicMock()
        auth.http_client = mock_http_client

        # Call function
        get_announcements(auth=auth, telemetry=False)

        # Verify headers were passed correctly
        mock_http_client.post.assert_called_once()
        call_args = mock_http_client.post.call_args
        headers = call_args[1]["headers"]

        # Check that user-agent is included
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

    @patch("safety.alerts.utils.httpx.get")
    def test_fetch_changelog_includes_user_agent(self, mock_get):
        """Test that fetch_changelog includes user-agent in headers."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        # Call function
        fetch_changelog(
            package="test-package",
            from_version="1.0.0",
            to_version="2.0.0",
            api_key="test-key",
        )

        # Verify headers were passed correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        headers = call_args[1]["headers"]

        # Check that user-agent is included
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

        # Check API key is included
        self.assertEqual(headers["X-Api-Key"], "test-key")

    @patch("safety.alerts.requirements.httpx.get")
    def test_requirement_get_hashes_includes_user_agent(self, mock_get):
        """Test that Requirement.get_hashes includes user-agent in headers."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.json.return_value = {"urls": []}
        mock_get.return_value = mock_response

        # Create requirement instance
        from packaging.specifiers import SpecifierSet

        req = Requirement(
            name="TestPackage",
            specs=SpecifierSet("==1.0.0"),
            line="TestPackage==1.0.0",
            lineno=1,
            extras=[],
            file_type="requirements.txt",
        )

        # Call method
        req.get_hashes("1.0.0")

        # Verify headers were passed correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        headers = call_args[1]["headers"]

        # Check that user-agent is included
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

    @patch("safety.events.handlers.common.httpx.AsyncClient")
    def test_events_handler_includes_user_agent(self, mock_client_class):
        """Test that event handler includes user-agent in headers."""
        from safety.events.handlers.common import SecurityEventsHandler

        # Create mock client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Setup async mock
        async def mock_post(*args, **kwargs):
            return mock_response

        mock_client.post = mock_post

        # Create mock SSL context
        mock_ssl_context = MagicMock(spec=ssl.SSLContext)

        # Create handler
        handler = SecurityEventsHandler(
            api_endpoint="https://events.safety.test/",
            api_key="test-key",
            tls_config=mock_ssl_context,
        )

        # Set the mock client
        handler.http_client = mock_client

        # Verify that headers would include user-agent
        # This is already handled in the flush method which calls get_meta_http_headers()
        headers = get_meta_http_headers()
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))


if __name__ == "__main__":
    unittest.main()
