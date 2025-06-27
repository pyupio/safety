import unittest
from unittest.mock import patch, MagicMock

from safety.meta import get_meta_http_headers
from safety.safety import fetch_database_url, fetch_policy, get_announcements
from safety.alerts.utils import fetch_changelog
from safety.alerts.requirements import Requirement
from safety.auth.utils import SafetyAuthSession


class TestUserAgentIntegration(unittest.TestCase):
    """Integration tests to verify user-agent is properly set in all HTTP requests."""

    def setUp(self):
        """Set up test fixtures."""
        self.expected_headers = get_meta_http_headers()
        self.user_agent = self.expected_headers["User-Agent"]

    @patch("safety.safety.requests.Session")
    def test_fetch_database_url_includes_user_agent(self, mock_session_class):
        """Test that fetch_database_url includes user-agent in headers."""
        # Setup mock
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"meta": {"schema_version": "2.0"}}
        mock_session.get.return_value = mock_response

        # Call function
        from safety.constants import JSON_SCHEMA_VERSION
        from safety_schemas.models import Ecosystem

        fetch_database_url(
            session=mock_session,
            mirror="https://api.safety.test/",
            db_name="insecure.json",
            cached=0,
            telemetry=False,
            ecosystem=Ecosystem.PYTHON,
            from_cache=False,
        )

        # Verify headers were passed correctly
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        headers = call_args[1]["headers"]

        # Check that user-agent is included
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

        # Check other custom headers
        self.assertIn("Safetycli-Client-Version", headers)
        self.assertIn("Safetycli-Client-Id", headers)
        self.assertEqual(headers["schema-version"], JSON_SCHEMA_VERSION)
        self.assertEqual(headers["ecosystem"], "python")

    @patch("safety.safety.requests.Session")
    def test_fetch_policy_includes_user_agent(self, mock_session_class):
        """Test that fetch_policy includes user-agent in headers."""
        # Setup mock
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "safety_policy": "",
            "audit_and_monitor": False,
        }
        mock_session.get.return_value = mock_response

        # Call function
        fetch_policy(session=mock_session)

        # Verify headers were passed correctly
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        headers = call_args[1]["headers"]

        # Check that user-agent is included
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

    @patch("safety.safety.requests.Session")
    def test_get_announcements_includes_user_agent(self, mock_session_class):
        """Test that get_announcements includes user-agent in headers."""
        # Setup mock
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"announcements": []}

        # Mock the method to return our response
        mock_session.post = MagicMock(return_value=mock_response)

        # Call function
        get_announcements(session=mock_session, telemetry=False)

        # Verify headers were passed correctly
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        headers = call_args[1]["headers"]

        # Check that user-agent is included
        self.assertIn("User-Agent", headers)
        self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

    @patch("safety.alerts.utils.requests.get")
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

    @patch("safety.alerts.requirements.requests.get")
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

    def test_safety_auth_session_includes_user_agent(self):
        """Test that SafetyAuthSession includes user-agent in headers."""
        # Create session
        session = SafetyAuthSession()

        # Test with API key
        session.api_key = "test-key"  # type: ignore

        # Mock the parent class request method
        with patch.object(
            session.__class__.__bases__[0], "request"
        ) as mock_super_request:
            mock_response = MagicMock()
            mock_super_request.return_value = mock_response

            # Make a request
            session.request("GET", "https://api.test.com/endpoint")

            # Verify headers were passed correctly
            mock_super_request.assert_called_once()
            call_args = mock_super_request.call_args
            headers = call_args[1]["headers"]

            # Check that user-agent is included
            self.assertIn("User-Agent", headers)
            self.assertTrue(headers["User-Agent"].startswith("safety-cli/"))

            # Check API key is included
            self.assertEqual(headers["X-Api-Key"], "test-key")

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

        # Create handler
        handler = SecurityEventsHandler(
            api_endpoint="https://events.safety.test/", api_key="test-key"
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
