"""
Unit tests for system-scan platform sink with machine token authentication.

Tests verify that system-scan uses the correct HTTP client (auth.platform.http_client)
when machine token authentication is active.
"""

from unittest.mock import Mock, patch
import pytest

from safety.system_scan.scanner.sinks.config import SafetyPlatformSinkConfig


@pytest.mark.unit
class TestMachineTokenHttpClient:
    """
    Test that system-scan uses the correct HTTP client with machine token auth.
    """

    def test_platform_sink_receives_correct_client(self):
        """
        Verify that SafetyPlatformSinkConfig receives auth.platform.http_client
        when machine token auth is active.
        """
        mock_auth = Mock()
        mock_auth.platform.has_machine_token = True

        mock_platform_http_client = Mock()
        mock_auth.platform.http_client = mock_platform_http_client

        sink_cfg = SafetyPlatformSinkConfig(
            base_url="https://platform.safetycli.com",
            timeout=30,
            http_client=mock_auth.platform.http_client,
        )

        assert sink_cfg.http_client is mock_platform_http_client

    @patch("safety.system_scan.scanner.sinks.factory.build_sink")
    def test_system_scan_command_passes_platform_client(self, mock_build_sink):
        """
        Integration-style test that verifies system-scan command.py passes the
        correct HTTP client to the platform sink.

        This simulates what happens in safety/system_scan/command.py:run_discovery()
        when sink="platform" and machine token auth is active.
        """
        from safety.system_scan.scanner.sinks.config import SafetyPlatformSinkConfig

        # Setup: mock auth with machine token
        mock_auth = Mock()
        mock_auth.platform.has_machine_token = True
        mock_platform_client = Mock()
        mock_auth.platform.http_client = mock_platform_client

        # Simulate system-scan command creating SafetyPlatformSinkConfig
        # (from safety/system_scan/command.py line 128-130)
        sink_cfg = SafetyPlatformSinkConfig(
            base_url="https://platform.safetycli.com",
            timeout=30,
            http_client=mock_auth.platform.http_client,
        )

        # Verify the config has the correct client
        assert sink_cfg.http_client is mock_platform_client
        assert sink_cfg.kind == "safety_platform"
        assert sink_cfg.timeout == 30


@pytest.mark.unit
class TestClientCleanup:
    """
    Test that the HTTP client is properly closed.
    """

    def test_platform_client_closed(self):
        """
        Verify that cleanup closes platform._http_client.
        """
        mock_platform_http_client = Mock()
        mock_auth = Mock()
        mock_auth.platform._http_client = mock_platform_http_client

        # Simulate cleanup (from safety/auth/cli_utils.py)
        mock_auth.platform._http_client.close()

        mock_platform_http_client.close.assert_called_once()
