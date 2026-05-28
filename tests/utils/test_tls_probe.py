"""Unit tests for safety.utils.tls_probe."""

import ssl
from unittest.mock import MagicMock, patch

import httpx
import pytest

from safety.errors import SSLCertificateError
from safety.utils.tls_probe import (
    TLSProbeResult,
    with_tls_fallback,
    probe_tls_connectivity,
    _do_tls_probe,
    _save_tls_fallback_preference,
)


def _make_tls_config(mode: str = "default"):
    """Create a minimal TLSConfig-like object for testing."""
    tls = MagicMock()
    tls.verify_context = ssl.create_default_context()
    tls.mode = mode
    return tls


def _make_proxy_config():
    """Create a minimal ProxyConfig-like object for testing."""
    proxy = MagicMock()
    proxy.endpoint.as_url.return_value = "http://proxy.test:8080"
    return proxy


PROBE_URL = "https://auth.example.com/.well-known/openid-configuration"


@pytest.mark.unit
class TestDoTlsProbe:
    """Tests for the low-level _do_tls_probe helper."""

    @patch("safety.utils.tls_probe.httpx.Client")
    def test_successful_probe(self, mock_client_cls):
        """Any HTTP response means TLS succeeded."""
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.head.return_value = MagicMock(status_code=200)

        tls = _make_tls_config()
        # Should not raise
        _do_tls_probe(PROBE_URL, tls, proxy_config=None, timeout=10.0)
        mock_client.head.assert_called_once_with(PROBE_URL)

    @patch("safety.utils.tls_probe.httpx.Client")
    def test_404_response_still_succeeds(self, mock_client_cls):
        """Even 4xx/5xx means TLS handshake worked."""
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.head.return_value = MagicMock(status_code=404)

        tls = _make_tls_config()
        _do_tls_probe(PROBE_URL, tls, proxy_config=None, timeout=10.0)

    @patch("safety.utils.tls_probe.httpx.Client")
    def test_ssl_error_raises_ssl_certificate_error(self, mock_client_cls):
        """Certificate errors are converted to SSLCertificateError."""
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.head.side_effect = httpx.ConnectError("certificate_verify_failed")

        tls = _make_tls_config()
        with pytest.raises(SSLCertificateError):
            _do_tls_probe(PROBE_URL, tls, proxy_config=None, timeout=10.0)

    @patch("safety.utils.tls_probe.httpx.Client")
    def test_non_ssl_connect_error_propagates(self, mock_client_cls):
        """Non-TLS connect errors propagate as-is (DNS, refused, etc)."""
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.head.side_effect = httpx.ConnectError("connection refused")

        tls = _make_tls_config()
        with pytest.raises(httpx.ConnectError, match="connection refused"):
            _do_tls_probe(PROBE_URL, tls, proxy_config=None, timeout=10.0)

    @patch("safety.utils.tls_probe.httpx.Client")
    def test_proxy_config_forwarded(self, mock_client_cls):
        """Proxy config should be forwarded to the httpx.Client."""
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.head.return_value = MagicMock(status_code=200)

        tls = _make_tls_config()
        proxy = _make_proxy_config()
        _do_tls_probe(PROBE_URL, tls, proxy_config=proxy, timeout=5.0)

        call_kwargs = mock_client_cls.call_args.kwargs
        assert call_kwargs["proxy"] == "http://proxy.test:8080"


@pytest.mark.unit
class TestWithTlsFallback:
    """Tests for the shared with_tls_fallback orchestrator."""

    def test_success_returns_original_config(self):
        """Successful action returns original config with fell_back=False."""
        tls = _make_tls_config("default")
        action = MagicMock()

        result = with_tls_fallback(action=action, tls_config=tls)

        assert isinstance(result, TLSProbeResult)
        assert result.tls_config is tls
        assert result.fell_back is False
        action.assert_called_once_with(tls)

    @patch("safety.utils.tls_probe._save_tls_fallback_preference")
    @patch("safety.utils.tls_probe.get_tls_config")
    def test_ssl_error_default_mode_falls_back_to_system(self, mock_get_tls, mock_save):
        """SSL error with mode=default should retry action with system trust store."""
        tls_default = _make_tls_config("default")
        tls_system = _make_tls_config("system")
        mock_get_tls.return_value = tls_system

        action = MagicMock(side_effect=[SSLCertificateError(), None])

        result = with_tls_fallback(
            action=action, tls_config=tls_default, save_preference=True
        )

        assert result.tls_config is tls_system
        assert result.fell_back is True
        assert action.call_count == 2
        action.assert_any_call(tls_default)
        action.assert_any_call(tls_system)
        mock_save.assert_called_once()

    def test_ssl_error_non_default_mode_raises_immediately(self):
        """SSL error with mode != 'default' should raise without fallback."""
        tls = _make_tls_config("system")
        action = MagicMock(side_effect=SSLCertificateError())

        with pytest.raises(SSLCertificateError):
            with_tls_fallback(action=action, tls_config=tls)

        action.assert_called_once()

    @patch("safety.utils.tls_probe.get_tls_config")
    def test_both_attempts_fail_raises(self, mock_get_tls):
        """If both default and system TLS fail, SSLCertificateError is raised."""
        tls_default = _make_tls_config("default")
        mock_get_tls.return_value = _make_tls_config("system")

        action = MagicMock(side_effect=[SSLCertificateError(), SSLCertificateError()])

        with pytest.raises(
            SSLCertificateError, match="TLS probe failed: primary=.*fallback="
        ):
            with_tls_fallback(action=action, tls_config=tls_default)

    @patch("safety.utils.tls_probe.get_tls_config")
    def test_both_attempts_fail_preserves_error_details(self, mock_get_tls):
        """Raised exception message should contain both primary and fallback error details."""
        tls_default = _make_tls_config("default")
        mock_get_tls.return_value = _make_tls_config("system")

        primary_err = SSLCertificateError("certifi CA bundle expired")
        fallback_err = SSLCertificateError("system store missing root CA")
        action = MagicMock(side_effect=[primary_err, fallback_err])

        with pytest.raises(SSLCertificateError) as exc_info:
            with_tls_fallback(action=action, tls_config=tls_default)

        msg = str(exc_info.value)
        assert "certifi CA bundle expired" in msg
        assert "system store missing root CA" in msg
        # __cause__ is chained from the primary (first) error
        assert exc_info.value.__cause__ is primary_err

    @patch("safety.utils.tls_probe._save_tls_fallback_preference")
    @patch("safety.utils.tls_probe.get_tls_config")
    def test_save_preference_false_skips_persistence(self, mock_get_tls, mock_save):
        """save_preference=False should not persist fallback to config."""
        tls_default = _make_tls_config("default")
        mock_get_tls.return_value = _make_tls_config("system")
        action = MagicMock(side_effect=[SSLCertificateError(), None])

        result = with_tls_fallback(
            action=action, tls_config=tls_default, save_preference=False
        )

        assert result.fell_back is True
        mock_save.assert_not_called()

    def test_non_tls_error_propagates(self):
        """Non-TLS errors should propagate as-is without fallback."""
        tls = _make_tls_config("default")
        action = MagicMock(side_effect=httpx.ConnectError("DNS resolution failed"))

        with pytest.raises(httpx.ConnectError, match="DNS resolution failed"):
            with_tls_fallback(action=action, tls_config=tls)

        action.assert_called_once()

    @patch("safety.utils.tls_probe._save_tls_fallback_preference")
    @patch("safety.utils.tls_probe.get_tls_config")
    def test_callback_receives_correct_tls_configs(self, mock_get_tls, mock_save):
        """Verify the callback receives the original config first, then system config."""
        tls_default = _make_tls_config("default")
        tls_system = _make_tls_config("system")
        mock_get_tls.return_value = tls_system

        received_configs = []

        def capture_action(tls):
            received_configs.append(tls)
            if len(received_configs) == 1:
                raise SSLCertificateError()

        with_tls_fallback(action=capture_action, tls_config=tls_default)

        assert received_configs[0] is tls_default
        assert received_configs[1] is tls_system


@pytest.mark.unit
class TestProbeTlsConnectivity:
    """Tests for the public probe_tls_connectivity function."""

    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_probe_success_returns_original_config(self, mock_probe):
        """Successful probe returns original config with fell_back=False."""
        tls = _make_tls_config("default")
        result = probe_tls_connectivity(
            probe_url=PROBE_URL,
            tls_config=tls,
            save_preference=False,
        )

        assert isinstance(result, TLSProbeResult)
        assert result.tls_config is tls
        assert result.fell_back is False
        mock_probe.assert_called_once()

    @patch("safety.utils.tls_probe._save_tls_fallback_preference")
    @patch("safety.utils.tls_probe.get_tls_config")
    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_probe_ssl_error_default_mode_falls_back_to_system(
        self, mock_probe, mock_get_tls, mock_save
    ):
        """SSL error with mode=default should retry with system trust store."""
        tls_default = _make_tls_config("default")
        tls_system = _make_tls_config("system")
        mock_get_tls.return_value = tls_system

        # First call fails with SSLCertificateError, second succeeds
        mock_probe.side_effect = [SSLCertificateError(), None]

        result = probe_tls_connectivity(
            probe_url=PROBE_URL,
            tls_config=tls_default,
            save_preference=True,
        )

        assert result.tls_config is tls_system
        assert result.fell_back is True
        assert mock_probe.call_count == 2
        mock_get_tls.assert_called_once_with(mode="system")
        mock_save.assert_called_once()

    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_probe_ssl_error_system_mode_raises_immediately(self, mock_probe):
        """SSL error with mode=system should raise immediately (no fallback)."""
        tls = _make_tls_config("system")
        mock_probe.side_effect = SSLCertificateError()

        with pytest.raises(SSLCertificateError):
            probe_tls_connectivity(
                probe_url=PROBE_URL,
                tls_config=tls,
            )

        # Only one attempt — no fallback
        mock_probe.assert_called_once()

    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_probe_ssl_error_bundle_mode_raises_immediately(self, mock_probe):
        """SSL error with mode=bundle should raise immediately (no fallback)."""
        tls = _make_tls_config("bundle")
        mock_probe.side_effect = SSLCertificateError()

        with pytest.raises(SSLCertificateError):
            probe_tls_connectivity(
                probe_url=PROBE_URL,
                tls_config=tls,
            )

        mock_probe.assert_called_once()

    @patch("safety.utils.tls_probe.get_tls_config")
    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_fallback_failure_raises(self, mock_probe, mock_get_tls):
        """If both default and system TLS fail, SSLCertificateError is raised."""
        tls_default = _make_tls_config("default")
        tls_system = _make_tls_config("system")
        mock_get_tls.return_value = tls_system

        # Both attempts fail
        mock_probe.side_effect = [SSLCertificateError(), SSLCertificateError()]

        with pytest.raises(
            SSLCertificateError, match="TLS probe failed: primary=.*fallback="
        ):
            probe_tls_connectivity(
                probe_url=PROBE_URL,
                tls_config=tls_default,
            )

    @patch("safety.utils.tls_probe._save_tls_fallback_preference")
    @patch("safety.utils.tls_probe.get_tls_config")
    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_save_preference_false_skips_persistence(
        self, mock_probe, mock_get_tls, mock_save
    ):
        """save_preference=False should not persist fallback to config."""
        tls_default = _make_tls_config("default")
        tls_system = _make_tls_config("system")
        mock_get_tls.return_value = tls_system
        mock_probe.side_effect = [SSLCertificateError(), None]

        result = probe_tls_connectivity(
            probe_url=PROBE_URL,
            tls_config=tls_default,
            save_preference=False,
        )

        assert result.fell_back is True
        mock_save.assert_not_called()

    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_non_tls_error_propagates(self, mock_probe):
        """Non-TLS errors (DNS, timeout) should propagate as-is."""
        tls = _make_tls_config("default")
        mock_probe.side_effect = httpx.ConnectError("DNS resolution failed")

        with pytest.raises(httpx.ConnectError, match="DNS resolution failed"):
            probe_tls_connectivity(
                probe_url=PROBE_URL,
                tls_config=tls,
            )

    @patch("safety.utils.tls_probe._do_tls_probe")
    def test_proxy_config_forwarded_to_probe(self, mock_probe):
        """Proxy config should be forwarded through to the probe."""
        tls = _make_tls_config()
        proxy = _make_proxy_config()

        probe_tls_connectivity(
            probe_url=PROBE_URL,
            tls_config=tls,
            proxy_config=proxy,
        )

        call_kwargs = mock_probe.call_args
        assert call_kwargs[0][2] is proxy  # positional arg: proxy_config


@pytest.mark.unit
class TestSaveTlsFallbackPreference:
    """Tests for _save_tls_fallback_preference."""

    def test_save_preference_persists_to_config(self, tmp_path):
        """Successful save writes mode=system to config.ini."""
        config_file = tmp_path / "config.ini"

        with patch("safety.utils.tls_probe.CONFIG", config_file):
            _save_tls_fallback_preference()

        content = config_file.read_text()
        assert "mode = system" in content

    def test_save_preference_preserves_existing_sections(self, tmp_path):
        """Writing TLS preference must not clobber pre-existing config sections."""
        config_file = tmp_path / "config.ini"

        # Seed config.ini with an existing [auth] section
        from configparser import ConfigParser

        existing = ConfigParser()
        existing.add_section("auth")
        existing.set("auth", "org", "my-org")
        existing.set("auth", "token", "abc123")
        with open(config_file, "w") as f:
            existing.write(f)

        with patch("safety.utils.tls_probe.CONFIG", config_file):
            _save_tls_fallback_preference()

        # Re-read and verify both sections survived
        result = ConfigParser()
        result.read(config_file)

        # New TLS section is present
        assert result.has_section("tls")
        assert result.get("tls", "mode") == "system"

        # Pre-existing auth section is intact
        assert result.has_section("auth")
        assert result.get("auth", "org") == "my-org"
        assert result.get("auth", "token") == "abc123"
