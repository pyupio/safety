"""
Integration tests for safety/config/ module

These tests verify that proxy and TLS configurations work together correctly
and test the public API exported by config.
"""

import pytest
import os
import ssl
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import Optional

# Test the public API imports
from safety.config import get_proxy_config, get_tls_config
from safety.config.proxy import ProxyConfig
from safety.config.tls import TLSConfig


@pytest.fixture
def integrated_config_factory(tmp_path: Path):
    """
    Factory fixture to create config.ini files with both proxy and TLS sections.
    """

    def _create_config(
        proxy_section: Optional[dict[str, str]] = None,
        tls_section: Optional[dict[str, str]] = None,
    ) -> Path:
        config_content = []

        if proxy_section:
            config_content.append("[proxy]")
            for key, value in proxy_section.items():
                config_content.append(f"{key} = {value}")
            config_content.append("")

        if tls_section:
            config_content.append("[tls]")
            for key, value in tls_section.items():
                config_content.append(f"{key} = {value}")
            config_content.append("")

        config_path = tmp_path / "config.ini"
        config_path.write_text("\n".join(config_content))
        return config_path

    return _create_config


# ─────────────────────────────────────────────────────────────────────────────
# Public API Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestConfigModulePublicAPI:
    """
    Test that the config module exposes the correct public API.
    """

    def test_public_api_not_accidentally_changed(self):
        """
        Catch accidental API changes.
        """
        from safety.config import __all__

        # This is the contract - update intentionally if API changes
        assert set(__all__) == {
            "get_proxy_config",
            "get_tls_config",
            "AuthConfig",
            "MachineCredentialConfig",
            "AUTH_CONFIG_USER",
        }


class TestConfigFileIntegration:
    """
    Test that both proxy and TLS configs can be read from the same file.
    """

    def test_both_configs_from_same_file(self, integrated_config_factory) -> None:
        """
        Test reading both proxy and TLS config from the same config file.
        """
        config_file = integrated_config_factory(
            proxy_section={
                "host": "proxy.example.com",
                "port": "8080",
                "protocol": "https",
            },
            tls_section={
                "mode": "system",
            },
        )

        # Test proxy config
        proxy_result = get_proxy_config(config_path=config_file)
        assert proxy_result is not None
        assert isinstance(proxy_result, ProxyConfig)
        assert proxy_result.endpoint.host == "proxy.example.com"
        assert proxy_result.endpoint.port == 8080
        assert proxy_result.endpoint.scheme == "https"

        # Test TLS config
        with patch("safety.config.tls.get_system_tls_context") as mock_context:
            mock_ssl_context = MagicMock()
            mock_context.return_value = mock_ssl_context

            tls_result = get_tls_config(config_path=config_file)
            assert tls_result.verify_context == mock_ssl_context

    def test_partial_config_sections(self, integrated_config_factory) -> None:
        """
        Test when config file has only one of the sections.
        """
        # Only proxy section
        proxy_only_config = integrated_config_factory(
            proxy_section={"host": "proxy.test.com"}, tls_section=None
        )

        proxy_result = get_proxy_config(config_path=proxy_only_config)
        assert proxy_result is not None
        assert proxy_result.endpoint.host == "proxy.test.com"

        # TLS should fall back to default
        with patch("safety.config.tls.certifi.where") as mock_certifi:
            with patch("ssl.create_default_context") as mock_ssl_context:
                mock_certifi.return_value = "/default/certifi.pem"
                mock_context = MagicMock(spec=ssl.SSLContext)
                mock_ssl_context.return_value = mock_context
                tls_result = get_tls_config(config_path=proxy_only_config)
                assert tls_result.verify_context == mock_context

    def test_empty_config_file(self, tmp_path: Path) -> None:
        """
        Test behavior with empty config file.
        """
        empty_config = tmp_path / "empty.ini"
        empty_config.write_text("")

        # Both should return defaults/None
        proxy_result = get_proxy_config(config_path=empty_config)
        assert proxy_result is None

        with patch("safety.config.tls.certifi.where") as mock_certifi:
            with patch("ssl.create_default_context") as mock_ssl_context:
                mock_certifi.return_value = "/default/certifi.pem"
                mock_context = MagicMock(spec=ssl.SSLContext)
                mock_ssl_context.return_value = mock_context
                tls_result = get_tls_config(config_path=empty_config)
                assert tls_result.verify_context == mock_context


class TestMixedSourcesIntegration:
    """
    Test configurations from mixed sources (CLI, env, config).
    """

    def test_cli_overrides_for_both(self, integrated_config_factory) -> None:
        """
        Test that CLI options take precedence for both proxy and TLS.
        """
        config_file = integrated_config_factory(
            proxy_section={"host": "config.proxy.com", "port": "8080"},
            tls_section={"mode": "default"},
        )

        # CLI should override config for both
        proxy_result = get_proxy_config(
            host="cli.proxy.com", port="9090", config_path=config_file
        )
        assert proxy_result is not None
        assert proxy_result.endpoint.host == "cli.proxy.com"
        assert proxy_result.endpoint.port == 9090

        with patch("safety.config.tls._build_tls_config") as mock_build:
            mock_config = MagicMock(spec=TLSConfig)
            mock_config.verify_context = "system_context"
            mock_build.return_value = mock_config

            tls_result = get_tls_config(mode="system", config_path=config_file)
            assert tls_result.verify_context == "system_context"

    def test_independent_source_resolution(self, integrated_config_factory) -> None:
        """
        Test that proxy and TLS resolve from different sources independently.
        """
        config_file = integrated_config_factory(
            proxy_section={"host": "config.proxy.com"}, tls_section={"mode": "default"}
        )

        # Proxy from CLI, TLS from config
        proxy_result = get_proxy_config(host="cli.proxy.com", config_path=config_file)
        assert proxy_result is not None
        assert proxy_result.endpoint.host == "cli.proxy.com"

        with patch("safety.config.tls.certifi.where") as mock_certifi:
            with patch("ssl.create_default_context") as mock_ssl_context:
                mock_certifi.return_value = "/config/certifi.pem"
                mock_context = MagicMock(spec=ssl.SSLContext)
                mock_ssl_context.return_value = mock_context

                tls_result = get_tls_config(config_path=config_file)
                assert tls_result.verify_context == mock_context

    def test_env_vs_config_precedence(self, integrated_config_factory) -> None:
        """
        Test environment variables vs config file precedence.
        """
        config_file = integrated_config_factory(
            proxy_section={"host": "config.proxy.com"}, tls_section={"mode": "default"}
        )

        # TLS from environment should override config
        env_vars = {"SAFETY_TLS_MODE": "system"}

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("safety.config.tls.get_system_tls_context") as mock_context:
                mock_ssl_context = MagicMock()
                mock_context.return_value = mock_ssl_context

                # Proxy should still come from config (no env vars for proxy)
                proxy_result = get_proxy_config(config_path=config_file)
                assert proxy_result is not None
                assert proxy_result.endpoint.host == "config.proxy.com"

                # TLS should come from environment
                tls_result = get_tls_config(config_path=config_file)
                assert tls_result.verify_context == mock_ssl_context


class TestFullIntegrationScenarios:
    """
    Test complete real-world scenarios.
    """

    @patch("ssl.create_default_context")
    def test_corporate_proxy_with_custom_ca(
        self, mock_ssl_context, integrated_config_factory, tmp_path: Path
    ) -> None:
        """
        Test a typical corporate setup with proxy and custom CA bundle.
        """
        # Create a mock CA bundle file
        ca_bundle = tmp_path / "corporate-ca.crt"
        ca_bundle.write_text(
            "-----BEGIN CERTIFICATE-----\nCorporateMockCert\n-----END CERTIFICATE-----"
        )

        # Mock the SSL context creation to avoid parsing the fake certificate
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_ssl_context.return_value = mock_context

        config_file = integrated_config_factory(
            proxy_section={
                "host": "corporate.proxy.com",
                "port": "8080",
                "protocol": "https",
            },
            tls_section={
                "mode": "bundle",
                "ca_bundle": str(ca_bundle),
            },
        )

        # Get both configurations
        proxy_result = get_proxy_config(config_path=config_file)
        tls_result = get_tls_config(config_path=config_file)

        # Verify proxy config
        assert proxy_result is not None
        assert proxy_result.endpoint.host == "corporate.proxy.com"
        assert proxy_result.endpoint.port == 8080
        assert proxy_result.endpoint.scheme == "https"

        # Verify TLS config
        assert tls_result.verify_context == mock_context
        mock_ssl_context.assert_called_once_with(cafile=ca_bundle.resolve())

    def test_mixed_environment_and_cli(self, integrated_config_factory) -> None:
        """
        Test environment variables for TLS and CLI for proxy.
        """
        config_file = integrated_config_factory(
            proxy_section={"host": "config.proxy.com"}, tls_section={"mode": "default"}
        )

        # Set TLS via environment
        env_vars = {"SAFETY_TLS_MODE": "system"}

        with patch.dict(os.environ, env_vars, clear=False):
            with patch("safety.config.tls.get_system_tls_context") as mock_context:
                mock_ssl_context = MagicMock()
                mock_context.return_value = mock_ssl_context

                # Proxy from CLI
                proxy_result = get_proxy_config(
                    host="cli.proxy.com", config_path=config_file
                )

                # TLS from environment
                tls_result = get_tls_config(config_path=config_file)

                assert proxy_result is not None
                assert proxy_result.endpoint.host == "cli.proxy.com"
                assert tls_result.verify_context == mock_ssl_context

    def test_error_handling_integration(
        self, integrated_config_factory, tmp_path: Path
    ) -> None:
        """
        Test that errors in one config don't affect the other.
        """
        # Create invalid CA bundle path
        config_file = integrated_config_factory(
            proxy_section={"host": "valid.proxy.com"},
            tls_section={
                "mode": "bundle",
                "ca_bundle": "/nonexistent/path.crt",  # Invalid path
            },
        )

        # Proxy should work fine
        proxy_result = get_proxy_config(config_path=config_file)
        assert proxy_result is not None
        assert proxy_result.endpoint.host == "valid.proxy.com"

        # TLS should raise an error
        with pytest.raises(ValueError, match="does not exist"):
            get_tls_config(config_path=config_file)

    def test_logging_integration(self, integrated_config_factory, caplog) -> None:
        """
        Test that both configurations log their resolution appropriately.
        """
        import logging

        caplog.set_level(logging.INFO)

        config_file = integrated_config_factory(
            proxy_section={"host": "logged.proxy.com"}, tls_section={"mode": "system"}
        )

        with patch("safety.utils.tls.get_system_tls_context") as mock_context:
            mock_context.return_value = MagicMock()

            # Get both configs
            proxy_result = get_proxy_config(config_path=config_file)
            tls_result = get_tls_config(config_path=config_file)

            assert proxy_result is not None
            assert tls_result is not None

            # Should have logs from both subsystems
            log_messages = [record.message for record in caplog.records]
            assert any("proxy" in msg.lower() for msg in log_messages)
            assert any(
                "tls" in msg.lower() or "resolved" in msg.lower()
                for msg in log_messages
            )
