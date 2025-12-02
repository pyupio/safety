import pytest
from pathlib import Path
from unittest.mock import patch
import configparser
from typing import Dict, Optional

from safety.config.proxy import (
    ProxyEndpoint,
    ProxyConfig,
    get_proxy_config,
    _build_proxy_config,
    _should_build_proxy_config,
    _proxy_from_config_ini,
    _proxy_from_cli_options,
)


# Fixtures

DEFAULT_PROXY_PORT = 80
DEFAULT_PROXY_SCHEME = "http"


@pytest.fixture
def valid_proxy_endpoint() -> ProxyEndpoint:
    """
    A valid ProxyEndpoint for reuse.
    """
    return ProxyEndpoint(scheme="https", host="proxy.example.com", port=8080)


@pytest.fixture
def valid_proxy_config(valid_proxy_endpoint: ProxyEndpoint) -> ProxyConfig:
    """
    A valid ProxyConfig for reuse.
    """
    return ProxyConfig(
        endpoint=valid_proxy_endpoint,
    )


@pytest.fixture
def config_file_factory(tmp_path: Path):
    """
    Factory fixture to create config.ini files with custom content.
    """

    def _create_config(proxy_section: Optional[Dict[str, str]] = None) -> Path:
        config = configparser.ConfigParser()
        if proxy_section is not None:
            config["proxy"] = proxy_section

        config_path = tmp_path / "config.ini"
        with open(config_path, "w") as f:
            config.write(f)
        return config_path

    return _create_config


class TestProxyEndpoint:
    """
    Tests for ProxyEndpoint NamedTuple.
    """

    def test_as_url_formats_correctly(
        self, valid_proxy_endpoint: ProxyEndpoint
    ) -> None:
        assert valid_proxy_endpoint.as_url() == "https://proxy.example.com:8080"

    def test_as_url_with_http(self) -> None:
        endpoint = ProxyEndpoint(scheme="http", host="localhost", port=3128)
        assert endpoint.as_url() == "http://localhost:3128"

    def test_as_url_with_different_ports(self) -> None:
        endpoint = ProxyEndpoint(scheme="https", host="proxy.corp.com", port=9090)
        assert endpoint.as_url() == "https://proxy.corp.com:9090"

    def test_as_dict_returns_expected_keys(
        self, valid_proxy_endpoint: ProxyEndpoint
    ) -> None:
        result = valid_proxy_endpoint.as_dict()
        assert result == {
            "protocol": "https",
            "host": "proxy.example.com",
            "port": "8080",  # Note: converted to string
        }

    def test_as_dict_with_http(self) -> None:
        endpoint = ProxyEndpoint(scheme="http", host="localhost", port=3128)
        result = endpoint.as_dict()
        assert result == {
            "protocol": "http",
            "host": "localhost",
            "port": "3128",
        }


class TestProxyConfig:
    """
    Tests for ProxyConfig NamedTuple.
    """

    def test_as_dict_includes_all_fields(self, valid_proxy_config: ProxyConfig) -> None:
        result = valid_proxy_config.as_dict()
        assert result == {
            "protocol": "https",
            "host": "proxy.example.com",
            "port": "8080",
        }

    def test_as_dict_with_different_values(self) -> None:
        endpoint = ProxyEndpoint(scheme="http", host="test.proxy", port=8888)
        config = ProxyConfig(endpoint=endpoint)

        result = config.as_dict()
        assert result == {
            "protocol": "http",
            "host": "test.proxy",
            "port": "8888",
        }


class TestShouldBuildProxyConfig:
    """
    Tests for _should_build_proxy_config helper.
    """

    @pytest.mark.parametrize("host", [None, ""])
    def test_returns_false_when_host_empty_and_no_other_values(
        self, host: Optional[str]
    ) -> None:
        assert _should_build_proxy_config(host, source="test") is False

    def test_returns_false_when_host_whitespace_only(self) -> None:
        assert _should_build_proxy_config("   ", source="test") is False

    def test_returns_true_when_host_provided(self) -> None:
        assert _should_build_proxy_config("proxy.example.com", source="test") is True

    def test_returns_true_when_host_with_whitespace(self) -> None:
        assert (
            _should_build_proxy_config("  proxy.example.com  ", source="test") is True
        )

    def test_raises_when_port_provided_without_host(self) -> None:
        with pytest.raises(ValueError, match="Proxy host must be provided"):
            _should_build_proxy_config(None, 8080, source="CLI")

    def test_raises_when_scheme_provided_without_host(self) -> None:
        with pytest.raises(ValueError, match="Proxy host must be provided"):
            _should_build_proxy_config(None, None, "https", source="CLI")

    def test_raises_when_required_provided_without_host(self) -> None:
        with pytest.raises(ValueError, match="Proxy host must be provided"):
            _should_build_proxy_config(None, None, None, True, source="CLI")

    def test_raises_when_timeout_provided_without_host(self) -> None:
        with pytest.raises(ValueError, match="Proxy host must be provided"):
            _should_build_proxy_config(None, None, None, None, 5000, source="CLI")

    def test_raises_when_multiple_values_provided_without_host(self) -> None:
        with pytest.raises(ValueError, match="Proxy host must be provided"):
            _should_build_proxy_config(None, 8080, "https", True, 5000, source="CLI")

    def test_allows_none_other_values_without_host(self) -> None:
        # Should not raise when all other values are None
        result = _should_build_proxy_config(None, None, None, None, None, source="test")
        assert result is False


class TestBuildProxyConfig:
    """
    Tests for _build_proxy_config helper.
    """

    def test_builds_with_all_values(self) -> None:
        result = _build_proxy_config(
            host="proxy.example.com",
            port=8080,
            scheme="https",
            source="test",
        )
        assert result.endpoint.host == "proxy.example.com"
        assert result.endpoint.port == 8080
        assert result.endpoint.scheme == "https"

    def test_applies_defaults_when_values_missing(self) -> None:
        result = _build_proxy_config(
            host="proxy.example.com",
            port=None,
            scheme=None,
            source="test",
        )
        assert result.endpoint.port == DEFAULT_PROXY_PORT
        assert result.endpoint.scheme == DEFAULT_PROXY_SCHEME

    def test_strips_whitespace_from_host(self) -> None:
        result = _build_proxy_config(
            host="  proxy.example.com  ",
            port=None,
            scheme=None,
            source="test",
        )
        assert result.endpoint.host == "proxy.example.com"

    @pytest.mark.parametrize("empty_host", ["", "   "])
    def test_raises_on_empty_host_string(self, empty_host: str) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            _build_proxy_config(
                host=empty_host,
                port=None,
                scheme=None,
                source="test",
            )

    def test_raises_on_none_host(self) -> None:
        with pytest.raises((ValueError, AttributeError)):
            _build_proxy_config(
                host=None,  # type: ignore
                port=None,
                scheme=None,
                source="test",
            )

    @pytest.mark.parametrize("invalid_scheme", ["ftp", "socks5", "tcp", "UDP", "ssh"])
    def test_raises_on_invalid_protocol(self, invalid_scheme: str) -> None:
        with pytest.raises(ValueError, match="Invalid proxy protocol"):
            _build_proxy_config(
                host="proxy.example.com",
                port=None,
                scheme=invalid_scheme,
                source="test",
            )

    def test_normalizes_scheme_to_lowercase(self) -> None:
        result = _build_proxy_config(
            host="proxy.example.com",
            port=None,
            scheme="HTTPS",
            source="test",
        )
        assert result.endpoint.scheme == "https"

    def test_normalizes_http_scheme(self) -> None:
        result = _build_proxy_config(
            host="proxy.example.com",
            port=None,
            scheme="HTTP",
            source="test",
        )
        assert result.endpoint.scheme == "http"


class TestProxyFromConfigIni:
    """
    Tests for _proxy_from_config_ini.
    """

    def test_returns_none_when_file_missing(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "nonexistent.ini"
        result = _proxy_from_config_ini(nonexistent)
        assert result is None

    def test_returns_none_when_no_proxy_section(self, config_file_factory) -> None:
        config_path = config_file_factory(proxy_section=None)
        result = _proxy_from_config_ini(config_path)
        assert result is None

    def test_returns_none_when_host_not_provided(self, config_file_factory) -> None:
        config_path = config_file_factory(proxy_section={})
        result = _proxy_from_config_ini(config_path)
        assert result is None

    def test_parses_full_config(self, config_file_factory) -> None:
        config_path = config_file_factory(
            proxy_section={
                "host": "proxy.corp.com",
                "port": "8080",
                "protocol": "https",
            }
        )
        result = _proxy_from_config_ini(config_path)

        assert result is not None
        assert result.endpoint.host == "proxy.corp.com"
        assert result.endpoint.port == 8080
        assert result.endpoint.scheme == "https"

    def test_applies_defaults_for_optional_fields(self, config_file_factory) -> None:
        config_path = config_file_factory(
            proxy_section={
                "host": "proxy.corp.com",
            }
        )
        result = _proxy_from_config_ini(config_path)

        assert result is not None
        assert result.endpoint.host == "proxy.corp.com"
        assert result.endpoint.port == DEFAULT_PROXY_PORT
        assert result.endpoint.scheme == DEFAULT_PROXY_SCHEME

    def test_handles_partial_config(self, config_file_factory) -> None:
        config_path = config_file_factory(
            proxy_section={
                "host": "proxy.corp.com",
                "port": "9090",
                "protocol": "http",
            }
        )
        result = _proxy_from_config_ini(config_path)

        assert result is not None
        assert result.endpoint.host == "proxy.corp.com"
        assert result.endpoint.port == 9090
        assert result.endpoint.scheme == "http"

    def test_raises_when_host_empty_but_other_values_in_config(
        self, config_file_factory
    ) -> None:
        config_path = config_file_factory(
            proxy_section={
                "host": "",
                "port": "8080",
            }
        )
        # Empty host with other values should raise exception
        with pytest.raises(ValueError, match=r"Proxy host must be provided"):
            _proxy_from_config_ini(config_path)

    def test_returns_none_when_host_empty_only_in_config(
        self, config_file_factory
    ) -> None:
        config_path = config_file_factory(
            proxy_section={
                "host": "",
            }
        )
        # Empty host with no other values should return None
        result = _proxy_from_config_ini(config_path)
        assert result is None

    def test_logs_missing_section_debug_message(
        self, config_file_factory, caplog
    ) -> None:
        import logging

        caplog.set_level(logging.DEBUG)

        config_path = config_file_factory(proxy_section=None)
        result = _proxy_from_config_ini(config_path)

        assert result is None
        # Check that missing section was logged
        assert any(
            "proxy" in record.message.lower() or "missing" in record.message.lower()
            for record in caplog.records
        )


class TestProxyFromCliOptions:
    """
    Tests for _proxy_from_cli_options.
    """

    def test_returns_none_when_no_options(self) -> None:
        result = _proxy_from_cli_options()
        assert result is None

    def test_returns_none_when_all_none(self) -> None:
        result = _proxy_from_cli_options(host=None, port=None, scheme=None)
        assert result is None

    def test_parses_all_options(self) -> None:
        result = _proxy_from_cli_options(
            host="cli-proxy.com",
            port="9090",
            scheme="https",
        )
        assert result is not None
        assert result.endpoint.host == "cli-proxy.com"
        assert result.endpoint.port == 9090
        assert result.endpoint.scheme == "https"

    def test_parses_minimal_options_with_defaults(self) -> None:
        result = _proxy_from_cli_options(host="cli-proxy.com")
        assert result is not None
        assert result.endpoint.host == "cli-proxy.com"
        assert result.endpoint.port == DEFAULT_PROXY_PORT
        assert result.endpoint.scheme == DEFAULT_PROXY_SCHEME

    def test_raises_on_invalid_port_string(self) -> None:
        with pytest.raises(ValueError, match="port must be an integer"):
            _proxy_from_cli_options(host="proxy.com", port="not-a-number")

    def test_handles_zero_port_string(self) -> None:
        with pytest.raises(ValueError, match="port must be an integer"):
            _proxy_from_cli_options(host="proxy.com", port="0.5")

    def test_handles_negative_port_string(self) -> None:
        result = _proxy_from_cli_options(host="proxy.com", port="-1")
        assert result is not None
        assert result.endpoint.port == -1

    def test_returns_none_when_host_empty_string(self) -> None:
        # Empty host string should return None due to _should_build_proxy_config check
        result = _proxy_from_cli_options(host="")
        assert result is None

    def test_raises_when_port_provided_without_host(self) -> None:
        with pytest.raises(ValueError, match="Proxy host must be provided"):
            _proxy_from_cli_options(port="8080")

    def test_handles_valid_integer_strings(self) -> None:
        result = _proxy_from_cli_options(host="proxy.com", port="8080")
        assert result is not None
        assert result.endpoint.port == 8080


class TestGetProxyConfig:
    """
    Tests for get_proxy_config.
    """

    def test_cli_options_take_precedence(self, config_file_factory) -> None:
        # Config file has one value
        config_path = config_file_factory(
            proxy_section={
                "host": "config-proxy.com",
                "port": "8080",
            }
        )

        # CLI provides different value - should win
        result = get_proxy_config(
            host="cli-proxy.com",
            port="9090",
            config_path=config_path,
        )

        assert result is not None
        assert result.endpoint.host == "cli-proxy.com"
        assert result.endpoint.port == 9090

    def test_falls_back_to_config_when_no_cli(self, config_file_factory) -> None:
        config_path = config_file_factory(
            proxy_section={
                "host": "config-proxy.com",
                "port": "8080",
            }
        )

        result = get_proxy_config(config_path=config_path)

        assert result is not None
        assert result.endpoint.host == "config-proxy.com"
        assert result.endpoint.port == 8080

    def test_returns_none_when_no_config_anywhere(self, config_file_factory) -> None:
        config_path = config_file_factory(proxy_section=None)
        result = get_proxy_config(config_path=config_path)
        assert result is None

    def test_returns_none_when_config_file_missing(self, tmp_path: Path) -> None:
        nonexistent_path = tmp_path / "nonexistent.ini"
        result = get_proxy_config(config_path=nonexistent_path)
        assert result is None

    def test_cli_partial_override_config_full(self, config_file_factory) -> None:
        config_path = config_file_factory(
            proxy_section={
                "host": "config-proxy.com",
                "port": "8080",
                "protocol": "https",
                "required": "true",
                "timeout": "5000",
            }
        )

        # CLI only provides host - should get CLI host, config defaults
        result = get_proxy_config(
            host="cli-proxy.com",
            config_path=config_path,
        )

        assert result is not None
        assert result.endpoint.host == "cli-proxy.com"
        # CLI options should use code defaults, not config values
        assert result.endpoint.port == DEFAULT_PROXY_PORT
        assert result.endpoint.scheme == DEFAULT_PROXY_SCHEME

    def test_logs_proxy_resolved_for_cli(self, config_file_factory, caplog) -> None:
        """Verify logging behavior for CLI resolution."""
        import logging

        caplog.set_level(logging.INFO)

        config_path = config_file_factory(proxy_section=None)
        get_proxy_config(host="proxy.com", config_path=config_path)

        # Check that resolution was logged with CLI source
        assert any(
            "cli" in record.message.lower() or getattr(record, "source", "") == "cli"
            for record in caplog.records
        )

    def test_logs_proxy_resolved_for_config(self, config_file_factory, caplog) -> None:
        """
        Verify logging behavior for config resolution.
        """
        import logging

        caplog.set_level(logging.INFO)

        config_path = config_file_factory(
            proxy_section={
                "host": "config-proxy.com",
            }
        )
        get_proxy_config(config_path=config_path)

        # Check that resolution was logged with config source
        assert any(
            "config" in record.message.lower()
            or getattr(record, "source", "") == "config"
            for record in caplog.records
        )

    def test_logs_proxy_not_defined_when_none(
        self, config_file_factory, caplog
    ) -> None:
        """Verify logging behavior when no proxy is defined."""
        import logging

        caplog.set_level(logging.INFO)

        config_path = config_file_factory(proxy_section=None)
        result = get_proxy_config(config_path=config_path)

        assert result is None
        # Check that "not defined" was logged
        assert any(
            "not" in record.message.lower() and "defined" in record.message.lower()
            for record in caplog.records
        )

    @patch("safety.config.proxy.logger")
    def test_logs_errors_on_invalid_config(
        self, mock_logger, config_file_factory
    ) -> None:
        """Test that errors are logged appropriately."""
        config_path = config_file_factory(
            proxy_section={
                "host": "proxy.com",
                "protocol": "invalid-protocol",
            }
        )

        with pytest.raises(ValueError):
            get_proxy_config(config_path=config_path)

        # Verify error was logged
        mock_logger.error.assert_called()
