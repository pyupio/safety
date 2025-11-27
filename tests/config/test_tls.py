import pytest
import os
import ssl
from pathlib import Path
from unittest.mock import patch, MagicMock
from configparser import ConfigParser
from typing import Dict, Optional

from safety.config.tls import (
    TLSConfig,
    get_tls_config,
    _should_build_tls_config,
    _normalize_bundle_path,
    _normalize_mode,
    _build_tls_config,
    _tls_from_cli_options,
    _tls_from_env,
    _tls_from_config_ini,
    _get_system_context,
)

# Fixtures

TLS_MODE_KEY = "mode"
VALID_TLS_MODES = ("default", "system", "bundle")
VALID_TLS_MODES_UPPERCASE = tuple(mode.upper() for mode in VALID_TLS_MODES)
DEFAULT_TLS_MODE = "default"

TLS_SECTION_NAME = "tls"
TLS_CA_BUNDLE_KEY = "ca_bundle"

ENV_TLS_MODE = "SAFETY_TLS_MODE"
ENV_CA_BUNDLE = "SAFETY_CA_BUNDLE"


@pytest.fixture
def valid_ca_bundle_file(tmp_path: Path) -> Path:
    """
    Create a valid CA bundle file for testing.
    """
    bundle_file = tmp_path / "ca-bundle.crt"
    bundle_file.write_text(
        "-----BEGIN CERTIFICATE-----\nMockCertContent\n-----END CERTIFICATE-----"
    )
    return bundle_file


@pytest.fixture
def valid_tls_config(valid_ca_bundle_file: Path) -> TLSConfig:
    """
    A valid TLSConfig for reuse.
    """
    return TLSConfig(
        mode="bundle",
        bundle_path=valid_ca_bundle_file,
        verify_context=str(valid_ca_bundle_file),
    )


@pytest.fixture
def config_file_factory(tmp_path: Path):
    """
    Factory fixture to create config.ini files with custom content.
    """

    def _create_config(tls_section: Optional[Dict[str, str]] = None) -> Path:
        config = ConfigParser()
        if tls_section is not None:
            config[TLS_SECTION_NAME] = tls_section

        config_path = tmp_path / "config.ini"
        with open(config_path, "w") as f:
            config.write(f)
        return config_path

    return _create_config


@pytest.fixture
def mock_certifi():
    """
    Mock certifi.where() function.
    """
    with patch("safety.config.tls.certifi.where") as mock:
        mock.return_value = "/path/to/certifi/cacert.pem"
        yield mock


# ─────────────────────────────────────────────────────────────────────────────
# TLSConfig Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestTLSConfig:
    """
    Tests for TLSConfig NamedTuple.
    """

    def test_as_dict_with_bundle_path(self, valid_ca_bundle_file: Path) -> None:
        config = TLSConfig(
            mode="bundle",
            bundle_path=valid_ca_bundle_file,
            verify_context=str(valid_ca_bundle_file),
        )

        result = config.as_dict()
        assert result == {
            "mode": "bundle",
            "ca_bundle": str(valid_ca_bundle_file),
        }

    def test_as_dict_without_bundle_path(self) -> None:
        config = TLSConfig(
            mode="default",
            bundle_path=None,
            verify_context="/path/to/certifi.pem",
        )

        result = config.as_dict()
        assert result == {
            "mode": "default",
            "ca_bundle": None,
        }

    def test_as_dict_system_mode(self) -> None:
        mock_context = MagicMock(spec=ssl.SSLContext)
        config = TLSConfig(
            mode="system",
            bundle_path=None,
            verify_context=mock_context,
        )

        result = config.as_dict()
        assert result == {
            "mode": "system",
            "ca_bundle": None,
        }


class TestShouldBuildTlsConfig:
    """
    Tests for _should_build_tls_config helper.
    """

    def test_returns_false_when_both_none(self) -> None:
        assert (
            _should_build_tls_config(mode=None, bundle_path=None, source="test")
            is False
        )

    def test_returns_false_when_both_empty_strings(self) -> None:
        assert _should_build_tls_config(mode="", bundle_path="", source="test") is False

    def test_returns_true_when_mode_provided(self) -> None:
        assert (
            _should_build_tls_config(mode="default", bundle_path=None, source="test")
            is True
        )

    def test_returns_true_when_bundle_provided(self) -> None:
        assert (
            _should_build_tls_config(
                mode=None, bundle_path="/path/to/bundle", source="test"
            )
            is True
        )

    def test_returns_true_when_both_provided(self) -> None:
        assert (
            _should_build_tls_config(
                mode="bundle", bundle_path="/path/to/bundle", source="test"
            )
            is True
        )

    def test_logs_debug_when_bundle_without_mode(self, caplog) -> None:
        import logging

        caplog.set_level(logging.DEBUG)

        result = _should_build_tls_config(
            mode=None, bundle_path="/path/to/bundle", source="CLI"
        )

        assert result is True
        assert any(
            "Bundle path provided without mode" in record.message
            for record in caplog.records
        )
        assert any(
            "assuming mode='bundle'" in record.message for record in caplog.records
        )

    def test_returns_true_when_mode_empty_but_bundle_provided(self) -> None:
        assert (
            _should_build_tls_config(
                mode="", bundle_path="/path/to/bundle", source="test"
            )
            is True
        )


class TestNormalizeBundlePath:
    """
    Tests for _normalize_bundle_path helper.
    """

    def test_normalizes_valid_file_path(self, valid_ca_bundle_file: Path) -> None:
        result = _normalize_bundle_path(valid_ca_bundle_file, "test")
        assert result == valid_ca_bundle_file.resolve()

    def test_expands_user_path(self, tmp_path: Path, monkeypatch) -> None:
        # Create a bundle in tmp_path
        bundle_file = tmp_path / "ca-bundle.crt"
        bundle_file.write_text("cert content")

        # Mock expanduser to return our test file
        with patch.object(Path, "expanduser") as mock_expand:
            mock_expand.return_value = bundle_file

            result = _normalize_bundle_path(Path("~/ca-bundle.crt"), "test")
            mock_expand.assert_called_once()
            assert result == bundle_file.resolve()

    def test_raises_when_path_none(self) -> None:
        with pytest.raises(ValueError, match="CA bundle path is empty"):
            _normalize_bundle_path(None, "test")

    def test_raises_when_path_does_not_exist(self, tmp_path: Path) -> None:
        nonexistent_path = tmp_path / "nonexistent.crt"
        with pytest.raises(ValueError, match="does not exist"):
            _normalize_bundle_path(nonexistent_path, "test")

    def test_raises_when_path_is_directory(self, tmp_path: Path) -> None:
        # Create a directory instead of a file
        directory_path = tmp_path / "cert_dir"
        directory_path.mkdir()

        with pytest.raises(ValueError, match="is not a file"):
            _normalize_bundle_path(directory_path, "test")

    def test_raises_when_file_not_readable(self, tmp_path: Path) -> None:
        bundle_file = tmp_path / "unreadable.crt"
        bundle_file.write_text("cert content")

        # Mock os.access to return False for read check
        with patch("os.access") as mock_access:
            mock_access.return_value = False

            with pytest.raises(ValueError, match="not readable"):
                _normalize_bundle_path(bundle_file, "test")

            mock_access.assert_called_with(bundle_file.resolve(), os.R_OK)

    def test_logs_resolved_bundle_path(
        self, valid_ca_bundle_file: Path, caplog
    ) -> None:
        import logging

        caplog.set_level(logging.DEBUG)

        _normalize_bundle_path(valid_ca_bundle_file, "CLI")

        assert any(
            "ca_bundle_resolved" in record.message.lower()
            or "resolved" in record.message.lower()
            for record in caplog.records
        )


class TestNormalizeMode:
    """
    Tests for _normalize_mode helper.
    """

    def test_returns_default_when_none(self) -> None:
        result = _normalize_mode(raw=None)
        assert result == DEFAULT_TLS_MODE

    def test_returns_default_when_empty_string(self) -> None:
        result = _normalize_mode(raw="")
        assert result == DEFAULT_TLS_MODE

    @pytest.mark.parametrize("mode", VALID_TLS_MODES)
    def test_normalizes_valid_modes(self, mode: str) -> None:
        result = _normalize_mode(raw=mode)
        assert result == mode

    @pytest.mark.parametrize("mode", VALID_TLS_MODES_UPPERCASE)
    def test_normalizes_case_insensitive(self, mode: str) -> None:
        result = _normalize_mode(raw=mode)
        assert result == mode.lower()

    def test_strips_whitespace(self) -> None:
        result = _normalize_mode(raw="  default  ")
        assert result == "default"

    @pytest.mark.parametrize("invalid_mode", ["invalid", "ssl", "tls", "none", "auto"])
    def test_raises_on_invalid_mode(self, invalid_mode: str) -> None:
        with pytest.raises(ValueError, match="Invalid TLS mode"):
            _normalize_mode(raw=invalid_mode)

    def test_error_message_includes_valid_options(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            _normalize_mode(raw="invalid")

        error_msg = str(exc_info.value)
        for valid_mode in VALID_TLS_MODES:
            assert valid_mode in error_msg


class TestBuildTlsConfig:
    """
    Tests for _build_tls_config helper.
    """

    def test_builds_bundle_mode_config(self, valid_ca_bundle_file: Path) -> None:
        result = _build_tls_config(
            mode="bundle", bundle_path=valid_ca_bundle_file, source="test"
        )

        assert result.mode == "bundle"
        assert result.bundle_path == valid_ca_bundle_file.resolve()
        assert result.verify_context == str(valid_ca_bundle_file.resolve())

    @patch("safety.config.tls._get_system_context")
    def test_builds_system_mode_config(self, mock_get_context) -> None:
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_get_context.return_value = mock_context

        result = _build_tls_config(mode="system", bundle_path=None, source="test")

        assert result.mode == "system"
        assert result.bundle_path is None
        assert result.verify_context == mock_context
        mock_get_context.assert_called_once()

    @patch("safety.config.tls.certifi.where")
    def test_builds_default_mode_config(self, mock_certifi) -> None:
        mock_certifi.return_value = "/path/to/certifi.pem"

        result = _build_tls_config(mode="default", bundle_path=None, source="test")

        assert result.mode == "default"
        assert result.bundle_path is None
        assert result.verify_context == "/path/to/certifi.pem"
        mock_certifi.assert_called_once()

    def test_normalizes_mode_case(self, valid_ca_bundle_file: Path) -> None:
        result = _build_tls_config(
            mode="BUNDLE", bundle_path=valid_ca_bundle_file, source="test"
        )
        assert result.mode == "bundle"

    def test_raises_on_bundle_mode_without_path(self) -> None:
        with pytest.raises(ValueError):
            _build_tls_config(mode="bundle", bundle_path=None, source="test")

    def test_raises_on_invalid_bundle_path(self, tmp_path: Path) -> None:
        nonexistent_path = tmp_path / "nonexistent.crt"
        with pytest.raises(ValueError):
            _build_tls_config(
                mode="bundle", bundle_path=nonexistent_path, source="test"
            )

    def test_raises_on_invalid_combination(self, valid_ca_bundle_file: Path) -> None:
        with pytest.raises(ValueError):
            _build_tls_config(
                mode="system", bundle_path=valid_ca_bundle_file, source="test"
            )


class TestTlsFromCliOptions:
    """
    Tests for _tls_from_cli_options.
    """

    def test_returns_none_when_no_options(self) -> None:
        result = _tls_from_cli_options()
        assert result is None

    def test_returns_none_when_both_none(self) -> None:
        result = _tls_from_cli_options(mode=None, ca_bundle=None)
        assert result is None

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_with_mode_only(self, mock_build) -> None:
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        result = _tls_from_cli_options(mode="system")

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="system", bundle_path=None, source="CLI"
        )

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_with_bundle_only(self, mock_build, tmp_path: Path) -> None:
        bundle_path = str(tmp_path / "bundle.crt")
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        result = _tls_from_cli_options(ca_bundle=bundle_path)

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="bundle",  # Default when only bundle is provided
            bundle_path=Path(bundle_path),
            source="CLI",
        )

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_with_both_options(self, mock_build, tmp_path: Path) -> None:
        bundle_path = str(tmp_path / "bundle.crt")
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        result = _tls_from_cli_options(mode="bundle", ca_bundle=bundle_path)

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="bundle", bundle_path=Path(bundle_path), source="CLI"
        )


class TestTlsFromEnv:
    """
    Tests for _tls_from_env.
    """

    def test_returns_none_when_no_env_vars(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = _tls_from_env()
            assert result is None

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_from_mode_env(self, mock_build) -> None:
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        with patch.dict(os.environ, {ENV_TLS_MODE: "system"}, clear=True):
            result = _tls_from_env()

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="system", bundle_path=None, source="environment"
        )

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_from_bundle_env(self, mock_build, tmp_path: Path) -> None:
        bundle_path = str(tmp_path / "bundle.crt")
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        with patch.dict(os.environ, {ENV_CA_BUNDLE: bundle_path}, clear=True):
            result = _tls_from_env()

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="bundle",  # Implied by bundle env var
            bundle_path=Path(bundle_path),
            source="environment",
        )

    @patch("safety.config.tls._build_tls_config")
    def test_mode_env_respected_when_both_set(self, mock_build, tmp_path: Path) -> None:
        bundle_path = str(tmp_path / "bundle.crt")
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        env_vars = {
            ENV_TLS_MODE: "system",
            ENV_CA_BUNDLE: bundle_path,
        }
        with patch.dict(os.environ, env_vars, clear=True):
            result = _tls_from_env()

        assert result == mock_config
        # Validation is done in _build_tls_config
        # so we expect it to be called with the explicit mode
        mock_build.assert_called_once_with(
            mode="system",  # Explicit mode is respected
            bundle_path=Path(bundle_path),
            source="environment",
        )


class TestTlsFromConfigIni:
    """
    Tests for _tls_from_config_ini.
    """

    def test_returns_none_when_file_missing(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "nonexistent.ini"
        result = _tls_from_config_ini(nonexistent)
        assert result is None

    def test_returns_none_when_no_tls_section(self, config_file_factory) -> None:
        config_path = config_file_factory(tls_section=None)
        result = _tls_from_config_ini(config_path)
        assert result is None

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_with_mode_only(
        self, mock_build, config_file_factory
    ) -> None:
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        config_path = config_file_factory(
            tls_section={
                TLS_MODE_KEY: "system",
            }
        )

        result = _tls_from_config_ini(config_path)

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="system", bundle_path=None, source="config"
        )

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_with_bundle_only(
        self, mock_build, config_file_factory, tmp_path: Path
    ) -> None:
        bundle_path = str(tmp_path / "bundle.crt")
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        config_path = config_file_factory(
            tls_section={
                TLS_CA_BUNDLE_KEY: bundle_path,
            }
        )

        result = _tls_from_config_ini(config_path)

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="bundle",  # Bundle path implies bundle mode
            bundle_path=Path(bundle_path),
            source="config",
        )

    @patch("safety.config.tls._build_tls_config")
    def test_builds_config_with_both_options(
        self, mock_build, config_file_factory, tmp_path: Path
    ) -> None:
        bundle_path = str(tmp_path / "bundle.crt")
        mock_config = MagicMock(spec=TLSConfig)
        mock_build.return_value = mock_config

        config_path = config_file_factory(
            tls_section={
                TLS_MODE_KEY: "bundle",
                TLS_CA_BUNDLE_KEY: bundle_path,
            }
        )

        result = _tls_from_config_ini(config_path)

        assert result == mock_config
        mock_build.assert_called_once_with(
            mode="bundle", bundle_path=Path(bundle_path), source="config"
        )

    def test_handles_empty_bundle_string(self, config_file_factory) -> None:
        config_path = config_file_factory(
            tls_section={
                TLS_MODE_KEY: "default",
                TLS_CA_BUNDLE_KEY: "",  # Empty string
            }
        )

        with patch("safety.config.tls._build_tls_config") as mock_build:
            mock_config = MagicMock(spec=TLSConfig)
            mock_build.return_value = mock_config

            _tls_from_config_ini(config_path)

            mock_build.assert_called_once_with(
                mode="default",
                bundle_path=None,  # Empty string should become None
                source="config",
            )

    def test_strips_whitespace_from_bundle_path(
        self, config_file_factory, tmp_path: Path
    ) -> None:
        bundle_path = str(tmp_path / "bundle.crt")

        config_path = config_file_factory(
            tls_section={
                TLS_CA_BUNDLE_KEY: f"  {bundle_path}  ",  # Whitespace around path
            }
        )

        with patch("safety.config.tls._build_tls_config") as mock_build:
            mock_config = MagicMock(spec=TLSConfig)
            mock_build.return_value = mock_config

            _tls_from_config_ini(config_path)

            mock_build.assert_called_once_with(
                mode="bundle",  # Bundle path implies bundle mode
                bundle_path=Path(bundle_path),  # Whitespace should be stripped
                source="config",
            )

    def test_returns_none_when_should_not_build(self, config_file_factory) -> None:
        # Empty section should return None (no config specified)
        config_path = config_file_factory(tls_section={})
        result = _tls_from_config_ini(config_path)
        # Empty section should return None, letting resolution continue to fallback
        assert result is None


class TestGetSystemContext:
    """
    Tests for _get_system_context.
    """

    def test_uses_truststore_when_available(self) -> None:
        mock_truststore = MagicMock()
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_truststore.SSLContext.return_value = mock_context

        with patch.dict("sys.modules", {"truststore": mock_truststore}):
            result = _get_system_context()

        assert result == mock_context
        mock_truststore.SSLContext.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)

    @patch("safety.config.tls.ssl.create_default_context")
    def test_falls_back_to_ssl_when_truststore_unavailable(
        self, mock_create_context
    ) -> None:
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_create_context.return_value = mock_context

        with patch(
            "builtins.__import__",
            side_effect=ImportError("No module named 'truststore'"),
        ):
            result = _get_system_context()

        assert result == mock_context
        mock_create_context.assert_called_once()

    def test_logs_attempt_and_truststore_resolved(self, caplog) -> None:
        import logging

        caplog.set_level(logging.DEBUG)

        mock_truststore = MagicMock()
        mock_context = MagicMock(spec=ssl.SSLContext)
        mock_truststore.SSLContext.return_value = mock_context

        with patch.dict("sys.modules", {"truststore": mock_truststore}):
            _get_system_context()

        # Should log both attempt and resolved with truststore using structured codes
        messages = [record.message for record in caplog.records]
        assert any("config.tls.system_store_attempt" in msg for msg in messages)
        assert any("config.tls.system_store_resolved" in msg for msg in messages)

    def test_logs_attempt_and_fallback(self, caplog) -> None:
        import logging
        import sys

        caplog.set_level(logging.DEBUG)

        # Temporarily remove truststore from sys.modules if present
        truststore_backup = sys.modules.pop("truststore", None)

        try:
            with patch(
                "safety.config.tls.ssl.create_default_context"
            ) as mock_create_context:
                mock_context = MagicMock(spec=ssl.SSLContext)
                mock_create_context.return_value = mock_context

                # Force ImportError by making import fail
                original_import = __builtins__["__import__"]

                def mock_import(name, *args, **kwargs):
                    if name == "truststore":
                        raise ImportError("No module named 'truststore'")
                    return original_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=mock_import):
                    result = _get_system_context()

                assert result == mock_context
        finally:
            # Restore backup
            if truststore_backup:
                sys.modules["truststore"] = truststore_backup

        # Should log both attempt and fallback using structured codes
        messages = [record.message for record in caplog.records]
        assert any("config.tls.system_store_attempt" in msg for msg in messages)
        assert any(
            "config.tls.system_store_unsupported" in msg
            or "config.tls.system_store_resolved" in msg
            for msg in messages
        )


class TestGetTlsConfig:
    """
    Tests for get_tls_config.
    """

    def test_cli_takes_precedence_over_env_and_config(
        self, config_file_factory, valid_ca_bundle_file: Path
    ) -> None:
        # Set up config file
        config_path = config_file_factory(
            tls_section={
                TLS_MODE_KEY: "system",
            }
        )

        # Set up environment
        env_vars = {ENV_TLS_MODE: "default"}

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("safety.config.tls._build_tls_config") as mock_build:
                mock_config = MagicMock(spec=TLSConfig)
                mock_config.verify_context = "cli_context"
                mock_build.return_value = mock_config

                result = get_tls_config(
                    mode="bundle",
                    ca_bundle=str(valid_ca_bundle_file),
                    config_path=config_path,
                )

                # Should call _build_tls_config for CLI options only
                mock_build.assert_called_once_with(
                    mode="bundle", bundle_path=valid_ca_bundle_file, source="CLI"
                )
                assert result == "cli_context"

    def test_env_takes_precedence_over_config(self, config_file_factory) -> None:
        # Set up config file
        config_path = config_file_factory(
            tls_section={
                TLS_MODE_KEY: "bundle",
            }
        )

        # Set up environment (should override config)
        env_vars = {ENV_TLS_MODE: "system"}

        with patch.dict(os.environ, env_vars, clear=True):
            with patch("safety.config.tls._build_tls_config") as mock_build:
                mock_config = MagicMock(spec=TLSConfig)
                mock_config.verify_context = "env_context"
                mock_build.return_value = mock_config

                result = get_tls_config(config_path=config_path)

                # Should call _build_tls_config for environment options only
                mock_build.assert_called_once_with(
                    mode="system", bundle_path=None, source="environment"
                )
                assert result == "env_context"

    def test_config_used_when_no_cli_or_env(self, config_file_factory) -> None:
        config_path = config_file_factory(
            tls_section={
                TLS_MODE_KEY: "system",
            }
        )

        with patch.dict(os.environ, {}, clear=True):
            with patch("safety.config.tls._build_tls_config") as mock_build:
                mock_config = MagicMock(spec=TLSConfig)
                mock_config.verify_context = "config_context"
                mock_build.return_value = mock_config

                result = get_tls_config(config_path=config_path)

                # Should call _build_tls_config for config options only
                mock_build.assert_called_once_with(
                    mode="system", bundle_path=None, source="config"
                )
                assert result == "config_context"

    @patch("safety.config.tls.certifi.where")
    def test_falls_back_to_default(self, mock_certifi, config_file_factory) -> None:
        mock_certifi.return_value = "/path/to/certifi.pem"

        # Config file with no TLS section
        config_path = config_file_factory(tls_section=None)

        with patch.dict(os.environ, {}, clear=True):
            result = get_tls_config(config_path=config_path)

        assert result == "/path/to/certifi.pem"
        mock_certifi.assert_called_once()

    def test_logs_cli_resolution(self, caplog) -> None:
        import logging

        caplog.set_level(logging.INFO)

        with patch("safety.config.tls._build_tls_config") as mock_build:
            mock_config = MagicMock(spec=TLSConfig)
            mock_config.verify_context = "test_context"
            mock_config.as_dict.return_value = {"mode": "default"}
            mock_build.return_value = mock_config

            get_tls_config(mode="default")

        # Check for structured log code for TLS resolution
        assert any("config.tls.resolved" in record.message for record in caplog.records)

    def test_logs_env_resolution(self, caplog) -> None:
        import logging

        caplog.set_level(logging.INFO)

        env_vars = {ENV_TLS_MODE: "system"}
        with patch.dict(os.environ, env_vars, clear=True):
            with patch("safety.config.tls._build_tls_config") as mock_build:
                mock_config = MagicMock(spec=TLSConfig)
                mock_config.verify_context = "test_context"
                mock_config.as_dict.return_value = {"mode": "system"}
                mock_build.return_value = mock_config

                get_tls_config()

        # Check for structured log code for TLS resolution
        assert any("config.tls.resolved" in record.message for record in caplog.records)

    def test_logs_config_resolution(self, config_file_factory, caplog) -> None:
        import logging

        caplog.set_level(logging.INFO)

        config_path = config_file_factory(
            tls_section={
                TLS_MODE_KEY: "default",
            }
        )

        with patch.dict(os.environ, {}, clear=True):
            with patch("safety.config.tls._build_tls_config") as mock_build:
                mock_config = MagicMock(spec=TLSConfig)
                mock_config.verify_context = "test_context"
                mock_config.as_dict.return_value = {"mode": "default"}
                mock_build.return_value = mock_config

                get_tls_config(config_path=config_path)

        assert any("config" in record.message.lower() for record in caplog.records)

    def test_logs_default_fallback(self, config_file_factory, caplog) -> None:
        import logging

        caplog.set_level(logging.INFO)

        config_path = config_file_factory(tls_section=None)

        with patch.dict(os.environ, {}, clear=True):
            with patch("safety.config.tls.certifi.where") as mock_certifi:
                mock_certifi.return_value = "/path/to/certifi.pem"
                get_tls_config(config_path=config_path)

        assert any("default" in record.message.lower() for record in caplog.records)

    def test_handles_build_errors_gracefully(self, valid_ca_bundle_file: Path) -> None:
        # Should propagate ValueError from _build_tls_config
        with pytest.raises(ValueError):
            get_tls_config(mode="invalid_mode", ca_bundle=str(valid_ca_bundle_file))
