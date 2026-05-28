import os
import ssl
from ssl import SSLContext
from pathlib import Path
from typing import NamedTuple, Optional, Union
from configparser import ConfigParser

import certifi
from safety.constants import CONFIG
from safety.utils.tls import get_system_tls_context
from .log_codes import (
    TLS_RESOLVED,
    TLS_RESOLUTION_FALLBACK_DEFAULT,
    TLS_CA_BUNDLE_RESOLVED,
)

import logging

logger = logging.getLogger(__name__)

TLS_SECTION_NAME = "tls"
TLS_MODE_KEY = "mode"
TLS_CA_BUNDLE_KEY = "ca_bundle"

ENV_TLS_MODE = "SAFETY_TLS_MODE"
ENV_CA_BUNDLE = "SAFETY_CA_BUNDLE"


# Default values
DEFAULT_TLS_MODE: str = "default"
VALID_TLS_MODES = ("default", "system", "bundle")


class TLSConfig(NamedTuple):
    """
    TLS configuration containing mode, bundle path, and resolved verify context.

    Args:
        mode (str): The TLS mode ('default', 'system', 'bundle').
        bundle_path (Optional[Path]): Path to custom CA bundle if mode='bundle'.
        verify_context (SSLContext): The resolved verification context.
    """

    mode: str
    bundle_path: Optional[Path]
    verify_context: SSLContext

    def as_dict(self) -> dict[str, Union[str, Path, None]]:
        """
        Convert TLS configuration to dictionary representation.

        Returns:
            dict: Dictionary containing TLS configuration data.
        """
        return {
            TLS_MODE_KEY: self.mode,
            TLS_CA_BUNDLE_KEY: str(self.bundle_path) if self.bundle_path else None,
        }


def _should_build_tls_config(
    mode: Optional[str],
    bundle_path: Optional[str],
    source: str,
) -> bool:
    """
    Return True if the TLS config should be built, False otherwise.

    Args:
        mode (Optional[str]): The TLS mode.
        bundle_path (Optional[str]): The CA bundle path.
        source (str): The source of the values.

    Returns:
        bool: True if the TLS config should be built, False otherwise.
    """
    if not mode and not bundle_path:
        return False

    if bundle_path and not mode:
        logger.debug(
            f"Bundle path provided without mode via {source}, assuming mode='bundle'"
        )
        return True

    return True


def _normalize_bundle_path(path: Optional[Path], source: str = "unknown") -> Path:
    """
    Validate and normalize a CA bundle path.

    Args:
        path (Optional[Path]): The path to validate.
        source (str): The source of the path for logging.

    Returns:
        Path: The validated and normalized path.

    Raises:
        ValueError: If the path is invalid.
    """
    if not path:
        raise ValueError("CA bundle path is empty")

    path = path.expanduser().resolve()

    if not path.exists():
        raise ValueError(f"CA bundle path does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"CA bundle path is not a file: {path}")

    if not os.access(path, os.R_OK):
        raise ValueError(f"CA bundle is not readable: {path}")

    logger.debug(TLS_CA_BUNDLE_RESOLVED, extra={"path": str(path), "source": source})
    return path


def _infer_effective_mode_and_bundle(
    raw_mode: Optional[str], raw_bundle: Optional[str]
) -> tuple[Optional[str], Optional[Path]]:
    """
    Infer effective mode and bundle path from raw inputs.

    Args:
        raw_mode (Optional[str]): The raw mode string.
        raw_bundle (Optional[str]): The raw bundle path string.

    Returns:
        tuple[Optional[str], Optional[Path]]: Effective mode and bundle path.
    """
    if raw_bundle and not raw_mode:
        return "bundle", Path(raw_bundle)
    elif raw_mode:
        bundle_path = Path(raw_bundle) if raw_bundle else None
        return raw_mode, bundle_path
    elif raw_bundle:  # bundle but no mode (redundant but explicit)
        return "bundle", Path(raw_bundle)
    else:
        return None, None


def _normalize_mode(raw: Optional[str]) -> str:
    """
    Validate and normalize TLS mode.

    Args:
        raw (Optional[str]): The raw mode string.

    Returns:
        str: The normalized mode.

    Raises:
        ValueError: If the mode is invalid.
    """
    if not raw:
        return DEFAULT_TLS_MODE

    mode = raw.strip().lower()
    if mode not in VALID_TLS_MODES:
        raise ValueError(
            f"Invalid TLS mode: {raw!r}. Valid options: {', '.join(VALID_TLS_MODES)}"
        )
    return mode


def _build_tls_config_from_source(
    raw_mode: Optional[str],
    raw_bundle: Optional[str],
    source: str,
) -> Optional[TLSConfig]:
    """
    Common logic for building TLS config from any source.

    Args:
        raw_mode (Optional[str]): The raw TLS mode.
        raw_bundle (Optional[str]): The raw CA bundle path.
        source (str): The source of the configuration for logging.

    Returns:
        Optional[TLSConfig]: The TLS configuration, or None if not buildable.
    """
    # Early validation
    if not _should_build_tls_config(raw_mode, raw_bundle, source):
        return None

    # Infer effective values
    effective_mode, bundle_path = _infer_effective_mode_and_bundle(raw_mode, raw_bundle)

    # If still no mode, return None (let resolution continue)
    if not effective_mode:
        return None

    return _build_tls_config(
        mode=effective_mode, bundle_path=bundle_path, source=source
    )


def _build_tls_config(
    mode: Optional[str],
    bundle_path: Optional[Path],
    source: str = "unknown",
) -> TLSConfig:
    """
    Build a TLS configuration from validated parameters.

    Args:
        mode (Optional[str]): The TLS mode (None defaults to DEFAULT_TLS_MODE).
        bundle_path (Optional[Path]): The CA bundle path if mode='bundle'.
        source (str): The source of the configuration for logging.

    Returns:
        TLSConfig: The built TLS configuration.

    Raises:
        ValueError: If the configuration is invalid.
    """
    normalized_mode = _normalize_mode(mode)

    if bundle_path and normalized_mode != "bundle":
        raise ValueError(
            "TLS mode is not 'bundle', but a TLS bundle path was provided."
        )

    if normalized_mode == "bundle":
        normalized_bundle_path = _normalize_bundle_path(bundle_path, source)
        verify_context = ssl.create_default_context(cafile=normalized_bundle_path)
    elif normalized_mode == "system":
        normalized_bundle_path = None
        verify_context = get_system_tls_context()
    else:  # normalized_mode == "default"
        normalized_bundle_path = None
        verify_context = ssl.create_default_context(cafile=certifi.where())

    return TLSConfig(
        mode=normalized_mode,
        bundle_path=normalized_bundle_path,
        verify_context=verify_context,
    )


def _tls_from_cli_options(
    mode: Optional[str] = None,
    ca_bundle: Optional[str] = None,
) -> Optional[TLSConfig]:
    """
    Retrieve the TLS configuration from command-line options.

    Args:
        mode (Optional[str]): The TLS mode from CLI options.
        ca_bundle (Optional[str]): The CA bundle path from CLI options.

    Returns:
        Optional[TLSConfig]: The TLS configuration, or None if not found.
    """
    return _build_tls_config_from_source(mode, ca_bundle, "CLI")


def _tls_from_env() -> Optional[TLSConfig]:
    """
    Retrieve the TLS configuration from environment variables.

    Environment variables:
        SAFETY_TLS_MODE: TLS mode ('default', 'system', 'bundle')
        SAFETY_CA_BUNDLE: Path to CA bundle (implies mode='bundle')

    Returns:
        Optional[TLSConfig]: The TLS configuration, or None if not found.
    """
    env_bundle = os.getenv(ENV_CA_BUNDLE)
    env_mode = os.getenv(ENV_TLS_MODE)

    return _build_tls_config_from_source(env_mode, env_bundle, "environment")


def _tls_from_config_ini(config_path: Path) -> Optional[TLSConfig]:
    """
    Retrieve the TLS configuration from the config.ini file.

    Args:
        config_path (Path): The path to the config.ini file.

    Returns:
        Optional[TLSConfig]: The TLS configuration, or None if not found.
    """
    config = ConfigParser()
    config_files = config.read([config_path])

    if not config_files or not config.has_section(TLS_SECTION_NAME):
        return None

    section = config[TLS_SECTION_NAME]

    raw_mode = section.get(TLS_MODE_KEY, "").strip() or None
    raw_bundle = section.get(TLS_CA_BUNDLE_KEY, "").strip() or None

    return _build_tls_config_from_source(raw_mode, raw_bundle, "config")


def get_tls_config(
    mode: Optional[str] = None,
    ca_bundle: Optional[str] = None,
    config_path: Path = CONFIG,
) -> TLSConfig:
    """
    Resolve the effective TLS verification configuration.

    Resolution order (first non-None wins):
      1. Command-line options/manual override (mode, ca_bundle)
      2. Environment variables (SAFETY_TLS_MODE, SAFETY_CA_BUNDLE)
      3. config.ini [tls] section
      4. Default: certifi bundle

    Args:
        mode (Optional[str]): The TLS mode from CLI options ('default', 'system', 'bundle').
        ca_bundle (Optional[str]): The CA bundle path from CLI options.
        config_path (Path): The path to the config.ini file.

    Returns:
        TLSConfig: The TLS configuration.

    Raises:
        ValueError: If the TLS configuration is invalid.

    TLS Modes:
        - default: Use certifi.where() (bundled CA certificates)
        - system: Use system trust store (via truststore if available)
        - bundle: Use custom CA bundle file
    """
    sources = [
        ("cli", lambda: _tls_from_cli_options(mode=mode, ca_bundle=ca_bundle)),
        ("environment", lambda: _tls_from_env()),
        ("config", lambda: _tls_from_config_ini(config_path=config_path)),
    ]

    for source_name, source_func in sources:
        result = source_func()
        if result is not None:
            extra = {"source": source_name, **result.as_dict()}
            if source_name == "config":
                extra["config_path"] = str(config_path)
            logger.info(TLS_RESOLVED, extra=extra)
            return result

    # Default fallback
    default_result = _build_tls_config(
        mode=DEFAULT_TLS_MODE, bundle_path=None, source="default"
    )

    extra = {
        "source": "default",
        "config_path": str(config_path),
        **default_result.as_dict(),
    }
    logger.info(TLS_RESOLUTION_FALLBACK_DEFAULT, extra=extra)
    return default_result
