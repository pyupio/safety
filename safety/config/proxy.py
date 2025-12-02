from typing import NamedTuple, Optional, Union
from pathlib import Path
from safety.constants import CONFIG
from .log_codes import (
    PROXY_RESOLVED,
    PROXY_NOT_DEFINED,
    PROXY_HOST_EMPTY,
    PROXY_PROTOCOL_INVALID,
    PROXY_CONFIG_MISSING_SECTION,
)

import configparser

import logging

logger = logging.getLogger(__name__)


DEFAULT_PROXY_PORT: int = 80
DEFAULT_PROXY_SCHEME: str = "http"
PROXY_ALLOWED_PROTOCOLS = ("http", "https")

PROXY_PROTOCOL_KEY = "protocol"
PROXY_HOST_KEY = "host"
PROXY_PORT_KEY = "port"


class ProxyEndpoint(NamedTuple):
    scheme: str
    host: str
    port: int

    def as_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def as_dict(self) -> dict[str, Union[str, int]]:
        return {
            PROXY_PROTOCOL_KEY: self.scheme,
            PROXY_HOST_KEY: self.host,
            PROXY_PORT_KEY: str(self.port),
        }


class ProxyConfig(NamedTuple):
    endpoint: ProxyEndpoint

    def as_dict(self) -> dict[str, Union[str, int]]:
        return self.endpoint.as_dict()


def _should_build_proxy_config(
    host: Optional[str],
    *other_values,
    source: str,
) -> bool:
    """
    Return True if the proxy config should be built, False otherwise.

    Args:
        host (Optional[str]): The proxy host.
        *other_values: Other values that may be provided.
        source (str): The source of the values.

    Returns:
        bool: True if the proxy config should be built, False otherwise.
    """

    if not host or not host.strip():
        if any(v is not None for v in other_values):
            raise ValueError(
                f"Proxy host must be provided when using other proxy options in {source}."
            )
        return False

    return True


def _build_proxy_config(
    host: str,
    port: Optional[int],
    scheme: Optional[str],
    source: str = "unknown",
) -> ProxyConfig:
    if not host or not host.strip():
        logger.error(PROXY_HOST_EMPTY, extra={"source": source})
        raise ValueError("Proxy host must not be empty")

    host = host.strip()

    scheme = (scheme or DEFAULT_PROXY_SCHEME).lower()
    if scheme not in PROXY_ALLOWED_PROTOCOLS:
        logger.error(
            PROXY_PROTOCOL_INVALID, extra={"protocol": scheme, "source": source}
        )
        raise ValueError(f"Invalid proxy protocol: {scheme!r}")

    port = port or DEFAULT_PROXY_PORT

    endpoint = ProxyEndpoint(
        scheme=scheme,
        host=host,
        port=port,
    )

    return ProxyConfig(endpoint=endpoint)


def _proxy_from_config_ini(config_path: Path) -> Optional[ProxyConfig]:
    """
    Retrieve the proxy configuration from the config.ini file.

    Args:
        config_path (Path): The path to the config.ini file.

    Returns:
        Optional[ProxyConfig]: The proxy configuration, or None if not found.
    """
    PROXY_SECTION_NAME = "proxy"

    config = configparser.ConfigParser()
    filenames = [config_path]
    config_files = config.read(filenames=filenames)

    if not config_files or not config.has_section(PROXY_SECTION_NAME):
        if config_files:
            logger.debug(
                PROXY_CONFIG_MISSING_SECTION, extra={"config_path": str(config_path)}
            )
        return None

    section = config[PROXY_SECTION_NAME]

    # raw values
    scheme_raw = section.get(PROXY_PROTOCOL_KEY, None)
    host_raw = section.get(PROXY_HOST_KEY, None)
    port_raw = section.getint(PROXY_PORT_KEY, fallback=None)

    if not _should_build_proxy_config(host_raw, port_raw, scheme_raw, source="config"):
        return None

    if not host_raw:
        raise ValueError("Proxy host must not be empty")

    return _build_proxy_config(
        host=host_raw,
        port=port_raw,
        scheme=scheme_raw,
        source="config",
    )


def _proxy_from_cli_options(
    host: Optional[str] = None,
    port: Optional[str] = None,
    scheme: Optional[str] = None,
) -> Optional[ProxyConfig]:
    """
    Retrieve the proxy configuration from the command-line options.

    Args:
        host (Optional[str]): The proxy host.
        port (Optional[str]): The proxy port.
        scheme (Optional[str]): The proxy scheme (http or https).

    Returns:
        Optional[ProxyConfig]: The proxy configuration, or None if not found.
    """
    # The user touched proxy options but forgot to provide the host
    if not _should_build_proxy_config(host, port, scheme, source="CLI"):
        return None

    if not host:
        raise ValueError("Proxy host must not be empty")

    port_val = None

    if port:
        try:
            port_val = int(port)
        except ValueError:
            raise ValueError("Proxy port must be an integer")

    return _build_proxy_config(
        host=host,
        port=port_val,
        scheme=scheme,
        source="CLI",
    )


def get_proxy_config(
    host: Optional[str] = None,
    port: Optional[str] = None,
    scheme: Optional[str] = None,
    config_path: Path = CONFIG,
) -> Optional[ProxyConfig]:
    """
    Resolve the effective proxy configuration.

    Resolution order (first non-None wins):
      1. Command-line options
      2. config.ini file
      3. No proxy (returns None)

    Args:
        host (Optional[str]): The proxy host from CLI options.
        port (Optional[str]): The proxy port from CLI options.
        scheme (Optional[str]): The proxy scheme (http or https) from CLI options.
        config_path (Path): The path to the config.ini file.

    Returns:
        Optional[ProxyConfig]: The proxy configuration, or None if not found.

    Raises:
        ValueError: If the proxy configuration is invalid.
    """
    sources = [
        (
            "cli",
            lambda: _proxy_from_cli_options(
                host=host,
                port=port,
                scheme=scheme,
            ),
        ),
        ("config", lambda: _proxy_from_config_ini(config_path=config_path)),
    ]

    for source_name, source_func in sources:
        result = source_func()
        if result is not None:
            extra = {"source": source_name, **result.as_dict()}
            if source_name == "config":
                extra["config_path"] = str(config_path)
            logger.info(PROXY_RESOLVED, extra=extra)
            return result

    logger.info(
        PROXY_NOT_DEFINED,
        extra={"config_path": str(config_path)},
    )
    return None
