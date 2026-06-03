"""
Configuration management for Safety CLI.

Manages authentication config (``auth.ini``), proxy settings, and TLS
configuration. Config files are stored in ``~/.safety/`` (user) and
``/etc/.safety/`` (system).

  - ``auth`` — AuthConfig model (OAuth tokens, API keys, machine credentials)
  - ``proxy`` — Proxy configuration resolution (HTTP/HTTPS proxies)
  - ``tls`` — TLS/SSL certificate configuration
"""

from .auth import AuthConfig, MachineCredentialConfig
from .proxy import get_proxy_config
from .tls import get_tls_config
from .main import AUTH_CONFIG_USER

__all__ = [
    "AuthConfig",
    "MachineCredentialConfig",
    "get_proxy_config",
    "get_tls_config",
    "AUTH_CONFIG_USER",
]
