"""
Log codes for configuration-related operations.
"""

CONFIG = "config"

# Proxy Configuration
PROXY = f"{CONFIG}.proxy"
PROXY_RESOLVED = f"{PROXY}.resolved"
PROXY_NOT_DEFINED = f"{PROXY}.not_defined"
PROXY_HOST_EMPTY = f"{PROXY}.host_empty"
PROXY_PROTOCOL_INVALID = f"{PROXY}.invalid_protocol"
PROXY_CONFIG_MISSING_SECTION = f"{PROXY}.missing_section"

# TLS Configuration
TLS = f"{CONFIG}.tls"
TLS_RESOLVED = f"{TLS}.resolved"
TLS_RESOLUTION_FALLBACK_DEFAULT = f"{TLS}.resolution_fallback_default"
TLS_CA_BUNDLE_RESOLVED = f"{TLS}.ca_bundle_resolved"
