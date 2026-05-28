import ssl
from ssl import SSLContext

import logging

logger = logging.getLogger(__name__)

TLS = "config.tls"
TLS_SYSTEM_STORE_ATTEMPT = f"{TLS}.system_store_attempt"
TLS_SYSTEM_STORE_RESOLVED = f"{TLS}.system_store_resolved"
TLS_SYSTEM_STORE_UNSUPPORTED = f"{TLS}.system_store_unsupported"


def get_system_tls_context() -> SSLContext:
    """
    Get SSL context for system trust store.

    Attempts to use truststore if available, falls back to ssl.create_default_context().

    Returns:
        SSLContext: The SSL context for system trust store.
    """
    logger.debug(TLS_SYSTEM_STORE_ATTEMPT)

    try:
        import truststore  # type: ignore[import-untyped]

        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        logger.debug(TLS_SYSTEM_STORE_RESOLVED, extra={"method": "truststore"})
        return context
    except ImportError:
        logger.debug(
            TLS_SYSTEM_STORE_UNSUPPORTED, extra={"reason": "truststore not available"}
        )
        context = ssl.create_default_context()
        logger.debug(
            TLS_SYSTEM_STORE_RESOLVED, extra={"method": "ssl.create_default_context"}
        )
        return context
