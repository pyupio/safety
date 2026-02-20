"""Shared TLS fallback orchestration and probe utility.

Provides ``with_tls_fallback`` — a callback-based orchestrator that
retries an action with the system trust store when certifi fails — and
``probe_tls_connectivity`` — a lightweight HEAD-based convenience
wrapper for paths that only need to validate TLS (e.g. machine-token).
"""

from __future__ import annotations

import logging
from configparser import ConfigParser
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional

import httpx
from filelock import FileLock

from safety.config import get_tls_config
from safety.constants import CONFIG
from safety.errors import SSLCertificateError

if TYPE_CHECKING:
    from safety.config.proxy import ProxyConfig
    from safety.config.tls import TLSConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TLSProbeResult:
    """Result of a TLS connectivity probe.

    Attributes:
        tls_config: The TLS configuration that was ultimately used (may
            differ from the input if a fallback occurred).
        fell_back: ``True`` when the probe switched from ``mode='default'``
            to ``mode='system'`` to work around a certificate error.
    """

    tls_config: TLSConfig
    fell_back: bool


def with_tls_fallback(
    action: Callable[[TLSConfig], None],
    tls_config: TLSConfig,
    save_preference: bool = True,
) -> TLSProbeResult:
    """Execute *action* with automatic certifi -> system trust store fallback.

    Calls ``action(tls_config)``.  On :class:`SSLCertificateError` **and**
    ``tls_config.mode == "default"`` the action is retried with
    ``mode='system'`` (system trust store).  If ``save_preference`` is true
    the successful fallback is persisted to ``config.ini``.

    This is the shared fallback orchestrator.  Callers supply a callback
    that performs the actual network I/O so the same retry logic works for
    any request type (e.g. the lightweight HEAD probe used by
    :func:`probe_tls_connectivity`).

    Args:
        action: Callable that takes a :class:`TLSConfig` and performs a
            network request.  It should raise :class:`SSLCertificateError`
            on certificate failures and propagate other errors as-is.
        tls_config: Current TLS configuration to try first.
        save_preference: Whether to persist a successful fallback to
            ``config.ini``.

    Returns:
        A :class:`TLSProbeResult` with the effective TLS configuration and
        whether a fallback occurred.

    Raises:
        SSLCertificateError: If TLS fails and no fallback is available
            (mode is not ``"default"``), or fallback also fails.
        Exception: Non-TLS errors propagate as-is from *action*.
    """
    try:
        action(tls_config)
        logger.debug("TLS action succeeded on first attempt")
        return TLSProbeResult(tls_config=tls_config, fell_back=False)
    except SSLCertificateError as first_error:
        if tls_config.mode != "default":
            logger.error(
                "TLS action failed with mode=%r; no fallback available",
                tls_config.mode,
            )
            raise

        logger.warning(
            "TLS action failed with default (certifi) trust store; "
            "retrying with system trust store"
        )
        system_tls = get_tls_config(mode="system")
        try:
            action(system_tls)
        except Exception as fallback_error:
            logger.error("TLS action failed after fallback: %s", fallback_error)
            raise SSLCertificateError(
                "TLS probe failed: primary={}, fallback={}".format(
                    first_error, fallback_error
                )
            ) from first_error

        if save_preference:
            _save_tls_fallback_preference()

        logger.info("TLS action succeeded after fallback to system trust store")
        return TLSProbeResult(tls_config=system_tls, fell_back=True)


def probe_tls_connectivity(
    probe_url: str,
    tls_config: TLSConfig,
    proxy_config: Optional[ProxyConfig] = None,
    timeout: float = 10.0,
    save_preference: bool = True,
) -> TLSProbeResult:
    """Probe *probe_url* with a HEAD request to verify TLS works.

    Convenience wrapper around :func:`with_tls_fallback` using a
    lightweight HEAD request as the action.  Use this when you only
    need to validate TLS connectivity (e.g. machine-token path) and
    don't need the response body.

    Args:
        probe_url: URL to send an HTTP HEAD request to.  Any HTTP response
            (even 404) means TLS succeeded.
        tls_config: Current TLS configuration to try first.
        proxy_config: Optional proxy settings forwarded to the probe client.
        timeout: Timeout in seconds for the HEAD request.
        save_preference: Whether to persist a successful fallback to
            ``config.ini``.

    Returns:
        A :class:`TLSProbeResult` with the effective TLS configuration and
        whether a fallback occurred.

    Raises:
        SSLCertificateError: If TLS fails and no fallback is available
            (mode is not ``"default"``), or fallback also fails.
        Exception: Non-TLS errors (DNS, timeout, refused) propagate as-is.
    """
    return with_tls_fallback(
        action=lambda tls: _do_tls_probe(probe_url, tls, proxy_config, timeout),
        tls_config=tls_config,
        save_preference=save_preference,
    )


def _do_tls_probe(
    url: str,
    tls_config: TLSConfig,
    proxy_config: Optional[ProxyConfig],
    timeout: float,
) -> None:
    """Send a HEAD request to *url* to exercise the TLS handshake.

    Any HTTP response (even 4xx/5xx) means TLS succeeded.  Only
    certificate-related ``ConnectError``s are converted to
    :class:`SSLCertificateError`.
    """
    client_kwargs: dict = {
        "verify": tls_config.verify_context,
        "timeout": httpx.Timeout(timeout),
        "trust_env": False,
    }
    if proxy_config:
        client_kwargs["proxy"] = proxy_config.endpoint.as_url()

    try:
        with httpx.Client(**client_kwargs) as client:
            client.head(url)
    except httpx.ConnectError as exc:
        # Lazy import to avoid circular dependency:
        # tls_probe -> platform.http_utils -> (platform.__init__ -> platform.client) -> tls_probe
        from safety.platform.http_utils import is_ca_certificate_error

        if is_ca_certificate_error(exc):
            raise SSLCertificateError() from exc
        raise


def _save_tls_fallback_preference() -> None:
    """Persist ``mode=system`` to the ``[tls]`` section of ``config.ini``."""
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)

        lock = FileLock(str(CONFIG) + ".lock", timeout=10)

        with lock:
            config = ConfigParser()
            config.read(CONFIG)

            if not config.has_section("tls"):
                config.add_section("tls")

            config.set("tls", "mode", "system")

            with open(CONFIG, "w") as configfile:
                config.write(configfile)

        logger.info(
            "Saved system trust store preference to config",
            extra={"config_path": str(CONFIG)},
        )
    except Exception as e:
        logger.warning(
            "Failed to save TLS fallback preference",
            extra={"config_path": str(CONFIG), "error": str(e)},
        )
