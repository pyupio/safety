"""
Authentication subsystem for the Safety CLI.

Provides OAuth2-based login/logout via Auth0, machine-token enrollment
for MDM scenarios, and session management. The main entry points are:

  - ``cli`` — Typer sub-command (``safety auth login | logout | status``)
  - ``cli_utils`` — Click option decorators (``--key``, proxy settings)
  - ``main`` — Core auth flow orchestration (login, logout, callback handling)
  - ``oauth2`` — OAuth2 client wrapper (token refresh, revocation)
  - ``models`` — Auth/OAuth data models (Token, Organization, Auth)
  - ``server`` — Local HTTP server for OAuth2 callback redirect
  - ``enrollment`` — Machine enrollment flow (MDM)
"""

from .cli_utils import auth_options, proxy_options, configure_auth_session
from .cli import auth


__all__ = [
    "proxy_options",
    "auth_options",
    "configure_auth_session",
    "auth",
]
