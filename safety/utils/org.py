"""
Organization resolution utilities.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from safety.config.auth import MachineCredentialConfig
from safety.utils.auth_session import AuthenticationType

if TYPE_CHECKING:
    from safety.auth.models import Auth

logger = logging.getLogger(__name__)


def resolve_org_slug(auth: Auth | None) -> str | None:
    """
    Resolve the organization slug from the given auth object.

    - MDM (machine_token): reads org_slug from stored machine credentials.
    - API Key / OAuth2: calls platform.initialize() to fetch org data.

    Args:
        auth: The Auth object from ctx.obj.auth (or None).

    Returns:
        The org slug string, or None if auth is missing or org_slug
        cannot be determined.
    """
    if not auth or not auth.platform.is_using_auth_credentials():
        return None

    auth_type = auth.platform.get_authentication_type()

    if auth_type == AuthenticationType.machine_token:
        machine_creds = MachineCredentialConfig.from_storage()
        if machine_creds and machine_creds.org_slug:
            return machine_creds.org_slug
        return None

    # API Key or OAuth2: resolve from platform
    try:
        data = auth.platform.initialize()
        return data.get("organization-data", {}).get("slug")
    except Exception:
        logger.debug("Failed to resolve org_slug from platform.initialize()")
        return None
