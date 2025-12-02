"""
Authentication session management utilities.
"""

from enum import Enum

from typing import TYPE_CHECKING
from safety.config import AuthConfig

from safety_schemas.models import Stage

if TYPE_CHECKING:
    from authlib.integrations.httpx_client import OAuth2Client


def discard_token(oauth2_client: "OAuth2Client") -> bool:
    """
    Clean the authentication session.

    Args:
        oauth2_client: The authentication client.

    Returns:
        bool: Always returns True.
    """

    AuthConfig.clear()
    oauth2_client.token = None

    return True


class AuthenticationType(str, Enum):
    """
    Enum representing authentication types.
    """

    token = "token"
    api_key = "api_key"
    none = "unauthenticated"

    def is_allowed_in(self, stage: Stage = Stage.development) -> bool:
        """
        Check if the authentication type is allowed in the given stage.

        Args:
            stage (Stage): The current stage.

        Returns:
            bool: True if the authentication type is allowed, otherwise False.
        """
        if self is AuthenticationType.none:
            return False

        if stage == Stage.development and self is AuthenticationType.api_key:
            return False

        if (not stage == Stage.development) and self is AuthenticationType.token:
            return False

        return True
