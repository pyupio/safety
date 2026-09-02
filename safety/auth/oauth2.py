from __future__ import annotations

import logging
from typing import Any, Literal

from authlib.oauth2.rfc6749 import OAuth2Token
from joserfc.jwt import Token as JWTToken

from safety.config import AuthConfig
from safety.logs_helpers import log_call
from safety.utils.tokens import get_token_claims

logger = logging.getLogger(__name__)


class Token:
    @staticmethod
    def get_claims_for(
        token: str,
        token_type: Literal["access_token", "id_token"],
        jwks: dict[str, Any],
        silent_if_expired: bool = False,
    ) -> JWTToken | None:
        """
        Decode and validate the token data.

        Args:
            token (str): The token to decode.
            token_type: Type of token (access_token or id_token)
            jwks: JSON Web Key Set for validation
            silent_if_expired (bool): Whether to silently ignore expired tokens.

        Returns:
            The decoded joserfc `Token` (payload via `.claims`), or None if invalid.
        """
        return get_token_claims(token, token_type, jwks, silent_if_expired)


@log_call()
def update_token(
    token: OAuth2Token,
    refresh_token: str | None = None,
    access_token: str | None = None,
):
    """
    Saves the refreshed token to the default storage.

    Args:
        token: OAuth2Token - the NEW refreshed token
        refresh_token: str | None - the OLD refresh_token string
        access_token: str | None - the OLD access_token string
    """

    existing = AuthConfig.from_storage()
    if auth_config := AuthConfig.from_token(token=token):
        if existing and existing.org_legacy_uuid:
            auth_config.org_legacy_uuid = existing.org_legacy_uuid
        auth_config.save()
    else:
        raise ValueError("Invalid authentication token.")
