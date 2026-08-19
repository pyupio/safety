"""
Token validation utilities shared across the application.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from joserfc import jwt
from joserfc.errors import ExpiredTokenError
from joserfc.jwk import KeySet

logger = logging.getLogger(__name__)

# Pin decoding to the asymmetric algorithms our IdP advertises (RS256 today,
# PS256 if it rotates) and deliberately exclude the symmetric HS* family. This
# blocks the HS* alg-confusion path (a token that HMAC-signs itself with the
# JWKS public key) even if a symmetric key is ever added to the JWKS.
_ALLOWED_ALGORITHMS = ["RS256", "PS256"]


def get_token_claims(
    token: str,
    token_type: Literal["access_token", "id_token"],
    jwks: dict[str, Any],
    silent_if_expired: bool = False,
) -> dict[str, Any] | None:
    """
    Decode and validate token claims.

    Args:
        token: The token to decode
        token_type: Type of token (access_token or id_token)
        jwks: JSON Web Key Set for validation
        silent_if_expired: If True, suppress ExpiredTokenError and still
            return the decoded claims (callers may need fields like
            `exp` or custom claims from an expired token).

    Returns:
        Decoded token claims as a dict, or None if decoding failed.
        When `silent_if_expired` is True and the token is expired,
        the claims are still returned.

    Raises:
        ValueError: If token_type is invalid
        ExpiredTokenError: If token is expired and silent_if_expired is False
    """
    if token_type not in ("access_token", "id_token"):
        raise ValueError(f"Invalid token_type: {token_type}")

    claims = None

    try:
        key_set = KeySet.import_key_set(jwks)  # type: ignore
        token_obj = jwt.decode(token, key_set, algorithms=_ALLOWED_ALGORITHMS)
        claims = token_obj.claims
        jwt.JWTClaimsRegistry().validate(claims)
    except ExpiredTokenError:
        if not silent_if_expired:
            raise

    return claims
