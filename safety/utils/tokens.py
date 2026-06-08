"""
Token validation utilities shared across the application.
"""

from typing import Any, Dict, Literal, Optional
import logging

from joserfc import jwt
from joserfc.errors import ExpiredTokenError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry


logger = logging.getLogger(__name__)

_CLAIMS_REGISTRY = JWTClaimsRegistry(
    iss={"essential": True},
    sub={"essential": True},
    aud={"essential": True},
    exp={"essential": True},
    iat={"essential": True},
)


def get_token_claims(
    token: str,
    token_type: Literal["access_token", "id_token"],
    jwks: Dict[str, Any],
    silent_if_expired: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Decode and validate token claims.

    Args:
        token: The token to decode
        token_type: Type of token (access_token or id_token)
        jwks: JSON Web Key Set for validation
        silent_if_expired: Whether to silently ignore expired tokens

    Returns:
        Decoded token claims, or None if invalid

    Raises:
        ValueError: If token_type is invalid
        ExpiredTokenError: If token is expired and silent_if_expired is False
    """
    if token_type not in ("access_token", "id_token"):
        raise ValueError(f"Invalid token_type: {token_type}")

    claims = None

    try:
        key_set = KeySet.import_key_set(jwks)
        token_obj = jwt.decode(token, key_set)
        claims = token_obj.claims
        _CLAIMS_REGISTRY.validate(claims)
    except ExpiredTokenError as e:
        if not silent_if_expired:
            raise e

    return claims
