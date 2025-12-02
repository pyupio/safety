"""
Token validation utilities shared across the application.
"""

from typing import Any, Dict, Literal, Optional
import logging

from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from authlib.jose.errors import ExpiredTokenError


logger = logging.getLogger(__name__)


def get_token_claims(
    token: str,
    token_type: Literal["access_token", "id_token"],
    jwks: Dict[str, Any],
    silent_if_expired: bool = False,
) -> Optional[CodeIDToken]:
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
        claims = jwt.decode(token, jwks, claims_cls=CodeIDToken)  # type: ignore
        claims.validate()

    except ExpiredTokenError as e:
        if not silent_if_expired:
            raise e

    return claims
