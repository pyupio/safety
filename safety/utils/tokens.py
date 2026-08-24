"""
Token validation utilities shared across the application.
"""

from typing import Any, Dict, Literal, Optional, Tuple, Type
import logging

from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from authlib.jose.errors import ExpiredTokenError

# Authlib >= 1.7 implements authlib.jose on top of joserfc and lets
# joserfc's own exceptions propagate instead of the authlib.jose ones,
# so ExpiredTokenError alone no longer catches an expired token on those
# versions. joserfc is a transitive dependency there, but not on older
# authlib releases, so only rely on it when it's actually importable.
try:
    from joserfc.errors import ExpiredTokenError as JoseRFCExpiredTokenError

    _EXPIRED_TOKEN_ERRORS: Tuple[Type[Exception], ...] = (
        ExpiredTokenError,
        JoseRFCExpiredTokenError,
    )
except ImportError:  # pragma: no cover - depends on installed authlib version
    _EXPIRED_TOKEN_ERRORS = (ExpiredTokenError,)

# Tolerance, in seconds, for clock skew between this machine and the token
# issuer when validating iat/exp/nbf. Matches the leeway authlib's own
# OAuth client integrations (Flask, Django, httpx) apply by default.
TOKEN_LEEWAY_SECONDS = 60

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
        claims.validate(leeway=TOKEN_LEEWAY_SECONDS)
    except _EXPIRED_TOKEN_ERRORS as e:
        if not silent_if_expired:
            raise e

    return claims
