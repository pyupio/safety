"""
Token validation utilities shared across the application.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from joserfc import jwt
from joserfc.errors import ExpiredTokenError
from joserfc.jwk import KeySet
from joserfc.jwt import Token as JWTToken

logger = logging.getLogger(__name__)

# Pin decoding to the asymmetric algorithms our IdP advertises (RS256 today,
# PS256 if it rotates) and deliberately exclude the symmetric HS* family. This
# blocks the HS* alg-confusion path (a token that HMAC-signs itself with the
# JWKS public key) even if a symmetric key is ever added to the JWKS.
_ALLOWED_ALGORITHMS = ["RS256", "PS256"]

# Tolerance, in seconds, for clock skew between this machine and the token
# issuer when validating iat/exp/nbf. Without this, a token issued even a
# few seconds ago can fail validation as "issued in the future" on a
# machine whose clock is slightly behind the issuer's.
_CLAIMS_LEEWAY_SECONDS = 60


def get_token_claims(
    token: str,
    token_type: Literal["access_token", "id_token"],
    jwks: dict[str, Any],
    silent_if_expired: bool = False,
) -> JWTToken | None:
    """
    Decode and validate a token.

    Args:
        token: The token to decode
        token_type: Type of token (access_token or id_token)
        jwks: JSON Web Key Set for validation
        silent_if_expired: If True, suppress ExpiredTokenError and still
            return the decoded token (callers may need fields like `exp`
            or custom claims, read via `.claims`, from an expired token).

    Returns:
        The decoded joserfc `Token` (its `.claims` holds the payload), or
        None if decoding failed. When `silent_if_expired` is True and the
        token is expired, the decoded token is still returned.

    Raises:
        ValueError: If token_type is invalid
        ExpiredTokenError: If token is expired and silent_if_expired is False
    """
    if token_type not in ("access_token", "id_token"):
        raise ValueError(f"Invalid token_type: {token_type}")

    decoded = None

    try:
        key_set = KeySet.import_key_set(jwks)  # type: ignore
        decoded = jwt.decode(token, key_set, algorithms=_ALLOWED_ALGORITHMS)
        jwt.JWTClaimsRegistry(leeway=_CLAIMS_LEEWAY_SECONDS).validate(decoded.claims)
    except ExpiredTokenError:
        if not silent_if_expired:
            raise

    return decoded
