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


def _required_claims_registry() -> jwt.JWTClaimsRegistry:
    """A registry that requires the registered claims to be present.

    JWTClaimsRegistry requires nothing by default and validates only the
    claims a token happens to carry. Without this a signature-valid token
    with no "exp" has nothing for the expiry check to compare against, so it
    never fails and is accepted forever. These are the claims authlib's
    CodeIDToken required before the joserfc migration, applied to both token
    types as it was then, so this is the contract 3.8.1 shipped with.
    """
    return jwt.JWTClaimsRegistry(
        iss={"essential": True},
        sub={"essential": True},
        aud={"essential": True},
        iat={"essential": True},
        exp={"essential": True},
    )


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
        MissingClaimError: If the token omits a registered claim. This is
            never silenced; silent_if_expired only forgives expiry.
        ExpiredTokenError: If token is expired and silent_if_expired is False
    """
    if token_type not in ("access_token", "id_token"):
        raise ValueError(f"Invalid token_type: {token_type}")

    decoded = None

    try:
        key_set = KeySet.import_key_set(jwks)  # type: ignore
        decoded = jwt.decode(token, key_set, algorithms=_ALLOWED_ALGORITHMS)
        _required_claims_registry().validate(decoded.claims)
    except ExpiredTokenError:
        if not silent_if_expired:
            raise

    return decoded
