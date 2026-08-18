"""
Unit tests for safety.utils.tokens.get_token_claims().

These exercise the real joserfc decode path rather than mocking it, so a
regression in the reused JWTClaimsRegistry or the expiry branch is caught.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.errors import ExpiredTokenError
from joserfc.jwk import RSAKey

from safety.utils.tokens import get_token_claims

_HEADER = {"alg": "RS256", "kid": "test-kid"}


def _key_and_jwks() -> tuple[RSAKey, dict[str, Any]]:
    key = RSAKey.generate_key(2048, parameters={"kid": "test-kid"})
    return key, {"keys": [key.as_dict(private=False)]}


def _sign(key: RSAKey, claims: dict[str, Any]) -> str:
    return joserfc_jwt.encode(_HEADER, claims, key)


def test_valid_token_returns_claims() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, {"sub": "user-1", "org": "acme", "exp": int(time.time()) + 3600})

    claims = get_token_claims(token, "id_token", jwks)

    assert claims is not None
    assert claims["sub"] == "user-1"
    assert claims["org"] == "acme"


def test_expired_token_raises_when_not_silent() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, {"sub": "user-1", "exp": int(time.time()) - 10})

    # Guards the reused-registry behavior: the module-level JWTClaimsRegistry
    # must read the clock per call, so an already-expired token is rejected.
    with pytest.raises(ExpiredTokenError):
        get_token_claims(token, "id_token", jwks, silent_if_expired=False)


def test_expired_token_returns_claims_when_silent() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, {"sub": "user-1", "exp": int(time.time()) - 10})

    claims = get_token_claims(token, "id_token", jwks, silent_if_expired=True)

    assert claims is not None
    assert claims["sub"] == "user-1"


def test_invalid_token_type_raises_value_error() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, {"sub": "user-1", "exp": int(time.time()) + 3600})

    with pytest.raises(ValueError):
        get_token_claims(token, "bogus", jwks)  # type: ignore[arg-type]
