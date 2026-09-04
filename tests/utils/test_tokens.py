"""
Unit tests for safety.utils.tokens.get_token_claims().

These exercise the real joserfc decode path rather than mocking it, so a
regression in the per-call JWTClaimsRegistry or the expiry branch is caught.
"""

from __future__ import annotations

import time
import warnings
from typing import Any

import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.errors import (
    ExpiredTokenError,
    MissingClaimError,
    UnsupportedAlgorithmError,
)
from joserfc.jwk import OctKey, RSAKey

from safety.utils.tokens import get_token_claims

_HEADER = {"alg": "RS256", "kid": "test-kid"}


def _key_and_jwks() -> tuple[RSAKey, dict[str, Any]]:
    key = RSAKey.generate_key(2048, parameters={"kid": "test-kid"})
    return key, {"keys": [key.as_dict(private=False)]}


def _sign(key: RSAKey, claims: dict[str, Any]) -> str:
    return joserfc_jwt.encode(_HEADER, claims, key)


def _claims(**overrides: Any) -> dict[str, Any]:
    """A complete claim set, shaped like what the IdP actually issues.

    get_token_claims requires the OIDC registered claims, so a test about
    something else (expiry, algorithm) still has to hand over a full set or
    it fails for the wrong reason.
    """
    now = int(time.time())
    return {
        "iss": "https://auth.safetycli.com/",
        "sub": "user-1",
        "aud": "safety-cli",
        "iat": now,
        "exp": now + 3600,
        **overrides,
    }


def test_valid_token_returns_claims() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, _claims(org="acme"))

    decoded = get_token_claims(token, "id_token", jwks)

    assert decoded is not None
    assert decoded.claims["sub"] == "user-1"
    assert decoded.claims["org"] == "acme"


def test_expired_token_raises_when_not_silent() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, _claims(exp=int(time.time()) - 10))

    # A JWTClaimsRegistry is constructed per call, so it reads the clock at
    # validate time and an already-expired token is rejected.
    with pytest.raises(ExpiredTokenError):
        get_token_claims(token, "id_token", jwks, silent_if_expired=False)


def test_expired_token_returns_claims_when_silent() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, _claims(exp=int(time.time()) - 10))

    decoded = get_token_claims(token, "id_token", jwks, silent_if_expired=True)

    assert decoded is not None
    assert decoded.claims["sub"] == "user-1"


def test_invalid_token_type_raises_value_error() -> None:
    key, jwks = _key_and_jwks()
    token = _sign(key, _claims())

    with pytest.raises(ValueError):
        get_token_claims(token, "bogus", jwks)  # type: ignore[arg-type]


def test_alg_confusion_hs256_is_rejected() -> None:
    # Forge an HS256 token whose HMAC secret is the RSA public key from the
    # JWKS. Without the algorithm allowlist joserfc would verify it; the
    # allowlist refuses the disallowed alg before any key is used.
    key, jwks = _key_and_jwks()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # joserfc warns on RSA-PEM-as-oct-key
        forged = joserfc_jwt.encode(
            {"alg": "HS256", "kid": "test-kid"},
            _claims(sub="attacker"),
            OctKey.import_key(key.as_pem(private=False)),
        )

    with pytest.raises(UnsupportedAlgorithmError):
        get_token_claims(forged, "id_token", jwks)


@pytest.mark.parametrize("missing", ["iss", "sub", "aud", "iat", "exp"])
def test_missing_registered_claim_is_rejected(missing: str) -> None:
    """A correctly signed token still has to carry the registered claims.

    A signature only proves who wrote the token, not that it says what we
    need it to say. Dropping "exp" is the sharp case: with no expiry claim
    there is nothing for the expiry check to compare against, so the token
    would be accepted forever.
    """
    key, jwks = _key_and_jwks()
    claims = _claims()
    del claims[missing]
    token = _sign(key, claims)

    with pytest.raises(MissingClaimError):
        get_token_claims(token, "id_token", jwks)


def test_missing_claim_is_not_silenced_by_silent_if_expired() -> None:
    """silent_if_expired only forgives expiry, never an incomplete token."""
    key, jwks = _key_and_jwks()
    claims = _claims()
    del claims["exp"]
    token = _sign(key, claims)

    with pytest.raises(MissingClaimError):
        get_token_claims(token, "id_token", jwks, silent_if_expired=True)
