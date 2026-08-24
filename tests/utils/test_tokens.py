import time

import pytest
from authlib.jose import jwt as authlib_jwt

from safety.utils.tokens import _EXPIRED_TOKEN_ERRORS, get_token_claims

SECRET = "test-secret"


def _make_token(iat_offset: int = 0, exp_offset: int = 3600) -> str:
    now = int(time.time())
    header = {"alg": "HS256"}
    payload = {
        "iss": "https://safetycli.com",
        "sub": "user-123",
        "aud": "safety-cli",
        "exp": now + exp_offset,
        "iat": now + iat_offset,
        "nonce": "n",
    }
    return authlib_jwt.encode(header, payload, SECRET).decode("utf-8")


class TestGetTokenClaims:
    def test_accepts_token_issued_slightly_in_the_future(self):
        # A few seconds of clock skew between the client and the token
        # issuer is normal and shouldn't reject an otherwise valid token.
        token = _make_token(iat_offset=5)
        claims = get_token_claims(token, "id_token", SECRET)
        assert claims is not None
        assert claims["sub"] == "user-123"

    def test_rejects_token_issued_far_in_the_future(self):
        token = _make_token(iat_offset=600)
        with pytest.raises(Exception, match="future"):
            get_token_claims(token, "id_token", SECRET)

    def test_silent_if_expired_swallows_an_expired_token(self):
        # Decoding still succeeds; only the raised validation error is
        # swallowed, so the (unvalidated) claims are still returned.
        token = _make_token(iat_offset=-7200, exp_offset=-3600)
        claims = get_token_claims(
            token, "access_token", SECRET, silent_if_expired=True
        )
        assert claims is not None
        assert claims["sub"] == "user-123"

    def test_expired_token_raises_by_default(self):
        token = _make_token(iat_offset=-7200, exp_offset=-3600)
        with pytest.raises(_EXPIRED_TOKEN_ERRORS):
            get_token_claims(token, "access_token", SECRET)
