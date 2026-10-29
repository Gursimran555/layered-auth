"""Layer 3: short-lived JWTs with server-side revocation.

Signature and expiry alone can't log anyone out: a stolen token stays valid
until `exp`. Every token's jti is recorded, and validation checks that record,
so revoke() and revoke_all() take effect immediately.
"""

from __future__ import annotations

import time
import uuid

import jwt

from .audit import log
from .config import Settings
from .passwords import AuthError
from .store import Store

REQUIRED_CLAIMS = ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]


class TokenService:
    def __init__(self, store: Store, settings: Settings, clock=time.time):
        self.store = store
        self.s = settings
        self.clock = clock

    def issue(self, username: str) -> str:
        now = int(self.clock())
        jti = str(uuid.uuid4())
        claims = {
            "sub": username, "jti": jti, "iat": now, "nbf": now,
            "exp": now + self.s.token_ttl_seconds,
            "iss": self.s.issuer, "aud": self.s.audience,
        }
        token = jwt.encode(claims, self.s.jwt_secret, algorithm=self.s.jwt_algorithm)
        self.store.run("INSERT INTO tokens (jti, username, issued_at, expires_at) "
                       "VALUES (?, ?, ?, ?)", jti, username, now, claims["exp"])
        log.info("TOKEN ISSUED user=%s jti=%s", username, jti)
        return token

    def _decode(self, token: str, verify_exp: bool = True) -> dict:
        try:
            claims = jwt.decode(
                token, self.s.jwt_secret,
                algorithms=[self.s.jwt_algorithm],      # pinned: no "none", no alg confusion
                audience=self.s.audience, issuer=self.s.issuer,
                # Time claims are checked below against the service clock, so
                # issuing and validating always agree on what "now" is.
                options={"require": REQUIRED_CLAIMS, "verify_exp": False,
                         "verify_nbf": False, "verify_iat": False},
            )
        except jwt.InvalidTokenError as exc:
            log.warning("TOKEN REJECTED %s", type(exc).__name__)
            raise AuthError("Invalid token.") from None
        now = self.clock()
        if claims["nbf"] > now or claims["iat"] > now:
            log.warning("TOKEN REJECTED not yet valid jti=%s", claims["jti"])
            raise AuthError("Invalid token.")
        if verify_exp and now >= claims["exp"]:
            log.warning("TOKEN REJECTED expired jti=%s", claims["jti"])
            raise AuthError("Token expired.")
        return claims

    def validate(self, token: str) -> str:
        claims = self._decode(token)
        rec = self.store.one("SELECT * FROM tokens WHERE jti = ?", claims["jti"])
        if rec is None or rec["username"] != claims["sub"]:
            log.warning("TOKEN REJECTED unknown jti=%s", claims["jti"])
            raise AuthError("Invalid token.")
        if rec["revoked"]:
            log.warning("TOKEN REJECTED revoked jti=%s", claims["jti"])
            raise AuthError("Token revoked.")
        return claims["sub"]

    def revoke(self, token: str) -> None:
        claims = self._decode(token, verify_exp=False)   # signature is still checked
        self.store.run("UPDATE tokens SET revoked = 1 WHERE jti = ?", claims["jti"])
        log.info("TOKEN REVOKED jti=%s", claims["jti"])

    def revoke_all(self, username: str) -> int:
        """'Log out everywhere' - e.g. after a password reset or a suspected compromise."""
        n = self.store.run("UPDATE tokens SET revoked = 1 WHERE username = ? AND revoked = 0",
                           username)
        log.info("TOKENS REVOKED user=%s count=%d", username, n)
        return n

    def purge_expired(self) -> int:
        return self.store.run("DELETE FROM tokens WHERE expires_at < ?", self.clock())
