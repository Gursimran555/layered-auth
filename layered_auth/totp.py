"""Layer 2b: TOTP (RFC 6238), the codes from Google Authenticator / Authy / 1Password.

Written from the RFC with only the standard library, and checked against the
RFC's own test vectors in tests/test_totp.py. A code is accepted for the
current 30-second step and one step either side for clock drift, and each step
can only be used once, so a shoulder-surfed code can't be replayed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from .audit import log
from .passwords import AuthError
from .store import Store

STEP = 30
DIGITS = 6
WINDOW = 1


def generate_secret() -> str:
    """160-bit secret, base32 without padding, as authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret_b32: str) -> bytes:
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    return base64.b32decode(padded)


def hotp(key: bytes, counter: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    """RFC 4226 section 5.3."""
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def totp(secret_b32: str, at: float, digits: int = DIGITS) -> str:
    return hotp(_key(secret_b32), int(at // STEP), digits)


def provisioning_uri(secret_b32: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


class TotpFactor:
    def __init__(self, store: Store, issuer: str, clock=time.time):
        self.store = store
        self.issuer = issuer
        self.clock = clock

    def begin_enrollment(self, username: str) -> tuple[str, str]:
        secret = generate_secret()
        self.store.run("INSERT OR REPLACE INTO totp (username, secret, active, last_step) "
                       "VALUES (?, ?, 0, -1)", username, secret)
        return secret, provisioning_uri(secret, username, self.issuer)

    def is_active(self, username: str) -> bool:
        row = self.store.one("SELECT active FROM totp WHERE username = ?", username)
        return bool(row and row["active"])

    def _match_step(self, secret: str, code: str) -> int | None:
        now_step = int(self.clock() // STEP)
        for step in range(now_step - WINDOW, now_step + WINDOW + 1):
            if hmac.compare_digest(hotp(_key(secret), step), code):
                return step
        return None

    def confirm_enrollment(self, username: str, code: str) -> None:
        """The user proves the app is set up before TOTP becomes required."""
        row = self.store.one("SELECT * FROM totp WHERE username = ?", username)
        if row is None:
            raise AuthError("No TOTP enrollment in progress.")
        step = self._match_step(row["secret"], code.strip())
        if step is None:
            raise AuthError("Wrong code.")
        self.store.run("UPDATE totp SET active = 1, last_step = ? WHERE username = ?",
                       step, username)
        log.info("TOTP ENROLLED user=%s", username)

    def verify(self, username: str, code: str) -> None:
        row = self.store.one("SELECT * FROM totp WHERE username = ? AND active = 1", username)
        if row is None:
            raise AuthError("TOTP is not set up for this account.")
        step = self._match_step(row["secret"], code.strip())
        if step is None:
            log.warning("TOTP FAILED user=%s", username)
            raise AuthError("Wrong code.")
        # Replay protection: only steps newer than the last accepted one.
        updated = self.store.run("UPDATE totp SET last_step = ? WHERE username = ? "
                                 "AND last_step < ?", step, username, step)
        if not updated:
            log.warning("TOTP REPLAY user=%s step=%d", username, step)
            raise AuthError("That code was already used. Wait for the next one.")
        log.info("TOTP OK user=%s", username)
