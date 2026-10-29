"""Layer 2a: one-time codes sent out of band (email/SMS style).

The first version stored SHA-256(code). A 6-digit code has a million possible
values, so anyone who gets the store file can brute-force every hash in about
a second. Now the store holds HMAC-SHA256(server_key, username:code). Without
the key, which is not in the database, the stored values are useless.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from .audit import log
from .config import Settings
from .passwords import AuthError
from .store import Store


class OneTimeCodes:
    def __init__(self, store: Store, settings: Settings, clock=time.time):
        self.store = store
        self.s = settings
        self.clock = clock

    def _mac(self, username: str, code: str) -> str:
        msg = f"{username}:{code}".encode("utf-8")
        return hmac.new(self.s.otp_key, msg, hashlib.sha256).hexdigest()

    def issue(self, username: str) -> str:
        code = "".join(secrets.choice("0123456789") for _ in range(self.s.otp_length))
        self.store.run(
            "INSERT OR REPLACE INTO otps (username, code_mac, expires_at, attempts_left) "
            "VALUES (?, ?, ?, ?)",
            username, self._mac(username, code), self.clock() + self.s.otp_ttl_seconds,
            self.s.otp_max_attempts)
        log.info("OTP ISSUED user=%s ttl=%ds", username, self.s.otp_ttl_seconds)
        return code

    def verify(self, username: str, code: str) -> None:
        rec = self.store.one("SELECT * FROM otps WHERE username = ?", username)
        if rec is None:
            raise AuthError("No active code. Start the login again.")
        if self.clock() > rec["expires_at"]:
            self.store.run("DELETE FROM otps WHERE username = ?", username)
            log.warning("OTP EXPIRED user=%s", username)
            raise AuthError("Code expired. Start the login again.")

        if hmac.compare_digest(self._mac(username, code.strip()), rec["code_mac"]):
            self.store.run("DELETE FROM otps WHERE username = ?", username)  # single use
            log.info("OTP OK user=%s", username)
            return

        left = rec["attempts_left"] - 1
        if left <= 0:
            self.store.run("DELETE FROM otps WHERE username = ?", username)
            log.warning("OTP FAILED user=%s, code invalidated", username)
            raise AuthError("Too many wrong codes. Start the login again.")
        self.store.run("UPDATE otps SET attempts_left = ? WHERE username = ?", left, username)
        log.warning("OTP FAILED user=%s, %d attempt(s) left", username, left)
        raise AuthError("Wrong code.")
