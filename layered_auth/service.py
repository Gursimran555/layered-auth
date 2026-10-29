"""Ties the three layers into one login flow.

    start_login(username, password)  -> Challenge   (password checked here)
    complete_login(challenge_id, code) -> token     (second factor checked here)

The challenge id is what links the two steps. In the first version, the OTP
step didn't know whether the password step had happened at all. Now a second
factor is only accepted against a live challenge that a correct password
created, and the challenge is consumed on use.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Callable

from .audit import log
from .config import Settings
from .otp import OneTimeCodes
from .passwords import AuthError, PasswordAuth
from .store import Store
from .tokens import TokenService
from .totp import TotpFactor


@dataclass
class Challenge:
    id: str
    method: str          # "totp" or "otp"
    expires_at: float


def print_delivery(username: str, code: str) -> None:
    """Stand-in for an email/SMS sender."""
    print(f"[out-of-band] code for {username}: {code}")


class AuthService:
    def __init__(self, settings: Settings, clock=time.time,
                 deliver: Callable[[str, str], None] = print_delivery,
                 equalize_timing: bool = True):
        self.s = settings
        self.clock = clock
        self.store = Store(settings.db_path)
        self.passwords = PasswordAuth(self.store, settings, clock, equalize_timing)
        self.otp = OneTimeCodes(self.store, settings, clock)
        self.totp = TotpFactor(self.store, settings.issuer, clock)
        self.tokens = TokenService(self.store, settings, clock)
        self.deliver = deliver

    def register(self, username: str, password: str) -> None:
        self.passwords.register(username, password)

    def start_login(self, username: str, password: str) -> Challenge:
        self.passwords.verify(username, password)
        method = "totp" if self.totp.is_active(username) else "otp"
        challenge = Challenge(secrets.token_urlsafe(24), method,
                              self.clock() + self.s.challenge_ttl_seconds)
        self.store.run("DELETE FROM challenges WHERE username = ?", username)
        self.store.run("INSERT INTO challenges (id, username, method, expires_at) "
                       "VALUES (?, ?, ?, ?)", challenge.id, username, method,
                       challenge.expires_at)
        if method == "otp":
            self.deliver(username, self.otp.issue(username))
        log.info("CHALLENGE user=%s method=%s", username, method)
        return challenge

    def complete_login(self, challenge_id: str, code: str) -> str:
        row = self.store.one("SELECT * FROM challenges WHERE id = ?", challenge_id)
        if row is None or self.clock() > row["expires_at"]:
            log.warning("SECOND FACTOR REJECTED no valid challenge")
            raise AuthError("Login session expired. Start again.")
        username = row["username"]
        try:
            if row["method"] == "totp":
                self.totp.verify(username, code)
            else:
                self.otp.verify(username, code)
        except AuthError as exc:
            # An OTP that is used up ends the challenge as well.
            if "Start the login again" in str(exc):
                self.store.run("DELETE FROM challenges WHERE id = ?", challenge_id)
            raise
        self.store.run("DELETE FROM challenges WHERE id = ?", challenge_id)
        return self.tokens.issue(username)

    def whoami(self, token: str) -> str:
        return self.tokens.validate(token)

    def logout(self, token: str) -> None:
        self.tokens.revoke(token)

    def logout_everywhere(self, username: str) -> int:
        return self.tokens.revoke_all(username)
