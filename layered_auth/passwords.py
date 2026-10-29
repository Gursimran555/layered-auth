"""Layer 1: passwords.

bcrypt with a per-user salt, account lockout, and the same response for
"no such user", "wrong password" and "locked" - in content *and* in timing.
"""

from __future__ import annotations

import re
import secrets
import time

import bcrypt

from .audit import log
from .config import Settings
from .store import Store

GENERIC_LOGIN_ERROR = "Invalid username or password, or the account is temporarily locked."
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
BCRYPT_MAX_BYTES = 72

# A real deployment would check against a breached-password list (e.g. the
# HIBP k-anonymity API). This is just enough to stop the obvious ones.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789012", "qwertyuiop12",
    "iloveyou1234", "letmein12345", "welcome12345", "admin1234567", "changeme1234",
    "correcthorsebatterystaple", "passw0rd1234",
}


class AuthError(Exception):
    """Raised for any failed authentication step. Messages are safe to show users."""


class PasswordAuth:
    def __init__(self, store: Store, settings: Settings, clock=time.time,
                 equalize_timing: bool = True):
        self.store = store
        self.s = settings
        self.clock = clock
        # equalize_timing=False exists only so the attack demo can show the difference.
        self.equalize_timing = equalize_timing
        self._dummy_hash = bcrypt.hashpw(secrets.token_bytes(16),
                                         bcrypt.gensalt(settings.bcrypt_rounds))

    def check_policy(self, username: str, password: str) -> None:
        if not USERNAME_RE.match(username):
            raise ValueError("Username must be 3-32 characters: letters, digits, . _ -")
        if len(password) < self.s.min_password_length:
            raise ValueError(f"Password must be at least {self.s.min_password_length} characters.")
        if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
            # bcrypt only uses the first 72 bytes. Rejecting is clearer than
            # silently ignoring the rest of someone's passphrase.
            raise ValueError(f"Password must be at most {BCRYPT_MAX_BYTES} bytes.")
        if password.lower() in COMMON_PASSWORDS or username.lower() in password.lower():
            raise ValueError("Password is too common or contains the username.")

    def register(self, username: str, password: str) -> None:
        self.check_policy(username, password)
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(self.s.bcrypt_rounds))
        try:
            self.store.run("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           username, pw_hash)
        except Exception:
            log.warning("REGISTER FAILED username taken: %s", username)
            raise ValueError("Username is not available.") from None
        log.info("REGISTER user=%s", username)

    def _check(self, password: str, pw_hash: bytes) -> bool:
        pw = password.encode("utf-8")
        if len(pw) > BCRYPT_MAX_BYTES:
            # Still spend the bcrypt time so this path looks like any other failure.
            bcrypt.checkpw(b"x", self._dummy_hash)
            return False
        return bcrypt.checkpw(pw, pw_hash)

    def verify(self, username: str, password: str) -> None:
        """Raises AuthError on any failure. Returns None on success."""
        now = self.clock()
        user = self.store.one("SELECT * FROM users WHERE username = ?", username)

        if user is None:
            if self.equalize_timing:
                self._check(password, self._dummy_hash)
            log.warning("LOGIN FAILED unknown user=%s", username)
            raise AuthError(GENERIC_LOGIN_ERROR)

        if user["locked_until"] and now < user["locked_until"]:
            self._check(password, self._dummy_hash)
            log.warning("LOGIN BLOCKED locked user=%s", username)
            raise AuthError(GENERIC_LOGIN_ERROR)

        if self._check(password, user["password_hash"]):
            self.store.run("UPDATE users SET failed_attempts = 0, locked_until = NULL "
                           "WHERE username = ?", username)
            log.info("LOGIN PASSWORD OK user=%s", username)
            return

        # Atomic increment: concurrent bad logins can't share one counter value.
        self.store.run("UPDATE users SET failed_attempts = failed_attempts + 1 "
                       "WHERE username = ?", username)
        attempts = self.store.one("SELECT failed_attempts FROM users WHERE username = ?",
                                  username)["failed_attempts"]
        log.warning("LOGIN FAILED bad password user=%s attempt=%d/%d",
                    username, attempts, self.s.max_login_attempts)
        if attempts >= self.s.max_login_attempts:
            self.store.run("UPDATE users SET locked_until = ?, failed_attempts = 0 "
                           "WHERE username = ?", now + self.s.lockout_seconds, username)
            log.warning("ACCOUNT LOCKED user=%s for %ds", username, self.s.lockout_seconds)
        raise AuthError(GENERIC_LOGIN_ERROR)
