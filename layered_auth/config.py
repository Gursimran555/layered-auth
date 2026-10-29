"""Settings. Secrets come from the environment and the service refuses to start without them."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

MIN_SECRET_BYTES = 32


class ConfigError(RuntimeError):
    pass


def _secret_from_env(name: str) -> bytes:
    value = os.environ.get(name, "")
    if not value:
        raise ConfigError(f"{name} is not set. Generate one with: "
                          "python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
    raw = value.encode("utf-8")
    if len(raw) < MIN_SECRET_BYTES:
        raise ConfigError(f"{name} is too short ({len(raw)} bytes, need {MIN_SECRET_BYTES}+)")
    return raw


@dataclass(frozen=True)
class Settings:
    jwt_secret: bytes
    otp_key: bytes                    # HMAC key for stored one-time codes
    db_path: str = "auth.db"

    bcrypt_rounds: int = 12
    min_password_length: int = 12
    max_login_attempts: int = 5
    lockout_seconds: int = 300

    otp_length: int = 6
    otp_ttl_seconds: int = 45
    otp_max_attempts: int = 3
    challenge_ttl_seconds: int = 120  # time allowed between password and second factor

    token_ttl_seconds: int = 300
    jwt_algorithm: str = "HS256"
    issuer: str = "layered-auth"
    audience: str = "layered-auth-api"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            jwt_secret=_secret_from_env("AUTH_JWT_SECRET"),
            otp_key=_secret_from_env("AUTH_OTP_KEY"),
            db_path=os.environ.get("AUTH_DB_PATH", "auth.db"),
        )

    @classmethod
    def ephemeral(cls, db_path: str = ":memory:", **overrides) -> "Settings":
        """Random secrets, for demos and tests only."""
        return cls(jwt_secret=secrets.token_bytes(48), otp_key=secrets.token_bytes(48),
                   db_path=db_path, **overrides)
