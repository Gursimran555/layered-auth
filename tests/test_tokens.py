import base64
import json

import jwt
import pytest

from layered_auth import AuthError, ConfigError, Settings

from .conftest import PASSWORD, USER


def claims_of(token):
    return jwt.decode(token, options={"verify_signature": False})


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_token_claims(svc, token):
    c = claims_of(token)
    assert c["sub"] == USER
    assert c["iss"] == "layered-auth" and c["aud"] == "layered-auth-api"
    assert c["exp"] - c["iat"] == 300
    assert {"jti", "nbf"} <= c.keys()


def test_whoami(svc, token):
    assert svc.whoami(token) == USER


def test_logout_revokes_immediately(svc, token):
    svc.logout(token)
    with pytest.raises(AuthError, match="revoked"):
        svc.whoami(token)


def test_logout_everywhere(svc, outbox, token):
    ch = svc.start_login(USER, PASSWORD)
    second = svc.complete_login(ch.id, outbox[USER])
    assert svc.logout_everywhere(USER) == 2
    for t in (token, second):
        with pytest.raises(AuthError):
            svc.whoami(t)


def test_alg_none_rejected(svc, token):
    forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64(claims_of(token)) + "."
    with pytest.raises(AuthError):
        svc.whoami(forged)


def test_wrong_key_rejected(svc, token):
    forged = jwt.encode(claims_of(token), "x" * 40, algorithm="HS256")
    with pytest.raises(AuthError):
        svc.whoami(forged)


def test_tampered_payload_rejected(svc, token):
    head, _, sig = token.split(".")
    c = claims_of(token)
    c["sub"] = "admin"
    with pytest.raises(AuthError):
        svc.whoami(f"{head}.{b64(c)}.{sig}")


def test_other_audience_rejected(svc, token):
    c = claims_of(token)
    c["aud"] = "another-service"
    with pytest.raises(AuthError):
        svc.whoami(jwt.encode(c, svc.s.jwt_secret, algorithm="HS256"))


def test_missing_jti_rejected(svc, token):
    c = claims_of(token)
    del c["jti"]
    with pytest.raises(AuthError):
        svc.whoami(jwt.encode(c, svc.s.jwt_secret, algorithm="HS256"))


def test_unknown_jti_rejected(svc, token):
    c = claims_of(token)
    c["jti"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(AuthError):
        svc.whoami(jwt.encode(c, svc.s.jwt_secret, algorithm="HS256"))


def test_expired_rejected(svc, token, clock):
    clock.advance(299)
    assert svc.whoami(token) == USER
    clock.advance(1)
    with pytest.raises(AuthError, match="expired"):
        svc.whoami(token)


def test_future_token_rejected(svc, clock):
    c = {"sub": USER, "jti": "x", "iat": clock() + 600, "nbf": clock() + 600,
         "exp": clock() + 900, "iss": "layered-auth", "aud": "layered-auth-api"}
    with pytest.raises(AuthError):
        svc.whoami(jwt.encode(c, svc.s.jwt_secret, algorithm="HS256"))


def test_expired_token_can_still_be_revoked(svc, token, clock):
    clock.advance(3600)
    svc.logout(token)
    row = svc.store.one("SELECT revoked FROM tokens WHERE username = ?", USER)
    assert row["revoked"] == 1


def test_settings_require_secrets(monkeypatch):
    monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
    monkeypatch.delenv("AUTH_OTP_KEY", raising=False)
    with pytest.raises(ConfigError, match="AUTH_JWT_SECRET"):
        Settings.from_env()
    monkeypatch.setenv("AUTH_JWT_SECRET", "too-short")
    with pytest.raises(ConfigError, match="too short"):
        Settings.from_env()
    monkeypatch.setenv("AUTH_JWT_SECRET", "a" * 40)
    monkeypatch.setenv("AUTH_OTP_KEY", "b" * 40)
    assert Settings.from_env().jwt_secret == b"a" * 40


def test_nothing_secret_in_logs(svc, outbox, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="layered_auth")
    ch = svc.start_login(USER, PASSWORD)
    code = outbox[USER]
    tok = svc.complete_login(ch.id, code)
    text = caplog.text
    assert PASSWORD not in text and code not in text and tok not in text
