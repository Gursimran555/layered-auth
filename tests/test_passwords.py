import pytest

from layered_auth import AuthError
from layered_auth.passwords import GENERIC_LOGIN_ERROR

from .conftest import PASSWORD, USER


def test_password_is_stored_as_bcrypt(svc):
    row = svc.store.one("SELECT password_hash FROM users WHERE username = ?", USER)
    assert row["password_hash"].startswith(b"$2b$04$")
    assert PASSWORD.encode() not in row["password_hash"]


def test_same_password_gets_different_salts(svc):
    svc.register("bob", PASSWORD.replace("violet", "orange"))
    svc.register("carol", PASSWORD.replace("violet", "orange"))
    a = svc.store.one("SELECT password_hash FROM users WHERE username='bob'")["password_hash"]
    b = svc.store.one("SELECT password_hash FROM users WHERE username='carol'")["password_hash"]
    assert a != b


@pytest.mark.parametrize("username,password", [
    ("al", "long-enough-password"),          # username too short
    ("bob", "short"),                        # too short
    ("bob", "x" * 73),                       # over bcrypt's 72-byte limit
    ("bob", "é" * 37),                       # 74 bytes in UTF-8
    ("bob", "password123"),                  # too short and common
    ("bob", "correcthorsebatterystaple"),    # common
    ("bobby", "my-name-is-bobby-ok"),        # contains username
])
def test_policy_rejects(svc, username, password):
    with pytest.raises(ValueError):
        svc.register(username, password)


def test_duplicate_username(svc):
    with pytest.raises(ValueError):
        svc.register(USER, "another-good-password-1")


def test_same_error_for_every_failure(svc, clock):
    errors = set()
    for user, pw in [("nobody", PASSWORD), (USER, "wrong-password-1"), (USER, "x" * 100)]:
        with pytest.raises(AuthError) as exc:
            svc.start_login(user, pw)
        errors.add(str(exc.value))
    assert errors == {GENERIC_LOGIN_ERROR}


def test_lockout_after_max_attempts(svc, clock):
    for _ in range(5):
        with pytest.raises(AuthError):
            svc.start_login(USER, "wrong-password-1")
    with pytest.raises(AuthError) as exc:
        svc.start_login(USER, PASSWORD)            # correct, but locked
    assert str(exc.value) == GENERIC_LOGIN_ERROR
    clock.advance(301)
    assert svc.start_login(USER, PASSWORD).method == "otp"


def test_success_resets_counter(svc):
    for _ in range(4):
        with pytest.raises(AuthError):
            svc.start_login(USER, "wrong-password-1")
    svc.start_login(USER, PASSWORD)
    row = svc.store.one("SELECT failed_attempts FROM users WHERE username = ?", USER)
    assert row["failed_attempts"] == 0


def test_unknown_user_still_runs_bcrypt(svc, monkeypatch):
    calls = []
    import layered_auth.passwords as mod
    real = mod.bcrypt.checkpw
    monkeypatch.setattr(mod.bcrypt, "checkpw", lambda *a: calls.append(1) or real(*a))
    with pytest.raises(AuthError):
        svc.start_login("nobody", PASSWORD)
    assert calls, "unknown usernames must cost the same bcrypt time as real ones"
