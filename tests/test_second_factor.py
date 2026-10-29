import hashlib

import pytest

from layered_auth import AuthError
from layered_auth.totp import hotp, provisioning_uri, totp

from .conftest import PASSWORD, USER

# --- emailed one-time codes -----------------------------------------------------

def test_code_is_stored_as_hmac_not_sha256(svc, outbox):
    svc.start_login(USER, PASSWORD)
    code = outbox[USER]
    stored = svc.store.one("SELECT code_mac FROM otps WHERE username = ?", USER)["code_mac"]
    assert stored != hashlib.sha256(code.encode()).hexdigest()
    assert code not in stored


def test_code_works_once(svc, outbox):
    ch = svc.start_login(USER, PASSWORD)
    code = outbox[USER]
    assert svc.complete_login(ch.id, code)
    with pytest.raises(AuthError):
        svc.complete_login(ch.id, code)


def test_code_expires(svc, outbox, clock):
    ch = svc.start_login(USER, PASSWORD)
    clock.advance(46)
    with pytest.raises(AuthError, match="expired"):
        svc.complete_login(ch.id, outbox[USER])


def test_three_wrong_codes_kill_the_challenge(svc, outbox):
    ch = svc.start_login(USER, PASSWORD)
    real = outbox[USER]
    wrong = "000000" if real != "000000" else "111111"
    for _ in range(3):
        with pytest.raises(AuthError):
            svc.complete_login(ch.id, wrong)
    with pytest.raises(AuthError):
        svc.complete_login(ch.id, real)


def test_second_factor_needs_a_password_challenge(svc):
    with pytest.raises(AuthError):
        svc.complete_login("not-a-real-challenge", "123456")


def test_challenge_expires(svc, outbox, clock):
    ch = svc.start_login(USER, PASSWORD)
    clock.advance(121)
    with pytest.raises(AuthError):
        svc.complete_login(ch.id, outbox[USER])


def test_new_login_replaces_old_challenge(svc, outbox):
    first = svc.start_login(USER, PASSWORD)
    svc.start_login(USER, PASSWORD)
    with pytest.raises(AuthError):
        svc.complete_login(first.id, outbox[USER])

# --- TOTP ----------------------------------------------------------------------

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # base32 of "12345678901234567890"


@pytest.mark.parametrize("t,expected", [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
])
def test_rfc6238_vectors(t, expected):
    assert totp(RFC_SECRET, t, digits=8) == expected


def test_rfc4226_vectors():
    key = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [hotp(key, i) for i in range(10)] == expected


def test_provisioning_uri():
    uri = provisioning_uri("ABC", "alice", "layered-auth")
    assert uri.startswith("otpauth://totp/layered-auth%3Aalice?secret=ABC&issuer=layered-auth")


@pytest.fixture
def enrolled(svc, clock):
    secret, _ = svc.totp.begin_enrollment(USER)
    svc.totp.confirm_enrollment(USER, totp(secret, clock()))
    clock.advance(30)
    return secret


def test_enrollment_switches_login_to_totp(svc, enrolled):
    assert svc.start_login(USER, PASSWORD).method == "totp"


def test_totp_login(svc, enrolled, clock):
    ch = svc.start_login(USER, PASSWORD)
    assert svc.whoami(svc.complete_login(ch.id, totp(enrolled, clock())))


def test_totp_allows_one_step_of_drift(svc, enrolled, clock):
    clock.advance(30)                       # phone clock 30s behind the server
    ch = svc.start_login(USER, PASSWORD)
    svc.complete_login(ch.id, totp(enrolled, clock() - 30))


def test_enrollment_code_cannot_be_reused_for_login(svc, clock):
    secret, _ = svc.totp.begin_enrollment(USER)
    code = totp(secret, clock())
    svc.totp.confirm_enrollment(USER, code)
    with pytest.raises(AuthError):
        svc.complete_login(svc.start_login(USER, PASSWORD).id, code)


def test_totp_rejects_old_codes(svc, enrolled, clock):
    ch = svc.start_login(USER, PASSWORD)
    with pytest.raises(AuthError):
        svc.complete_login(ch.id, totp(enrolled, clock() - 90))


def test_totp_code_cannot_be_replayed(svc, enrolled, clock):
    code = totp(enrolled, clock())
    svc.complete_login(svc.start_login(USER, PASSWORD).id, code)
    with pytest.raises(AuthError, match="already used"):
        svc.complete_login(svc.start_login(USER, PASSWORD).id, code)


def test_unconfirmed_totp_is_not_required(svc):
    svc.totp.begin_enrollment(USER)
    assert svc.start_login(USER, PASSWORD).method == "otp"
