"""Run real attacks against the system and report which ones were stopped.

    python -m layered_auth attacks

Each attack runs against a fresh in-memory instance. Several of them also show
what happened against the first version of this code, which is how I found
the weaknesses fixed here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import statistics
import time
import warnings

import jwt

from .config import Settings
from .passwords import AuthError
from .service import AuthService
from .totp import totp

USER, PASSWORD = "alice", "violet-anchor-73-river"


class Outbox:
    def __init__(self):
        self.last = {}

    def __call__(self, username, code):
        self.last[username] = code


def fresh(**overrides):
    outbox = Outbox()
    svc = AuthService(Settings.ephemeral(**overrides), deliver=outbox)
    svc.register(USER, PASSWORD)
    return svc, outbox


def login(svc, outbox):
    ch = svc.start_login(USER, PASSWORD)
    return svc.complete_login(ch.id, outbox.last[USER])


def rejected(fn) -> tuple[bool, str]:
    try:
        fn()
    except AuthError as exc:
        return True, str(exc)
    return False, "accepted"


def b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# --- attacks -----------------------------------------------------------------

def online_guessing():
    svc, _ = fresh()
    guesses = ["123456", "password", "alice2026", "qwerty", "letmein", "summer2026!"]
    for g in guesses:
        rejected(lambda: svc.start_login(USER, g))
    ok, _ = rejected(lambda: svc.start_login(USER, PASSWORD))
    return ok, f"{len(guesses)} wrong guesses -> account locked; correct password refused while locked"


def enumeration_by_message():
    svc, _ = fresh()
    _, unknown = rejected(lambda: svc.start_login("mallory", "whatever-password"))
    _, known = rejected(lambda: svc.start_login(USER, "whatever-password"))
    _, long_pw = rejected(lambda: svc.start_login(USER, "x" * 100))
    same = unknown == known == long_pw
    return same, "unknown user, wrong password and 100-byte password all give the same message"


def _median_ms(fn, n=5):
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        rejected(fn)
        samples.append((time.perf_counter() - t) * 1000)
    return statistics.median(samples)


def enumeration_by_timing():
    results = {}
    for equalize in (False, True):
        s = Settings.ephemeral(max_login_attempts=1000)
        svc = AuthService(s, deliver=Outbox(), equalize_timing=equalize)
        svc.register(USER, PASSWORD)
        known = _median_ms(lambda: svc.start_login(USER, "wrong-password-123"))
        unknown = _median_ms(lambda: svc.start_login("mallory", "wrong-password-123"))
        results[equalize] = (known, unknown)
    (k0, u0), (k1, u1) = results[False], results[True]
    blocked = u1 > 0.5 * k1
    return blocked, (f"first version: real user {k0:.0f} ms vs unknown {u0:.2f} ms. "
                     f"now: {k1:.0f} ms vs {u1:.0f} ms")


def offline_otp_crack():
    svc, outbox = fresh()
    svc.start_login(USER, PASSWORD)
    code = outbox.last[USER]
    stored = svc.store.one("SELECT code_mac FROM otps WHERE username = ?", USER)["code_mac"]

    # What the first version stored: plain SHA-256 of the code.
    legacy = hashlib.sha256(code.encode()).hexdigest()
    t = time.perf_counter()
    cracked_legacy = cracked_now = None
    for i in range(10 ** 6):
        candidate = f"{i:06d}"
        h = hashlib.sha256(candidate.encode()).hexdigest()
        if h == legacy:
            cracked_legacy = candidate
        if h == stored:
            cracked_now = candidate
    elapsed = time.perf_counter() - t
    blocked = cracked_legacy == code and cracked_now is None
    return blocked, (f"leaked OTP table: SHA-256 version cracked in {elapsed:.1f}s; "
                     "HMAC version not recoverable without the server key")


def otp_guessing():
    svc, _ = fresh()
    ch = svc.start_login(USER, PASSWORD)
    for g in ("000000", "123456", "111111"):
        rejected(lambda: svc.complete_login(ch.id, g))
    ok, msg = rejected(lambda: svc.complete_login(ch.id, "999999"))
    return ok, "3 wrong codes -> code and login session invalidated"


def otp_replay():
    svc, outbox = fresh()
    ch = svc.start_login(USER, PASSWORD)
    code = outbox.last[USER]
    svc.complete_login(ch.id, code)
    ok, _ = rejected(lambda: svc.complete_login(ch.id, code))
    return ok, "a used code (and its challenge) can't be submitted again"


def skip_password_step():
    svc, _ = fresh()
    ok, _ = rejected(lambda: svc.complete_login("made-up-challenge-id", "123456"))
    return ok, "second factor without a password-verified challenge is refused"


def totp_replay():
    clock = [1_800_000_000.0]
    s = Settings.ephemeral()
    svc = AuthService(s, clock=lambda: clock[0], deliver=Outbox())
    svc.register(USER, PASSWORD)
    secret, _ = svc.totp.begin_enrollment(USER)
    clock[0] += 30
    svc.totp.confirm_enrollment(USER, totp(secret, clock[0]))
    clock[0] += 30
    code = totp(secret, clock[0])
    svc.complete_login(svc.start_login(USER, PASSWORD).id, code)
    ok, _ = rejected(lambda: svc.complete_login(svc.start_login(USER, PASSWORD).id, code))
    return ok, "a shoulder-surfed TOTP code can't be reused in the same 30s window"


def jwt_alg_none():
    svc, outbox = fresh()
    real = jwt.decode(login(svc, outbox), options={"verify_signature": False})
    forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64(real) + "."
    ok, _ = rejected(lambda: svc.whoami(forged))
    return ok, "token with alg=none and no signature"


def jwt_weak_key():
    svc, outbox = fresh()
    real = jwt.decode(login(svc, outbox), options={"verify_signature": False})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")      # PyJWT rightly warns about the short key
        forged = jwt.encode(real, "change-me", algorithm="HS256")
    ok, _ = rejected(lambda: svc.whoami(forged))
    return ok, "valid-looking token signed with a guessed key"


def jwt_tamper():
    svc, outbox = fresh()
    head, body, sig = login(svc, outbox).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["sub"] = "admin"
    ok, _ = rejected(lambda: svc.whoami(f"{head}.{b64(claims)}.{sig}"))
    return ok, "sub changed to admin, original signature kept"


def jwt_wrong_audience():
    svc, outbox = fresh()
    login(svc, outbox)
    real = jwt.decode(svc.tokens.issue(USER), options={"verify_signature": False})
    real["aud"] = "some-other-api"
    other = jwt.encode(real, svc.s.jwt_secret, algorithm="HS256")
    ok, _ = rejected(lambda: svc.whoami(other))
    return ok, "correctly signed token meant for a different service"


def revoked_token():
    svc, outbox = fresh()
    token = login(svc, outbox)
    svc.logout(token)
    ok, _ = rejected(lambda: svc.whoami(token))
    return ok, "token used after logout (signature and exp still valid)"


def stolen_tokens_after_reset():
    svc, outbox = fresh()
    tokens = [login(svc, outbox) for _ in range(3)]
    svc.logout_everywhere(USER)
    ok = all(rejected(lambda t=t: svc.whoami(t))[0] for t in tokens)
    return ok, "3 sessions, 'log out everywhere' -> all rejected"


def expired_token():
    svc, outbox = fresh()
    old = login(svc, outbox)
    svc.tokens.clock = lambda: time.time() + 3600      # an hour later
    ok, _ = rejected(lambda: svc.whoami(old))
    return ok, "token whose exp passed an hour ago"


ATTACKS = [
    ("Online password guessing", online_guessing),
    ("Username enumeration (messages)", enumeration_by_message),
    ("Username enumeration (timing)", enumeration_by_timing),
    ("Offline crack of leaked OTP table", offline_otp_crack),
    ("OTP guessing", otp_guessing),
    ("OTP replay", otp_replay),
    ("Skip the password step", skip_password_step),
    ("TOTP replay", totp_replay),
    ("JWT alg=none", jwt_alg_none),
    ("JWT signed with guessed key", jwt_weak_key),
    ("JWT payload tampering", jwt_tamper),
    ("JWT for another audience", jwt_wrong_audience),
    ("Revoked token reuse", revoked_token),
    ("Stolen sessions after reset", stolen_tokens_after_reset),
    ("Expired token", expired_token),
]


def run(selected=None) -> int:
    width = max(len(n) for n, _ in ATTACKS)
    failures = 0
    for name, fn in ATTACKS:
        if selected and name not in selected:
            continue
        blocked, detail = fn()
        failures += not blocked
        print(f"{'BLOCKED' if blocked else 'NOT BLOCKED':11}  {name:{width}}  {detail}")
    print(f"\n{len(ATTACKS) - failures}/{len(ATTACKS)} attacks blocked")
    return 1 if failures else 0
