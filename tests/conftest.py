import pytest

from layered_auth import AuthService, Settings

USER, PASSWORD = "alice", "violet-anchor-73-river"


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class Outbox(dict):
    def __call__(self, username, code):
        self[username] = code


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def outbox():
    return Outbox()


@pytest.fixture
def svc(clock, outbox):
    service = AuthService(Settings.ephemeral(bcrypt_rounds=4), clock=clock, deliver=outbox)
    service.register(USER, PASSWORD)
    return service


@pytest.fixture
def token(svc, outbox):
    ch = svc.start_login(USER, PASSWORD)
    return svc.complete_login(ch.id, outbox[USER])
