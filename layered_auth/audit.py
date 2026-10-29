"""Audit logging. Codes, passwords and full tokens are never logged; tokens appear by jti only."""

import logging

log = logging.getLogger("layered_auth")
log.addHandler(logging.NullHandler())


def enable_console(level: int = logging.INFO, path: str | None = None) -> None:
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if path:
        handlers.append(logging.FileHandler(path))
    for h in handlers:
        h.setFormatter(fmt)
        log.addHandler(h)
    log.setLevel(level)
    log.propagate = False
