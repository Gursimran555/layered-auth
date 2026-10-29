"""python -m layered_auth demo | attacks | serve-cli"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys

from . import attacks
from .audit import enable_console
from .config import ConfigError, Settings
from .passwords import AuthError
from .service import AuthService


def demo() -> int:
    enable_console(logging.INFO)
    codes = {}
    svc = AuthService(Settings.ephemeral(), deliver=lambda u, c: codes.__setitem__(u, c))
    print("\n== register ==")
    svc.register("alice", "violet-anchor-73-river")

    print("\n== password, then emailed one-time code ==")
    ch = svc.start_login("alice", "violet-anchor-73-river")
    print(f"challenge method: {ch.method}")
    token = svc.complete_login(ch.id, codes["alice"])
    print(f"whoami -> {svc.whoami(token)}")

    print("\n== logout, then try the same token ==")
    svc.logout(token)
    try:
        svc.whoami(token)
    except AuthError as exc:
        print(f"rejected: {exc}")
    return 0


def interactive() -> int:
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    enable_console(logging.INFO, path="auth_audit.log")
    svc = AuthService(settings)
    token = None
    while True:
        print("\n1 register  2 login  3 whoami  4 set up authenticator app  5 logout  6 quit")
        choice = input("> ").strip()
        try:
            if choice == "1":
                svc.register(input("username: ").strip(), getpass.getpass("password: "))
                print("registered")
            elif choice == "2":
                user = input("username: ").strip()
                ch = svc.start_login(user, getpass.getpass("password: "))
                prompt = "authenticator code: " if ch.method == "totp" else "code: "
                token = svc.complete_login(ch.id, input(prompt))
                print("logged in")
            elif choice == "3":
                print(svc.whoami(token) if token else "not logged in")
            elif choice == "4":
                user = input("username: ").strip()
                secret, uri = svc.totp.begin_enrollment(user)
                print(f"add this to your authenticator app:\n  {uri}\n  (or key: {secret})")
                svc.totp.confirm_enrollment(user, input("code from the app: "))
                print("authenticator app enabled")
            elif choice == "5" and token:
                svc.logout(token)
                token = None
                print("logged out")
            elif choice == "6":
                return 0
        except (AuthError, ValueError) as exc:
            print(f"error: {exc}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m layered_auth")
    p.add_argument("command", choices=["demo", "attacks", "cli"])
    args = p.parse_args(argv)
    if args.command == "demo":
        return demo()
    if args.command == "attacks":
        return attacks.run()
    return interactive()


if __name__ == "__main__":
    sys.exit(main())
