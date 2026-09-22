"""MlinziOps command-line interface.

Usage:
    python -m app.cli create-admin
    python -m app.cli create-user USERNAME EMAIL ROLE
    python -m app.cli seed-demo
    python -m app.cli run-checks
    python -m app.cli run-detection
"""
from __future__ import annotations

import argparse
import sys

from app.config import settings
from app.logging_config import configure_logging


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser(prog="mlinziops", description="MlinziOps CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("create-admin", help="Create the initial admin account")
    p = sub.add_parser("create-user", help="Create a user")
    p.add_argument("username")
    p.add_argument("email")
    p.add_argument("role", choices=["ADMIN", "ANALYST", "VIEWER"])
    p.add_argument("--password", default=None)
    sub.add_parser("seed-demo", help="Load clearly-labelled demo data")
    sub.add_parser("run-checks", help="Print Linux hardening checks")
    sub.add_parser("run-detection", help="Run the detection engine over configured logs")
    sub.add_parser("check-scope", help="Print the authorized scan scope")

    args = parser.parse_args()

    if args.command == "create-admin":
        _create_user(
            username=settings.default_admin_username,
            email=settings.default_admin_email,
            role="ADMIN",
            password=settings.default_admin_password,
        )
    elif args.command == "create-user":
        _create_user(username=args.username, email=args.email, role=args.role, password=args.password)
    elif args.command == "seed-demo":
        from scripts.seed_demo import seed_demo

        seed_demo()
    elif args.command == "run-checks":
        from app.services.security_checks import run_checks

        for c in run_checks():
            print(f"[{c['status']:7s}] {c['title']}: {c['detail']}")
    elif args.command == "run-detection":
        from app.services.log_parser import collect_log_events
        from app.services.detection_engine import run_detection

        events = collect_log_events()
        print(f"parsed {len(events)} events")
        for d in run_detection(events):
            print(f"[{d['severity']}] {d['rule']}: {d['description']}")
    elif args.command == "check-scope":
        from app.services.nmap_scanner import parse_authorized_networks

        print("Authorized scan networks:")
        for net in parse_authorized_networks():
            print(f"  {net}")
    return 0


def _create_user(username: str, email: str, role: str, password: str | None) -> None:
    import getpass

    from sqlalchemy.exc import IntegrityError

    from app.database import SessionLocal
    from app.models import User
    from app.security.authentication import hash_password

    if not password:
        password = getpass.getpass(f"Password for {username} (min 12 chars): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if len(password) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        sys.exit(1)

    with SessionLocal() as db:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"User '{username}' already exists (id={existing.id}).")
            return
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            print(f"Email or username already in use: {username}/{email}.", file=sys.stderr)
            sys.exit(1)
        print(f"Created {role} user '{username}' (id={user.id}).")
        if role == "ADMIN" and password == settings.default_admin_password:
            print("WARNING: using the DEFAULT admin password — change it immediately.")


if __name__ == "__main__":
    raise SystemExit(main())
