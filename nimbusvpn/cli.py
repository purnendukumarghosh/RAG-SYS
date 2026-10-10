"""Command-line entry point: ``python -m nimbusvpn <command>``."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import secrets
import sys

from sqlalchemy import select


def _settings():
    from pydantic import ValidationError

    from nimbusvpn.config import Settings

    try:
        return Settings()
    except ValidationError as exc:
        sys.exit(f"configuration error:\n{exc}")


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    from nimbusvpn.main import create_app

    app = create_app(_settings())
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        server_header=False,
        log_level=args.log_level,
    )


def cmd_create_admin(args: argparse.Namespace) -> None:
    from nimbusvpn.db import User, init_db, make_engine, make_session_factory
    from nimbusvpn.security import USERNAME_RE, hash_password, password_problems

    settings = _settings()
    username = args.username.strip().lower()
    if not USERNAME_RE.fullmatch(username):
        sys.exit("username must be 3-32 characters of letters, digits, '.', '_' or '-'")
    password = os.environ.get("NIMBUS_NEW_ADMIN_PASSWORD") or getpass.getpass("New password: ")
    problems = password_problems(password, username, settings.min_password_length)
    if problems:
        sys.exit("password " + "; ".join(problems))

    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    engine = make_engine(settings.resolved_database_url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        user = db.scalar(select(User).where(User.username == username))
        if user is None:
            db.add(User(username=username, password_hash=hash_password(password), role="admin"))
            print(f"created admin {username!r}")
        else:
            user.password_hash = hash_password(password)
            user.role, user.enabled, user.locked_until = "admin", True, None
            user.token_version += 1
            print(f"reset password and granted admin to existing user {username!r}")
        db.commit()


def cmd_gen_secret(_: argparse.Namespace) -> None:
    print(secrets.token_urlsafe(48))


def cmd_show_config(_: argparse.Namespace) -> None:
    """Print the rendered server config with secrets redacted (for troubleshooting)."""
    from nimbusvpn.main import build_context

    config, peers = build_context(_settings()).wg.render()
    for line in config.splitlines():
        key = line.split("=", 1)[0].strip()
        print(f"{key} = <redacted>" if key in {"PrivateKey", "PresharedKey"} else line)
    print(f"# {peers} active peer(s)", file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="nimbusvpn", description="NimbusVPN control plane")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the API server and WireGuard manager")
    serve.add_argument("--host", default=os.environ.get("NIMBUS_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("NIMBUS_PORT", "8000")))
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(func=cmd_serve)

    admin = sub.add_parser("create-admin", help="create an admin or reset an admin password")
    admin.add_argument("--username", required=True)
    admin.set_defaults(func=cmd_create_admin)

    sub.add_parser("gen-secret", help="print a new random NIMBUS_SECRET_KEY").set_defaults(
        func=cmd_gen_secret
    )
    sub.add_parser("show-config", help="print the server config, secrets redacted").set_defaults(
        func=cmd_show_config
    )

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    args.func(args)


if __name__ == "__main__":
    main()
