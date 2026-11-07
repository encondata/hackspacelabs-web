"""Command-line helpers: ``kiln serve``, ``kiln migrate``, ``kiln create-admin``, ``kiln generate-secrets``."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet


def generate_secrets() -> None:
    print(f"KILN_SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"KILN_ENCRYPTION_KEY={Fernet.generate_key().decode()}")


def migrate() -> None:
    from alembic import command
    from alembic.config import Config

    # alembic.ini lives in the project root (/app in the Docker image), not in site-packages.
    candidates = [Path(os.environ.get("KILN_ALEMBIC_INI", "alembic.ini")), Path(__file__).resolve().parent.parent / "alembic.ini"]
    ini = next((p for p in candidates if p.is_file()), None)
    if ini is None:
        sys.exit("alembic.ini not found; run from the project root or set KILN_ALEMBIC_INI")
    command.upgrade(Config(str(ini)), "head")


async def _create_admin(email: str, password: str, name: str) -> None:
    from kiln.db.session import dispose_engine, get_sessionmaker
    from kiln.services.users import UserError, create_user, get_role, get_user_by_email, seed_system_roles

    async with get_sessionmaker()() as db:
        await seed_system_roles(db)
        existing = await get_user_by_email(db, email)
        try:
            if existing:
                admin = await get_role(db, "admin")
                if admin not in existing.roles:
                    existing.roles.append(admin)
                print(f"{email} already exists; granted the admin role.")
            else:
                await create_user(db, email=email, password=password, full_name=name, role_names=["admin"])
                print(f"Created admin {email}.")
        except UserError as exc:
            sys.exit(f"Error: {exc}")
        await db.commit()
    await dispose_engine()


def create_admin(args: argparse.Namespace) -> None:
    password = args.password or getpass.getpass("Password (10+ characters): ")
    asyncio.run(_create_admin(args.email, password, args.name))


def serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run(
        "kiln.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="kiln", description="Kiln management commands")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="Run the web server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")

    sub.add_parser("migrate", help="Apply database migrations")
    sub.add_parser("generate-secrets", help="Print fresh KILN_SECRET_KEY / KILN_ENCRYPTION_KEY values")

    p = sub.add_parser("create-admin", help="Create an admin user (or grant admin to an existing one)")
    p.add_argument("email")
    p.add_argument("--name", default="Administrator")
    p.add_argument("--password", help="Prompted for if omitted")

    args = parser.parse_args()
    if args.command == "serve":
        serve(args)
    elif args.command == "migrate":
        migrate()
    elif args.command == "generate-secrets":
        generate_secrets()
    elif args.command == "create-admin":
        create_admin(args)


if __name__ == "__main__":
    main()
