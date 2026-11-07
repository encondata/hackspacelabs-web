"""User and role management: seeding, bootstrap, creation and safety checks."""

from __future__ import annotations

import logging

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from kiln.core.config import get_settings
from kiln.core.permissions import SYSTEM_ROLES
from kiln.core.security import MIN_PASSWORD_LENGTH, hash_password_async
from kiln.models import Role, User, user_roles

log = logging.getLogger(__name__)

# pg_advisory_xact_lock key shared by the first-admin and last-admin checks.
_ACCOUNTS_LOCK_KEY = 0x6B696C6E


class UserError(ValueError):
    pass


async def seed_system_roles(db: AsyncSession) -> None:
    """Create or refresh the built-in roles so upgrades pick up new permissions."""
    existing = {r.name: r for r in (await db.scalars(select(Role))).all()}
    for name, spec in SYSTEM_ROLES.items():
        perms = sorted(str(p) for p in spec["permissions"])  # type: ignore[union-attr]
        role = existing.get(name)
        if role is None:
            db.add(Role(name=name, description=str(spec["description"]), permissions=perms, is_system=True))
        else:
            role.permissions = perms
            role.description = str(spec["description"])
            role.is_system = True
    await db.flush()


async def get_role(db: AsyncSession, name: str) -> Role:
    role = await db.scalar(select(Role).where(Role.name == name))
    if role is None:
        raise UserError(f"Role '{name}' does not exist")
    return role


async def user_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(User)) or 0)


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    return await db.scalar(select(User).where(User.email == email.strip().lower()))


async def lock_accounts(db: AsyncSession) -> None:
    """Serialise first-admin / last-admin decisions until this transaction ends.

    PostgreSQL only; elsewhere (SQLite in tests and previews) this is a no-op.
    """
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(text(f"SELECT pg_advisory_xact_lock({_ACCOUNTS_LOCK_KEY})"))


def check_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")


async def create_user(
    db: AsyncSession,
    *,
    email: str,
    password: str | None = None,
    full_name: str = "",
    role_names: list[str] | None = None,
    avatar_url: str | None = None,
) -> User:
    """Create a user. The very first account always becomes an admin.

    ``role_names=None`` gives the default role; an empty list gives no roles.
    """
    email = email.strip().lower()
    if password is not None:
        check_password_strength(password)
    # Hash before the first query, so a caller that has not used ``db`` yet holds no pooled
    # connection while queuing for argon2.
    password_hash = await hash_password_async(password) if password else None
    if await get_user_by_email(db, email):
        raise UserError("An account with this email already exists")

    await lock_accounts(db)
    first_user = await user_count(db) == 0
    if first_user:
        names = ["admin"]
    elif role_names is None:
        names = [get_settings().default_role]
    else:
        names = role_names
    roles = [await get_role(db, n) for n in dict.fromkeys(names)]

    user = User(
        email=email,
        full_name=full_name.strip(),
        password_hash=password_hash,
        avatar_url=avatar_url,
        roles=roles,
        oauth_accounts=[],
    )
    db.add(user)
    await db.flush()
    if first_user:
        log.info("Created first user %s with the admin role", email)
    return user


async def admin_count(db: AsyncSession, *, exclude_user_id=None) -> int:
    stmt = (
        select(func.count(func.distinct(User.id)))
        .select_from(User)
        .join(user_roles, user_roles.c.user_id == User.id)
        .join(Role, Role.id == user_roles.c.role_id)
        .where(User.is_active.is_(True), Role.name == "admin")
    )
    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)
    return int(await db.scalar(stmt) or 0)


async def ensure_not_last_admin(db: AsyncSession, user: User) -> None:
    """Raise if removing admin rights from / deactivating ``user`` would leave no admins."""
    if "admin" not in user.role_names:
        return
    await lock_accounts(db)
    if await admin_count(db, exclude_user_id=user.id) == 0:
        raise UserError("This is the last active admin; promote someone else first")


async def bootstrap(db: AsyncSession) -> None:
    """Startup hook: seed roles and create the env-configured admin on an empty database."""
    await seed_system_roles(db)
    settings = get_settings()
    if await db.scalar(select(Role.id).where(Role.name == settings.default_role)) is None:
        log.error("KILN_DEFAULT_ROLE=%s is not an existing role; sign-ups will fail until it is created", settings.default_role)
    if settings.admin_email and settings.admin_password and await user_count(db) == 0:
        try:
            await create_user(
                db, email=settings.admin_email, password=settings.admin_password, full_name="Administrator"
            )
        except UserError as exc:
            # Keep serving: a crash here would restart the container forever.
            log.error(
                "Admin account %s from KILN_ADMIN_EMAIL was not created: %s. "
                "Fix KILN_ADMIN_PASSWORD and restart, or run `kiln create-admin`.",
                settings.admin_email, exc,
            )
        else:
            log.info("Bootstrapped admin account %s from KILN_ADMIN_EMAIL", settings.admin_email)
    await db.commit()
