"""User and role management: seeding, bootstrap, creation and safety checks."""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kiln.core.config import get_settings
from kiln.core.permissions import SYSTEM_ROLES
from kiln.core.security import MIN_PASSWORD_LENGTH, hash_password
from kiln.models import Role, User, user_roles

log = logging.getLogger(__name__)


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
    """Create a user. The very first account always becomes an admin."""
    email = email.strip().lower()
    if await get_user_by_email(db, email):
        raise UserError("An account with this email already exists")
    if password is not None:
        check_password_strength(password)

    first_user = await user_count(db) == 0
    names = ["admin"] if first_user else (role_names or [get_settings().default_role])
    roles = [await get_role(db, n) for n in dict.fromkeys(names)]

    user = User(
        email=email,
        full_name=full_name.strip(),
        password_hash=hash_password(password) if password else None,
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
    if "admin" in user.role_names and await admin_count(db, exclude_user_id=user.id) == 0:
        raise UserError("This is the last active admin; promote someone else first")


async def bootstrap(db: AsyncSession) -> None:
    """Startup hook: seed roles and create the env-configured admin on an empty database."""
    await seed_system_roles(db)
    settings = get_settings()
    if settings.admin_email and settings.admin_password and await user_count(db) == 0:
        await create_user(
            db, email=settings.admin_email, password=settings.admin_password, full_name="Administrator"
        )
        log.info("Bootstrapped admin account %s from KILN_ADMIN_EMAIL", settings.admin_email)
    await db.commit()
