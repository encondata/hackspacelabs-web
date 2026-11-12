"""Mirror Keycloak accounts into Slipway's users table.

Keycloak owns who people are and which Slipway roles they hold. Slipway keeps a row per Keycloak account
(keyed by the immutable ``sub``) so audit events, "deployed by" and GitHub links have something to point at,
and refreshes its name, email and roles whenever the account is seen. Accounts are never matched by email.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from slipway.db.base import utcnow
from slipway.models import KEYCLOAK, OAuthAccount, Role, User
from slipway.services import audit
from slipway.services.oidc import OwnerStatus, roles_from_claims

_TOUCH_INTERVAL = timedelta(minutes=5)


def _text(value: Any, limit: int) -> str | None:
    return value.strip()[:limit] or None if isinstance(value, str) and value.strip() else None


def profile_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    email = claims.get("email")
    return {
        "username": _text(claims.get("preferred_username"), 255),
        # An address too long for the column is dropped, never cut into a different one.
        "email": email.strip().lower() if isinstance(email, str) and 0 < len(email.strip()) <= 320 else None,
        "full_name": _text(claims.get("name"), 200) or "",
    }


def profile_from_owner(owner: OwnerStatus) -> dict[str, Any]:
    return profile_from_claims({"preferred_username": owner.username, "email": owner.email, "name": owner.full_name})


async def _account(db: AsyncSession, sub: str) -> OAuthAccount | None:
    return await db.scalar(
        select(OAuthAccount)
        .options(
            joinedload(OAuthAccount.user).options(selectinload(User.oauth_accounts), selectinload(User.roles))
        )
        .where(OAuthAccount.provider == KEYCLOAK, OAuthAccount.provider_user_id == sub)
    )


async def _set_roles(db: AsyncSession, user: User, names: Iterable[str]) -> tuple[list[str], list[str]] | None:
    wanted = sorted(set(names))
    if wanted == user.role_names:
        return None
    roles = list((await db.scalars(select(Role).where(Role.name.in_(wanted)))).all()) if wanted else []
    before = user.role_names
    user.roles = roles
    return before, user.role_names


async def _apply_profile(db: AsyncSession, user: User, profile: dict[str, Any]) -> bool:
    changed = False
    email = profile["email"]
    if email and email != user.email:
        # Another Slipway user may hold that address (Keycloak allows duplicates when emails are unverified);
        # keep the old value rather than fail the request.
        taken = await db.scalar(select(User.id).where(User.email == email, User.id != user.id))
        if taken is None:
            user.email = email
            changed = True
    for field in ("username", "full_name"):
        if profile[field] is not None and profile[field] != getattr(user, field):
            setattr(user, field, profile[field])
            changed = True
    return changed


async def sync_user(
    db: AsyncSession,
    sub: str,
    *,
    profile: dict[str, Any],
    roles: Iterable[str],
    interactive: bool,
    enabled: bool = True,
    request: Request | None = None,
) -> User:
    """Find or create the user for Keycloak account ``sub`` and bring it up to date. Commits when anything changed."""
    account = await _account(db, sub)
    created = False
    if account is None:
        user = User(
            username=profile["username"], full_name=profile["full_name"], roles=[], oauth_accounts=[], is_active=enabled
        )
        user.oauth_accounts.append(OAuthAccount(provider=KEYCLOAK, provider_user_id=sub, login=(profile["username"] or sub)[:100]))
        db.add(user)
        try:
            await db.flush()
        except IntegrityError:
            # A concurrent first request for the same account created it first.
            await db.rollback()
            account = await _account(db, sub)
            if account is None:
                raise
            user = account.user
        else:
            created = True
            audit.record(
                db, "user.provisioned", actor=user, target=user,
                summary=f"First sign-in from HackSpaceLabs as {user.display_name}", request=request,
            )
    else:
        user = account.user

    changed = await _apply_profile(db, user, profile)
    if profile["username"] and user.keycloak and user.keycloak.login != profile["username"][:100]:
        user.keycloak.login = profile["username"][:100]
        changed = True
    if user.is_active != enabled:
        user.is_active = enabled
        changed = True
    if (diff := await _set_roles(db, user, roles)) is not None:
        changed = True
        if not created:
            before, after = diff
            audit.record(
                db, "user.roles_synced", target=user, summary=f"Keycloak roles for {user.display_name}: {', '.join(after) or 'none'}",
                details={"before": before, "after": after}, request=request,
            )
    now = utcnow()
    if interactive and (user.last_login_at is None or now - user.last_login_at > _TOUCH_INTERVAL):
        user.last_login_at = now
        changed = True
    if created or changed:
        await db.commit()
    return user


async def user_for_claims(db: AsyncSession, claims: dict[str, Any], request: Request | None = None) -> User:
    return await sync_user(
        db, claims["sub"], profile=profile_from_claims(claims), roles=roles_from_claims(claims), interactive=True,
        request=request,
    )


async def refresh_owner(db: AsyncSession, user: User, owner: OwnerStatus, request: Request | None = None) -> User:
    """Apply what Keycloak says about an API token's owner (enabled flag, roles, profile)."""
    account = user.keycloak
    if account is None:
        return user
    return await sync_user(
        db, account.provider_user_id, profile=profile_from_owner(owner), roles=owner.roles if owner.enabled else (),
        interactive=False, enabled=owner.exists and owner.enabled, request=request,
    )
