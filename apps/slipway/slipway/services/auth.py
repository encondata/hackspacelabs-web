"""Login, browser sessions and API-token authentication."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.config import get_settings
from slipway.core.security import (
    API_TOKEN_PREFIX,
    hash_password_async,
    hash_token,
    new_token,
    password_needs_rehash,
    verify_password_async,
)
from slipway.db.base import utcnow
from slipway.models import ApiToken, OAuthAccount, User, UserSession
from slipway.services.audit import client_ip

SESSION_COOKIE = "slipway_session"
CSRF_HEADER = "X-CSRF-Token"
_TOUCH_INTERVAL = timedelta(minutes=5)
# Adding or removing a sign-in method (a first password, a GitHub link) needs a sign-in this recent, so a
# stolen session cookie cannot plant a credential that outlives it.
RECENT_SIGN_IN_MAX_AGE = timedelta(minutes=15)


def signed_in_recently(session: UserSession) -> bool:
    return utcnow() - session.created_at <= RECENT_SIGN_IN_MAX_AGE


def sign_in_again(action: str) -> str:
    """The refusal shown when ``action`` needs a more recent sign-in."""
    return f"Sign out and sign in again, then {action} within {RECENT_SIGN_IN_MAX_AGE.seconds // 60} minutes"


@dataclass
class AuthContext:
    user: User
    via: Literal["session", "token"]
    session: UserSession | None = None
    token: ApiToken | None = None

    def can(self, permission: str) -> bool:
        return self.user.can(permission)

    @property
    def csrf_token(self) -> str:
        return self.session.csrf_token if self.session else ""


async def authenticate_password(db: AsyncSession, email: str, password: str) -> User | None:
    """Check an email/password pair. Commits the (read-only) transaction before hashing."""
    user = await db.scalar(select(User).where(User.email == email.strip().lower()))
    # Hand the pooled connection back while queuing for argon2, so a login burst cannot
    # starve every other request (and the background tasks) of database connections.
    await db.commit()
    ok = await verify_password_async(password, user.password_hash if user else None)
    if not (user and ok and user.is_active):
        return None
    if user.password_hash and password_needs_rehash(user.password_hash):
        user.password_hash = await hash_password_async(password)
    return user


async def create_session(db: AsyncSession, user: User, request: Request | None) -> tuple[str, UserSession]:
    raw = new_token()
    now = utcnow()
    session = UserSession(
        user_id=user.id,
        token_hash=hash_token(raw),
        csrf_token=new_token(24),
        expires_at=now + timedelta(hours=get_settings().session_ttl_hours),
        last_seen_at=now,
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent", "")[:300] if request else None),
    )
    db.add(session)
    user.last_login_at = now
    await db.flush()
    return raw, session


def cookie_secure(request: Request) -> bool:
    """Mark the session cookie Secure for requests that arrived over https, or that are addressed to an https
    SLIPWAY_BASE_URL host (through a proxy whose forwarded scheme isn't trusted). A browser drops a Secure cookie
    sent over plain http, so opening Slipway directly (http://<server>:8000) with an https base URL must get a
    plain one, or every sign-in silently fails."""
    if request.url.scheme == "https":
        return True
    settings = get_settings()
    return settings.secure_cookies and request.url.hostname == urlsplit(settings.base_url).hostname


def set_session_cookie(response: Response, raw_token: str, request: Request) -> None:
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=cookie_secure(request),
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


async def session_from_cookie(db: AsyncSession, raw: str) -> UserSession | None:
    session = await db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(raw)))
    if session is None:
        return None
    now = utcnow()
    if session.expires_at <= now or not session.user.is_active:
        await db.delete(session)
        await db.commit()
        return None
    if now - session.last_seen_at > _TOUCH_INTERVAL:
        session.last_seen_at = now
        await db.commit()
    return session


async def token_from_bearer(db: AsyncSession, raw: str) -> ApiToken | None:
    if not raw.startswith(API_TOKEN_PREFIX):
        return None
    token = await db.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(raw)))
    if token is None or not token.user.is_active:
        return None
    now = utcnow()
    if token.expires_at and token.expires_at <= now:
        return None
    if token.last_used_at is None or now - token.last_used_at > _TOUCH_INTERVAL:
        token.last_used_at = now
        await db.commit()
    return token


async def revoke_user_sessions(db: AsyncSession, user: User, *, keep: UserSession | None = None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user.id)
    if keep is not None:
        stmt = stmt.where(UserSession.id != keep.id)
    await db.execute(stmt)


async def revoke_user_tokens(db: AsyncSession, user: User) -> None:
    await db.execute(delete(ApiToken).where(ApiToken.user_id == user.id))


async def revoke_user_github(db: AsyncSession, user: User) -> list[str]:
    """Unlink every GitHub account from ``user``. Returns the logins that were linked."""
    logins = [a.login for a in user.oauth_accounts]
    user.oauth_accounts.clear()
    await db.flush()
    # Also catch a link a concurrent callback committed after ``user`` was loaded.
    await db.execute(delete(OAuthAccount).where(OAuthAccount.user_id == user.id))
    return logins


async def revoke_user_credentials(db: AsyncSession, user: User) -> None:
    """Sign the user out everywhere, delete their API tokens and unlink GitHub (admin reset, deactivation).

    A GitHub link is a credential too: one planted with a stolen session must not survive a reset.
    """
    await revoke_user_sessions(db, user)
    await revoke_user_tokens(db, user)
    await revoke_user_github(db, user)
