"""Login, browser sessions and API-token authentication."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from kiln.core.config import get_settings
from kiln.core.security import (
    API_TOKEN_PREFIX,
    hash_password,
    hash_token,
    new_token,
    password_needs_rehash,
    verify_password,
)
from kiln.db.base import utcnow
from kiln.models import ApiToken, User, UserSession
from kiln.services.audit import client_ip

SESSION_COOKIE = "kiln_session"
CSRF_HEADER = "X-CSRF-Token"
_TOUCH_INTERVAL = timedelta(minutes=5)


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
    user = await db.scalar(select(User).where(User.email == email.strip().lower()))
    ok = verify_password(password, user.password_hash if user else None)
    if not (user and ok and user.is_active):
        return None
    if user.password_hash and password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
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


def set_session_cookie(response: Response, raw_token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.secure_cookies,
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
