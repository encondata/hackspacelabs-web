"""Email/password login, logout, self-registration and the current user's profile."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status

from kiln.api.deps import DB, Auth
from kiln.core import ratelimit
from kiln.core.config import get_settings
from kiln.core.ratelimit import (
    LOGIN_PAIR_V6_PREFIX,
    ip_bucket,
    login_email_limiter,
    login_ip_limiter,
    login_pair_limiter,
    password_change_limiter,
    password_change_user_limiter,
    register_limiter,
)
from kiln.core.security import hash_password_async, verify_password_async
from kiln.db.base import utcnow
from kiln.models import UserSession
from kiln.schemas import LoginIn, PasswordChange, ProfileUpdate, RegisterIn, SessionOut, UserOut
from kiln.services import audit
from kiln.services.audit import client_ip
from kiln.services.auth import (
    AuthContext,
    authenticate_password,
    clear_session_cookie,
    create_session,
    revoke_user_sessions,
    set_session_cookie,
)
from kiln.services.users import UserError, check_password_strength, create_user

router = APIRouter(prefix="/auth", tags=["auth"])

TOO_MANY = "Too many attempts; try again in a few minutes"
# Setting a first password on a GitHub-only account needs a sign-in this recent.
FIRST_PASSWORD_MAX_SESSION_AGE = timedelta(minutes=15)


def _require_session(ctx: AuthContext) -> UserSession:
    """Credential changes need a browser session, never an API token."""
    if ctx.via != "session" or ctx.session is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This can only be done from the web UI")
    return ctx.session


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: DB) -> SessionOut:
    email = body.email.strip().lower()
    addr = client_ip(request)
    ip = ip_bucket(addr)
    pair = f"{ip_bucket(addr, LOGIN_PAIR_V6_PREFIX)}|{email}"
    # Count the attempt before any await, so a burst of parallel guesses is limited too.
    if not ratelimit.acquire((login_ip_limiter, ip), (login_pair_limiter, pair), (login_email_limiter, email)):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    user = await authenticate_password(db, email, body.password)
    if user is None:
        audit.record(db, "auth.login_failed", summary=f"Failed login for {body.email[:100]}", request=request)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    # Only failures count against the limits.
    login_pair_limiter.reset(pair)
    login_ip_limiter.undo(ip)
    login_email_limiter.undo(email)
    raw, session = await create_session(db, user, request)
    audit.record(db, "auth.login", actor=user, target=user, summary="Signed in with password", request=request)
    await db.commit()
    set_session_cookie(response, raw)
    return SessionOut(user=UserOut.of(user), csrf_token=session.csrf_token)


@router.post("/logout", status_code=204)
async def logout(ctx: Auth, response: Response, db: DB) -> None:
    if ctx.session is not None:
        await db.delete(ctx.session)
        await db.commit()
    clear_session_cookie(response)


@router.post("/register", status_code=201)
async def register(body: RegisterIn, request: Request, response: Response, db: DB) -> SessionOut:
    if not get_settings().allow_signup:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Self-registration is disabled; ask an admin for an account")
    if not register_limiter.acquire(ip_bucket(client_ip(request))):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    try:
        user = await create_user(db, email=body.email, password=body.password, full_name=body.full_name)
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    raw, session = await create_session(db, user, request)
    audit.record(db, "user.register", actor=user, target=user, summary=f"Registered {user.email}", request=request)
    await db.commit()
    set_session_cookie(response, raw)
    return SessionOut(user=UserOut.of(user), csrf_token=session.csrf_token)


@router.get("/me")
async def me(ctx: Auth) -> SessionOut:
    return SessionOut(user=UserOut.of(ctx.user), csrf_token=ctx.csrf_token)


@router.patch("/me")
async def update_me(body: ProfileUpdate, ctx: Auth, db: DB) -> UserOut:
    ctx.user.full_name = body.full_name.strip()
    await db.commit()
    return UserOut.of(ctx.user)


@router.post("/me/password", status_code=204)
async def change_password(body: PasswordChange, ctx: Auth, request: Request, db: DB) -> None:
    session = _require_session(ctx)
    user = ctx.user
    try:
        check_password_strength(body.new_password)
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    # Nothing is pending yet: hand the pooled connection back before queuing for argon2.
    await db.commit()
    if user.password_hash:
        attempt = ((password_change_limiter, f"{user.id}:{session.id}"), (password_change_user_limiter, str(user.id)))
        if not ratelimit.acquire(*attempt):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
        if not await verify_password_async(body.current_password or "", user.password_hash):
            audit.record(
                db, "auth.password_change_failed", actor=user, target=user, summary="Wrong current password", request=request
            )
            await db.commit()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
        for limiter, key in attempt:
            limiter.reset(key)
    elif utcnow() - session.created_at > FIRST_PASSWORD_MAX_SESSION_AGE:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Sign out and sign in again, then set your password within 15 minutes"
        )
    user.password_hash = await hash_password_async(body.new_password)
    await revoke_user_sessions(db, user, keep=session)
    audit.record(db, "auth.password_changed", actor=user, target=user, request=request)
    await db.commit()


@router.delete("/me/github", status_code=204)
async def unlink_github(ctx: Auth, request: Request, db: DB) -> None:
    _require_session(ctx)
    account = ctx.user.github
    if account is None:
        return
    if ctx.user.password_hash is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Set a password before unlinking GitHub, or you'll be locked out")
    ctx.user.oauth_accounts.remove(account)
    audit.record(db, "auth.github_unlinked", actor=ctx.user, target=ctx.user, summary=f"Unlinked @{account.login}", request=request)
    await db.commit()
