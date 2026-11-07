"""Email/password login, logout, self-registration and the current user's profile."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status

from kiln.api.deps import DB, Auth
from kiln.core.config import get_settings
from kiln.core.ratelimit import login_limiter
from kiln.core.security import hash_password, verify_password
from kiln.schemas import LoginIn, PasswordChange, ProfileUpdate, RegisterIn, SessionOut, UserOut
from kiln.services import audit
from kiln.services.audit import client_ip
from kiln.services.auth import (
    authenticate_password,
    clear_session_cookie,
    create_session,
    revoke_user_sessions,
    set_session_cookie,
)
from kiln.services.users import UserError, check_password_strength, create_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: DB) -> SessionOut:
    keys = (f"ip:{client_ip(request)}", f"email:{body.email.strip().lower()}")
    if login_limiter.blocked(*keys):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts; try again in a few minutes")
    user = await authenticate_password(db, body.email, body.password)
    if user is None:
        login_limiter.hit(*keys)
        audit.record(db, "auth.login_failed", summary=f"Failed login for {body.email[:100]}", request=request)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    login_limiter.reset(keys[1])
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
    user = ctx.user
    if user.password_hash and not verify_password(body.current_password or "", user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    try:
        check_password_strength(body.new_password)
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    user.password_hash = hash_password(body.new_password)
    await revoke_user_sessions(db, user, keep=ctx.session)
    audit.record(db, "auth.password_changed", actor=user, target=user, request=request)
    await db.commit()


@router.delete("/me/github", status_code=204)
async def unlink_github(ctx: Auth, request: Request, db: DB) -> None:
    account = ctx.user.github
    if account is None:
        return
    if ctx.user.password_hash is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Set a password before unlinking GitHub, or you'll be locked out")
    ctx.user.oauth_accounts.remove(account)
    audit.record(db, "auth.github_unlinked", actor=ctx.user, target=ctx.user, summary=f"Unlinked @{account.login}", request=request)
    await db.commit()
