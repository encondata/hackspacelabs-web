"""Admin user management."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from kiln.api.deps import DB, not_found, require
from kiln.core.permissions import Perm, has_permission
from kiln.core.security import hash_password
from kiln.models import OAuthAccount, Role, User
from kiln.schemas import UserCreate, UserOut, UserUpdate
from kiln.services import audit
from kiln.services.auth import AuthContext, revoke_user_sessions
from kiln.services.github import GitHubClient, GitHubError
from kiln.services.repos import github_token_for
from kiln.services.users import UserError, check_password_strength, create_user, ensure_not_last_admin

router = APIRouter(prefix="/users", tags=["users"])

Reader = Annotated[AuthContext, require(Perm.USERS_READ)]
Writer = Annotated[AuthContext, require(Perm.USERS_WRITE)]


async def _roles(db: DB, names: list[str], actor: User) -> list[Role]:
    roles = (await db.scalars(select(Role).where(Role.name.in_(names)))).all()
    missing = set(names) - {r.name for r in roles}
    if missing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown role(s): {', '.join(sorted(missing))}")
    # No privilege escalation: you may only grant permissions you hold yourself.
    for role in roles:
        if not all(has_permission(actor.permissions, p) for p in role.permissions):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"You cannot grant the '{role.name}' role")
    return list(roles)


async def _get(db: DB, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise not_found("User")
    return user


@router.get("")
async def list_users(ctx: Reader, db: DB) -> list[UserOut]:
    users = (await db.scalars(select(User).order_by(User.created_at))).all()
    return [UserOut.of(u) for u in users]


async def _resolve_github(db: DB, login: str, actor: User) -> OAuthAccount:
    token, _ = github_token_for(actor)
    try:
        async with GitHubClient(token) as gh:
            profile = await gh.get_user_by_login(login)
    except GitHubError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"GitHub user @{login} not found") from exc
    gh_id = str(profile["id"])
    taken = await db.scalar(
        select(OAuthAccount).where(OAuthAccount.provider == "github", OAuthAccount.provider_user_id == gh_id)
    )
    if taken is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"@{profile['login']} is already linked to another account")
    return OAuthAccount(provider="github", provider_user_id=gh_id, login=profile["login"])


@router.post("", status_code=201)
async def create(body: UserCreate, ctx: Writer, request: Request, db: DB) -> UserOut:
    if not body.password and not body.github_login:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Give the user a password or a GitHub username to sign in with")
    await _roles(db, body.roles, ctx.user)
    account = await _resolve_github(db, body.github_login, ctx.user) if body.github_login else None
    try:
        user = await create_user(
            db, email=str(body.email), password=body.password, full_name=body.full_name, role_names=body.roles
        )
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if account is not None:
        user.oauth_accounts.append(account)
    audit.record(db, "user.create", actor=ctx.user, target=user, summary=f"Created {user.email}", request=request)
    await db.commit()
    return UserOut.of(user)


@router.get("/{user_id}")
async def get_user(user_id: uuid.UUID, ctx: Reader, db: DB) -> UserOut:
    return UserOut.of(await _get(db, user_id))


@router.patch("/{user_id}")
async def update(user_id: uuid.UUID, body: UserUpdate, ctx: Writer, request: Request, db: DB) -> UserOut:
    user = await _get(db, user_id)
    try:
        if body.roles is not None:
            new_roles = await _roles(db, body.roles, ctx.user)
            if "admin" not in body.roles:
                await ensure_not_last_admin(db, user)
            user.roles = new_roles
        if body.is_active is not None and body.is_active != user.is_active:
            if user.id == ctx.user.id:
                raise UserError("You cannot deactivate your own account")
            if not body.is_active:
                await ensure_not_last_admin(db, user)
                await revoke_user_sessions(db, user)
            user.is_active = body.is_active
        if body.full_name is not None:
            user.full_name = body.full_name.strip()
        if body.password:
            check_password_strength(body.password)
            user.password_hash = hash_password(body.password)
            await revoke_user_sessions(db, user)
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    audit.record(
        db, "user.update", actor=ctx.user, target=user, summary=f"Updated {user.email}",
        details=body.model_dump(exclude_none=True, exclude={"password"}), request=request,
    )
    await db.commit()
    await db.refresh(user)
    return UserOut.of(user)


@router.delete("/{user_id}", status_code=204)
async def delete(user_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    user = await _get(db, user_id)
    if user.id == ctx.user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete your own account")
    try:
        await ensure_not_last_admin(db, user)
    except UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    audit.record(db, "user.delete", actor=ctx.user, target=user, summary=f"Deleted {user.email}", request=request)
    await db.delete(user)
    await db.commit()
