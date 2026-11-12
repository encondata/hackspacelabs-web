"""Slipway's view of HackSpaceLabs accounts.

People, their sign-in and their Slipway roles are managed in the HackSpaceLabs portal (Keycloak). Here admins can
see who has used Slipway, remove someone's GitHub link, and list or revoke their API tokens.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm, has_permission
from slipway.models import ApiToken, User
from slipway.schemas import TokenOut, UserOut
from slipway.services import audit
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/users", tags=["users"])

Reader = Annotated[AuthContext, require(Perm.USERS_READ)]
Writer = Annotated[AuthContext, require(Perm.USERS_WRITE)]


def _ensure_can_manage(actor: User, target: User) -> None:
    """users:write only reaches users whose every permission the actor holds too."""
    if target.id != actor.id and not all(has_permission(actor.permissions, p) for p in target.permissions):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot manage a user who has permissions you don't have")


async def _get(db: DB, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise not_found("User")
    return user


@router.get("")
async def list_users(ctx: Reader, db: DB) -> list[UserOut]:
    users = (await db.scalars(select(User).order_by(User.created_at))).all()
    return [UserOut.of(u) for u in users]


@router.get("/{user_id}")
async def get_user(user_id: uuid.UUID, ctx: Reader, db: DB) -> UserOut:
    return UserOut.of(await _get(db, user_id))


@router.delete("/{user_id}/github", status_code=204)
async def unlink_user_github(user_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    """Remove a user's GitHub link (one they should no longer deploy with, say). Their account is unaffected."""
    user = await _get(db, user_id)
    _ensure_can_manage(ctx.user, user)
    account = user.github
    if account is None:
        return
    user.oauth_accounts.remove(account)
    audit.record(
        db, "user.github_unlinked", actor=ctx.user, target=user,
        summary=f"Unlinked @{account.login} from {user.display_name}", request=request,
    )
    await db.commit()


@router.get("/{user_id}/tokens")
async def list_user_tokens(user_id: uuid.UUID, ctx: Writer, db: DB) -> list[TokenOut]:
    user = await _get(db, user_id)
    _ensure_can_manage(ctx.user, user)
    tokens = await db.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    )
    return [TokenOut.model_validate(t) for t in tokens]


@router.delete("/{user_id}/tokens/{token_id}", status_code=204)
async def revoke_user_token(user_id: uuid.UUID, token_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    user = await _get(db, user_id)
    _ensure_can_manage(ctx.user, user)
    token = await db.get(ApiToken, token_id)
    if token is None or token.user_id != user.id:
        raise not_found("Token")
    audit.record(
        db, "token.revoke", actor=ctx.user, target=token,
        summary=f"Revoked API token {token.name} of {user.display_name}", request=request,
    )
    await db.delete(token)
    await db.commit()
