"""Personal API tokens (``Authorization: Bearer slipway_pat_...``) for scripts and CI."""

from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import select

from slipway.api.deps import DB, Auth, Interactive, not_found
from slipway.core.security import API_TOKEN_PREFIX, hash_token, new_api_token
from slipway.db.base import utcnow
from slipway.models import ApiToken
from slipway.schemas import TokenCreate, TokenCreated, TokenOut
from slipway.services import audit

router = APIRouter(prefix="/tokens", tags=["tokens"])


@router.get("")
async def list_tokens(ctx: Auth, db: DB) -> list[TokenOut]:
    tokens = await db.scalars(
        select(ApiToken).where(ApiToken.user_id == ctx.user.id).order_by(ApiToken.created_at.desc())
    )
    return [TokenOut.model_validate(t) for t in tokens]


@router.post("", status_code=201)
async def create_token(body: TokenCreate, ctx: Interactive, request: Request, db: DB) -> TokenCreated:
    raw = new_api_token()
    token = ApiToken(
        user_id=ctx.user.id,
        name=body.name,
        # Shown in lists to tell tokens apart: the fixed prefix plus 7 random characters (column is 20 wide).
        prefix=raw[: len(API_TOKEN_PREFIX) + 7],
        token_hash=hash_token(raw),
        expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(token)
    await db.flush()
    audit.record(db, "token.create", actor=ctx.user, target=token, summary=f"Created API token {body.name}", request=request)
    await db.commit()
    return TokenCreated(**TokenOut.model_validate(token).model_dump(), token=raw)


@router.delete("/{token_id}", status_code=204)
async def revoke_token(token_id: uuid.UUID, ctx: Auth, request: Request, db: DB) -> None:
    token = await db.get(ApiToken, token_id)
    if token is None or token.user_id != ctx.user.id:
        raise not_found("Token")
    audit.record(db, "token.revoke", actor=ctx.user, target=token, summary=f"Revoked API token {token.name}", request=request)
    await db.delete(token)
    await db.commit()
