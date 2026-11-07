from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from kiln.api.deps import DB, require
from kiln.core.permissions import Perm
from kiln.models import AuditEvent
from kiln.schemas import AuditOut
from kiln.services.auth import AuthContext

router = APIRouter(prefix="/audit", tags=["audit"])

MAX_OFFSET = 2**31 - 1  # PostgreSQL binds OFFSET as a 32-bit integer


@router.get("")
async def list_events(
    ctx: Annotated[AuthContext, require(Perm.AUDIT_READ)],
    db: DB,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
    action: Annotated[str | None, Query(max_length=64)] = None,
) -> list[AuditOut]:
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)
    if action:
        stmt = stmt.where(AuditEvent.action.startswith(action, autoescape=True))
    return [
        AuditOut(
            id=e.id,
            action=e.action,
            actor=e.actor.email if e.actor else None,
            target_type=e.target_type,
            target_id=e.target_id,
            summary=e.summary,
            ip=e.ip,
            created_at=e.created_at,
        )
        for e in (await db.scalars(stmt)).all()
    ]
