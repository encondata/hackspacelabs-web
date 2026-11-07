from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter
from sqlalchemy import select

from kiln.api.deps import DB, require
from kiln.core.permissions import Perm
from kiln.models import AuditEvent
from kiln.schemas import AuditOut
from kiln.services.auth import AuthContext

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_events(
    ctx: Annotated[AuthContext, require(Perm.AUDIT_READ)], db: DB, limit: int = 100, offset: int = 0, action: str | None = None
) -> list[AuditOut]:
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(min(limit, 500)).offset(max(offset, 0))
    if action:
        stmt = stmt.where(AuditEvent.action.startswith(action))
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
