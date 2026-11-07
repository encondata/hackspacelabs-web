"""Record audit events. Callers commit as part of their own transaction."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from kiln.models import AuditEvent, User


def client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


def record(
    db: AsyncSession,
    action: str,
    *,
    actor: User | None = None,
    target: Any = None,
    target_type: str | None = None,
    summary: str = "",
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditEvent:
    if target is not None and target_type is None:
        target_type = type(target).__name__.lower()
    event = AuditEvent(
        actor_id=actor.id if actor else None,
        action=action,
        target_type=target_type,
        target_id=str(getattr(target, "id", target)) if target is not None else None,
        summary=summary[:300],
        details=details or {},
        ip=client_ip(request),
    )
    db.add(event)
    return event
