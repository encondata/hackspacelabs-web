"""Append-only audit trail of security-relevant and operational actions."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kiln.db.base import Base, Timestamps, UUIDPrimaryKey
from kiln.models.user import User


class AuditEvent(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "audit_events"

    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. "host.create"
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(String(300), default="")
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    ip: Mapped[str | None] = mapped_column(String(64))

    actor: Mapped[User | None] = relationship(lazy="selectin")
