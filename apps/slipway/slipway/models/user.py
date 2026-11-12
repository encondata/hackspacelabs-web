"""Accounts, roles, linked OAuth identities, browser sessions and API tokens."""

from __future__ import annotations

import uuid
from datetime import datetime
from sqlalchemy import Column, ForeignKey, String, Table, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from slipway.core.crypto import EncryptedText
from slipway.core.permissions import has_permission
from slipway.db.base import Base, Timestamps, UUIDPrimaryKey

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Uuid, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class Role(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    permissions: Mapped[list[str]] = mapped_column(default=list)
    is_system: Mapped[bool] = mapped_column(default=False)


class User(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    # Null for accounts that only sign in with GitHub.
    password_hash: Mapped[str | None] = mapped_column(String(255))
    avatar_url: Mapped[str | None] = mapped_column(String(500))
    is_active: Mapped[bool] = mapped_column(default=True)
    last_login_at: Mapped[datetime | None]

    roles: Mapped[list[Role]] = relationship(secondary=user_roles, lazy="selectin")
    oauth_accounts: Mapped[list[OAuthAccount]] = relationship(
        back_populates="user", lazy="selectin", cascade="all, delete-orphan"
    )

    @property
    def permissions(self) -> frozenset[str]:
        return frozenset(p for role in self.roles for p in role.permissions)

    def can(self, permission: str) -> bool:
        return self.is_active and has_permission(self.permissions, permission)

    @property
    def is_admin(self) -> bool:
        return "*" in self.permissions

    @property
    def display_name(self) -> str:
        return self.full_name or self.email.split("@", 1)[0]

    @property
    def initials(self) -> str:
        parts = self.display_name.replace(".", " ").split()
        return "".join(p[0] for p in parts[:2]).upper() or "?"

    @property
    def role_names(self) -> list[str]:
        return sorted(r.name for r in self.roles)

    @property
    def github(self) -> OAuthAccount | None:
        return next((a for a in self.oauth_accounts if a.provider == "github"), None)


class OAuthAccount(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "oauth_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_user_id"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    provider_user_id: Mapped[str] = mapped_column(String(64))
    login: Mapped[str] = mapped_column(String(100))
    access_token: Mapped[str | None] = mapped_column(EncryptedText)
    scopes: Mapped[str] = mapped_column(String(500), default="")

    user: Mapped[User] = relationship(back_populates="oauth_accounts")


class UserSession(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))

    user: Mapped[User] = relationship(lazy="joined")


class ApiToken(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "api_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    prefix: Mapped[str] = mapped_column(String(20))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    last_used_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]

    user: Mapped[User] = relationship(lazy="joined")
