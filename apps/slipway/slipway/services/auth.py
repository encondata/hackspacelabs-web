"""Who is calling: Keycloak access tokens (forwarded by the portal gateway) and Slipway API tokens."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.security import API_TOKEN_PREFIX, hash_token
from slipway.db.base import utcnow
from slipway.models import ApiToken, OAuthAccount, User

_TOUCH_INTERVAL = timedelta(minutes=5)


@dataclass
class AuthContext:
    user: User
    # "keycloak": a person signed in to HackSpaceLabs, through the gateway. "token": a personal API token.
    via: Literal["keycloak", "token"]
    token: ApiToken | None = None
    claims: dict[str, Any] = field(default_factory=dict)

    def can(self, permission: str) -> bool:
        return self.user.can(permission)

    @property
    def interactive(self) -> bool:
        return self.via == "keycloak"


async def token_from_bearer(db: AsyncSession, raw: str) -> ApiToken | None:
    """The unexpired API token ``raw``, or None. The owner's Keycloak status is checked by the caller."""
    if not raw.startswith(API_TOKEN_PREFIX):
        return None
    token = await db.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(raw)))
    if token is None:
        return None
    now = utcnow()
    if token.expires_at and token.expires_at <= now:
        return None
    if token.last_used_at is None or now - token.last_used_at > _TOUCH_INTERVAL:
        token.last_used_at = now
        await db.commit()
    return token


async def revoke_user_tokens(db: AsyncSession, user: User) -> None:
    await db.execute(delete(ApiToken).where(ApiToken.user_id == user.id))


async def revoke_user_github(db: AsyncSession, user: User) -> list[str]:
    """Unlink every GitHub account from ``user``. Returns the logins that were linked."""
    logins = [a.login for a in user.oauth_accounts if a.provider == "github"]
    for account in [a for a in user.oauth_accounts if a.provider == "github"]:
        user.oauth_accounts.remove(account)
    await db.flush()
    # Also catch a link a concurrent callback committed after ``user`` was loaded.
    await db.execute(delete(OAuthAccount).where(OAuthAccount.user_id == user.id, OAuthAccount.provider == "github"))
    return logins
