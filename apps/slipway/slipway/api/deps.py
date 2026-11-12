"""Authentication and permission dependencies.

Slipway is only reachable through the HackSpaceLabs gateway, which handles browser sessions, CSRF and
origin checks. Every request carries ``Authorization: Bearer <token>``: a Keycloak access token for a
signed-in person (verified here, never trusted on the gateway's word), or a Slipway API token.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.core.security import API_TOKEN_PREFIX
from slipway.db.session import get_db
from slipway.services.auth import AuthContext, token_from_bearer
from slipway.services.identity import refresh_owner, user_for_claims
from slipway.services.oidc import IdentityUnavailable, TokenError, owners, verify_access_token

DB = Annotated[AsyncSession, Depends(get_db)]

UNAVAILABLE = "Sign-in service unavailable; try again shortly"


async def get_optional_auth(request: Request, db: DB) -> AuthContext | None:
    authz = request.headers.get("authorization", "")
    ctx: AuthContext | None = None
    if authz[:7].lower() == "bearer ":
        raw = authz[7:].strip()
        try:
            if raw.startswith(API_TOKEN_PREFIX):
                token = await token_from_bearer(db, raw)
                if token is None or token.user.keycloak is None:
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API token")
                owner = await owners.get(token.user.keycloak.provider_user_id)
                user = await refresh_owner(db, token.user, owner, request)
                if not user.is_active:
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The owner of this API token is disabled in HackSpaceLabs")
                ctx = AuthContext(user=user, via="token", token=token)
            else:
                claims = await verify_access_token(raw)
                ctx = AuthContext(user=await user_for_claims(db, claims, request), via="keycloak", claims=claims)
        except TokenError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
        except IdentityUnavailable as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, UNAVAILABLE) from exc
    request.state.auth = ctx
    return ctx


OptionalAuth = Annotated[AuthContext | None, Depends(get_optional_auth)]


async def get_auth(ctx: OptionalAuth) -> AuthContext:
    if ctx is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return ctx


Auth = Annotated[AuthContext, Depends(get_auth)]


async def get_interactive(ctx: Auth) -> AuthContext:
    """A person signed in to HackSpaceLabs, not an API token (creating tokens, linking GitHub)."""
    if not ctx.interactive:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This can only be done from the HackSpaceLabs portal")
    return ctx


Interactive = Annotated[AuthContext, Depends(get_interactive)]


def require(*permissions: str):
    """Dependency factory: ``ctx: Annotated[AuthContext, require(Perm.HOSTS_READ)]``."""

    async def checker(ctx: Auth) -> AuthContext:
        missing = [p for p in permissions if not ctx.can(p)]
        if missing:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {', '.join(missing)}")
        return ctx

    return Depends(checker)


def not_found(what: str = "Resource") -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")
