"""The signed-in user, and connecting GitHub for repository access.

Signing in happens in the HackSpaceLabs portal (Keycloak); there are no Slipway passwords or sessions. GitHub is
not a way to sign in: it is linked so Slipway can sync a person's repositories and deploy with their access.

Connecting GitHub (through the gateway, so the browser stays on the portal's origin):

1. ``POST /auth/github/link`` returns GitHub's authorize URL. Its ``state`` is signed with ``SLIPWAY_SECRET_KEY``,
   bound to the Slipway user who asked, and expires after 10 minutes.
2. GitHub redirects the browser to ``<portal>/api/slipway/auth/github/callback``. The gateway attaches that
   person's access token, so the callback knows who is completing the link and refuses a state minted for
   anyone else (a link planted from another account, or a replayed authorization).
3. The callback redirects back to the portal with ``?github=linked`` or ``?github_error=<code>``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from slipway.api.deps import DB, Auth, Interactive
from slipway.core.config import get_settings
from slipway.core.security import safe_equals
from slipway.models import OAuthAccount
from slipway.schemas import GitHubLinkStart, UserOut
from slipway.services import audit
from slipway.services.github import GitHubClient, GitHubError, authorize_url, exchange_code

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

STATE_TTL_SECONDS = 600


def _sign(user_id: str, nonce: str, expires: str) -> str:
    message = "|".join(("slipway-github-link", user_id, nonce, expires)).encode()
    return hmac.new(get_settings().secret_key.encode(), message, hashlib.sha256).hexdigest()


def make_state(user_id: str, *, now: float | None = None) -> str:
    nonce = secrets.token_urlsafe(18)
    expires = str(int((now if now is not None else time.time()) + STATE_TTL_SECONDS))
    return f"{nonce}.{expires}.{_sign(user_id, nonce, expires)}"


def state_valid(state: str, user_id: str, *, now: float | None = None) -> bool:
    parts = state.split(".") if state.isascii() else []
    if len(parts) != 3 or not parts[1].isdigit():
        return False
    nonce, expires, signature = parts
    if int(expires) < (now if now is not None else time.time()):
        return False
    return safe_equals(signature, _sign(user_id, nonce, expires))


def _back(**params: str) -> RedirectResponse:
    # A relative URL on the portal's origin: the gateway serves this API on the same host.
    return RedirectResponse(f"{get_settings().portal_return_path}?{urlencode(params)}", status_code=302)


@router.get("/me")
async def me(ctx: Auth) -> UserOut:
    return UserOut.of(ctx.user)


@router.post("/github/link")
async def start_github_link(ctx: Interactive) -> GitHubLinkStart:
    if not get_settings().github_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitHub is not configured for Slipway")
    return GitHubLinkStart(authorize_url=authorize_url(make_state(str(ctx.user.id))))


@router.get("/github/callback", include_in_schema=False)
async def github_callback(
    ctx: Interactive, request: Request, db: DB, code: str = "", state: str = "", error: str = ""
) -> RedirectResponse:
    if error:
        if error != "access_denied":
            log.warning("GitHub OAuth returned error %r", error[:100])
        return _back(github_error="cancelled" if error == "access_denied" else "failed")
    if not code or not state_valid(state, str(ctx.user.id)):
        return _back(github_error="state")
    user = ctx.user
    try:
        token, scopes = await exchange_code(code)
        async with GitHubClient(token) as gh:
            profile = await gh.get_user()
    except GitHubError as exc:
        log.warning("GitHub OAuth failed: %s", exc)
        return _back(github_error="failed")
    gh_id, login = str(profile["id"]), str(profile["login"])[:100]
    account = await db.scalar(
        select(OAuthAccount)
        .options(joinedload(OAuthAccount.user))
        .where(OAuthAccount.provider == "github", OAuthAccount.provider_user_id == gh_id)
    )
    if account is not None and account.user_id != user.id:
        return _back(github_error="already_linked")
    if account is None:
        # Connecting a different GitHub account replaces the previous link.
        if (previous := user.github) is not None:
            user.oauth_accounts.remove(previous)
            await db.flush()
        account = OAuthAccount(provider="github", provider_user_id=gh_id, login=login)
        user.oauth_accounts.append(account)
    account.login = login
    account.access_token = token
    account.scopes = scopes[:500]
    avatar = profile.get("avatar_url")
    if isinstance(avatar, str) and len(avatar) <= 500:
        user.avatar_url = avatar
    audit.record(db, "auth.github_linked", actor=user, target=user, summary=f"Linked @{login}", request=request)
    await db.commit()
    return _back(github="linked")


@router.delete("/me/github", status_code=204)
async def unlink_github(ctx: Interactive, request: Request, db: DB) -> None:
    account = ctx.user.github
    if account is None:
        return
    ctx.user.oauth_accounts.remove(account)
    audit.record(db, "auth.github_unlinked", actor=ctx.user, target=ctx.user, summary=f"Unlinked @{account.login}", request=request)
    await db.commit()
