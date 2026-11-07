"""GitHub OAuth: sign in with GitHub, and link GitHub to an existing Kiln account.

Rules for an unknown GitHub identity signing in:

* Already linked to a Kiln user -> sign in as that user.
* Otherwise an account is created only if self-signup is enabled, or the GitHub login /
  one of its orgs is allow-listed (``KILN_GITHUB_ALLOWED_USERS`` / ``_ORGS``), or Kiln has
  no users yet (the first account becomes admin).
* GitHub is never auto-linked to an existing account by email: sign in with your password
  and link GitHub from Settings instead. This prevents account takeover via email reuse.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from kiln.api.deps import DB, OptionalAuth
from kiln.core.config import get_settings
from kiln.models import OAuthAccount
from kiln.services import audit
from kiln.services.auth import create_session, set_session_cookie
from kiln.services.github import GitHubClient, GitHubError, authorize_url, exchange_code
from kiln.services.users import UserError, create_user, user_count

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/github", include_in_schema=False)

STATE_COOKIE = "kiln_oauth"


def safe_next(value: str | None) -> str:
    """Only allow same-site relative redirects."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    return value


def _start(mode: str, next_url: str) -> RedirectResponse:
    settings = get_settings()
    if not settings.github_enabled:
        raise HTTPException(404, "GitHub sign-in is not configured")
    state = secrets.token_urlsafe(24)
    payload = base64.urlsafe_b64encode(json.dumps({"s": state, "m": mode, "n": safe_next(next_url)}).encode())
    response = RedirectResponse(authorize_url(state), status_code=302)
    response.set_cookie(
        STATE_COOKIE, payload.decode(), max_age=600, httponly=True,
        secure=settings.secure_cookies, samesite="lax", path="/auth/github",
    )
    return response


def _fail(message: str, mode: str = "login") -> RedirectResponse:
    target = "/settings" if mode == "link" else "/login"
    response = RedirectResponse(f"{target}?error={quote(message)}", status_code=302)
    response.delete_cookie(STATE_COOKIE, path="/auth/github")
    return response


@router.get("/login")
async def github_login(next: str = "/") -> RedirectResponse:
    return _start("login", next)


@router.get("/link")
async def github_link(ctx: OptionalAuth) -> RedirectResponse:
    if ctx is None:
        return RedirectResponse("/login?next=/settings", status_code=302)
    return _start("link", "/settings")


async def _signup_allowed(db: DB, gh: GitHubClient, login: str) -> bool:
    settings = get_settings()
    if settings.allow_signup or await user_count(db) == 0:
        return True
    if login.lower() in settings.github_allowed_users:
        return True
    if settings.github_allowed_orgs:
        try:
            orgs = await gh.get_org_logins()
        except GitHubError:
            return False
        return bool(orgs & set(settings.github_allowed_orgs))
    return False


@router.get("/callback")
async def github_callback(
    request: Request, db: DB, ctx: OptionalAuth, code: str = "", state: str = "", error: str = ""
) -> RedirectResponse:
    try:
        cookie = json.loads(base64.urlsafe_b64decode(request.cookies.get(STATE_COOKIE, "")))
    except ValueError:
        cookie = {}
    mode = cookie.get("m", "login")
    if error:
        return _fail(f"GitHub sign-in was cancelled ({error})", mode)
    if not code or not state or not secrets.compare_digest(state, str(cookie.get("s", ""))):
        return _fail("GitHub sign-in expired or was tampered with; please try again", mode)

    try:
        token, scopes = await exchange_code(code)
        async with GitHubClient(token) as gh:
            profile = await gh.get_user()
            gh_id, login = str(profile["id"]), profile["login"]
            account = await db.scalar(
                select(OAuthAccount)
                .options(joinedload(OAuthAccount.user))
                .where(OAuthAccount.provider == "github", OAuthAccount.provider_user_id == gh_id)
            )

            if mode == "link":
                if ctx is None:
                    return _fail("Your Kiln session expired; sign in and try again", "login")
                user = ctx.user
                if account is not None and account.user_id != user.id:
                    return _fail(f"@{login} is already linked to another Kiln account", mode)
                if account is None and user.github is not None:
                    return _fail("Unlink your current GitHub account first", mode)
                if account is None:
                    account = OAuthAccount(provider="github", provider_user_id=gh_id, login=login)
                    user.oauth_accounts.append(account)
                audit.record(db, "auth.github_linked", actor=user, target=user, summary=f"Linked @{login}", request=request)

            elif account is not None:
                user = account.user
                if not user.is_active:
                    return _fail("This account has been deactivated")

            else:
                if not await _signup_allowed(db, gh, login):
                    return _fail(f"@{login} is not allowed to sign in to Kiln; ask an admin to invite you")
                email, verified = await gh.get_primary_email()
                if not email or not verified:
                    return _fail("Your GitHub account needs a verified primary email address")
                try:
                    user = await create_user(
                        db, email=email, full_name=profile.get("name") or login, avatar_url=profile.get("avatar_url")
                    )
                except UserError:
                    return _fail(
                        f"A Kiln account already uses {email}. Sign in with your password, "
                        "then link GitHub from Settings."
                    )
                account = OAuthAccount(provider="github", provider_user_id=gh_id, login=login)
                user.oauth_accounts.append(account)
                audit.record(db, "user.register", actor=user, target=user, summary=f"Signed up with GitHub @{login}", request=request)
    except GitHubError as exc:
        log.warning("GitHub OAuth failed: %s", exc)
        return _fail("GitHub sign-in failed; please try again", mode)

    account.login = login
    account.access_token = token
    account.scopes = scopes
    if profile.get("avatar_url"):
        user.avatar_url = profile["avatar_url"]

    if mode == "link":
        await db.commit()
        response = RedirectResponse("/settings?linked=1", status_code=302)
    else:
        raw, _ = await create_session(db, user, request)
        audit.record(db, "auth.login", actor=user, target=user, summary=f"Signed in with GitHub @{login}", request=request)
        await db.commit()
        response = RedirectResponse(safe_next(cookie.get("n")), status_code=302)
        set_session_cookie(response, raw)
    response.delete_cookie(STATE_COOKIE, path="/auth/github")
    return response
