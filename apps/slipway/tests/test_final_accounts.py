"""Regression tests for the final accounts review: GitHub links as credentials (12) and the
SLIPWAY_ADMIN_EMAIL first-admin seat (13), plus the fix-up round (the stale-session link page, and
reactivating an account that deactivation left with no way to sign in)."""

from __future__ import annotations

import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import func, select

from slipway import cli
from slipway.core.config import get_settings
from slipway.db.base import utcnow
from slipway.db.session import get_sessionmaker
from slipway.models import OAuthAccount, User
from slipway.services import users as users_service
from slipway.services.auth import SESSION_COOKIE, create_session
from slipway.services.users import UserError, bootstrap, create_user, get_user_by_email
from slipway.web import oauth
from tests.conftest import PASSWORD, login, make_user

PROFILE = {"id": 1001, "login": "octocat", "name": "Mona Octocat", "avatar_url": "https://avatars.githubusercontent.com/u/1001"}
USER_MANAGER = {"name": "user-manager", "permissions": ["users:read", "users:write"]}
SHORT_PASSWORD = "Tr0ub4d0r"  # 9 characters: too short, so bootstrap creates no admin
ADMIN_PASSWORD = "a-long-admin-password"


class FakeGH:
    profile: dict = PROFILE
    email = ("mona@example.com", True)
    orgs: list[dict] = []

    def __init__(self, token):
        assert token == "gho_test"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_user(self):
        return self.profile

    async def get_primary_email(self):
        return self.email

    async def get_orgs(self):
        return self.orgs


@pytest.fixture
def gh(monkeypatch):
    async def exchange(code):
        assert code == "good-code"
        return "gho_test", "read:user,user:email,repo"

    monkeypatch.setattr(oauth, "exchange_code", exchange)
    monkeypatch.setattr(oauth, "GitHubClient", FakeGH)
    FakeGH.profile, FakeGH.email, FakeGH.orgs = PROFILE, ("mona@example.com", True), []
    return FakeGH


async def _github_flow(client: httpx.AsyncClient, path: str = "/auth/github/login?next=/hosts") -> httpx.Response:
    """Start an OAuth flow at ``path`` and finish it at the callback with the mocked GitHub."""
    r = await client.get(path)
    assert r.status_code == 302 and urlparse(r.headers["location"]).netloc == "github.com", r.headers["location"]
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    return await client.get(f"/auth/github/callback?code=good-code&state={state}")


async def _me(client: httpx.AsyncClient) -> dict | None:
    r = await client.get("/api/v1/auth/me")
    return r.json()["user"] if r.status_code == 200 else None


async def _link_github(user: User, login_name: str = "octocat", github_id: str = "1001") -> None:
    async with get_sessionmaker()() as db:
        db.add(OAuthAccount(user_id=user.id, provider="github", provider_user_id=github_id, login=login_name))
        await db.commit()


async def _session_client(make_client, user: User, *, age: timedelta = timedelta(0)) -> httpx.AsyncClient:
    """A browser-like client signed in as ``user`` (with or without a password), ``age`` ago."""
    async with get_sessionmaker()() as db:
        raw, session = await create_session(db, await db.get(User, user.id), None)
        session.created_at = utcnow() - age
        await db.commit()
        csrf = session.csrf_token
    c = make_client()
    c.cookies.set(SESSION_COOKIE, raw)  # in the jar, so the OAuth state cookie is sent alongside it
    c.headers["X-CSRF-Token"] = csrf
    return c


async def _user(email: str) -> User:
    async with get_sessionmaker()() as db:
        user = await get_user_by_email(db, email)
        assert user is not None
        return user


async def _github_of(email: str) -> str | None:
    user = await _user(email)
    return user.github.login if user.github else None


async def _user_count() -> int:
    async with get_sessionmaker()() as db:
        return int(await db.scalar(select(func.count()).select_from(User)) or 0)


async def _create_admin(*argv: str) -> list[str]:
    args = cli.build_parser().parse_args(["create-admin", *argv])
    async with get_sessionmaker()() as db:
        lines = await cli._ensure_admin(db, args)
        await db.commit()
    return lines


# ------------------------------------------- 12: a GitHub link is a credential too


async def test_admin_password_reset_unlinks_github(admin_client, make_client, gh):
    victim = await make_user("victim@example.com", roles=["maintainer"])
    await _link_github(victim, "mallory")  # planted with a stolen session

    r = await admin_client.patch(f"/api/v1/users/{victim.id}", json={"password": "brand-new-password-123"})
    assert r.status_code == 200 and r.json()["github_login"] is None
    attacker = make_client()
    r = await _github_flow(attacker)
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"
    assert await _me(attacker) is None
    await login(make_client(), "victim@example.com", "brand-new-password-123")


async def test_deactivation_unlinks_github(admin_client, make_client, gh):
    dev = await make_user("dev@example.com", roles=["developer"])
    await _link_github(dev)
    r = await admin_client.patch(f"/api/v1/users/{dev.id}", json={"is_active": False})
    assert r.status_code == 200 and r.json()["github_login"] is None
    r = await admin_client.patch(f"/api/v1/users/{dev.id}", json={"is_active": True})
    assert r.status_code == 200 and r.json()["github_login"] is None
    r = await _github_flow(make_client())
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"


async def test_create_admin_reset_password_unlinks_github(make_client, gh):
    await make_user("admin@example.com")
    ops = await make_user("ops@example.com", roles=["viewer"])
    await _link_github(ops, "mallory")

    lines = await _create_admin("ops@example.com", "--reset-password", "--password", "a-fresh-password")
    assert "GitHub: @mallory" in lines[0]
    assert "Password reset; signed out 0 session(s) and deleted 0 API token(s)." in lines
    assert any(line.startswith("Unlinked GitHub @mallory;") for line in lines)
    assert await _github_of("ops@example.com") is None
    r = await _github_flow(make_client())  # the planted link no longer reaches the new admin
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"


async def test_create_admin_reset_password_help_mentions_github(capsys):
    await make_user("admin@example.com")
    await make_user("ops@example.com", roles=["viewer"])
    lines = await _create_admin("ops@example.com", "--reset-password", "--password", "a-fresh-password")
    assert not any("Unlinked GitHub" in line for line in lines)  # nothing to unlink, nothing said
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["create-admin", "--help"])
    assert "and unlink GitHub" in " ".join(capsys.readouterr().out.split())


@pytest.mark.parametrize("has_password", [True, False])
async def test_linking_github_needs_a_recent_sign_in(make_client, gh, has_password):
    await make_user("admin@example.com")
    mona = await make_user("mona@example.com", roles=["developer"], password=PASSWORD if has_password else None)
    if not has_password:
        await _link_github(mona)  # GitHub-only: "Re-authorize" starts the same flow

    stale = await _session_client(make_client, mona, age=timedelta(days=3))  # a replayed, stolen cookie
    r = await stale.get("/auth/github/link")
    # No OAuth flow starts, and the page says what to do (a redirect with an unmapped ?error= code would
    # only show the generic "Sign-in failed").
    assert r.status_code == 403 and "location" not in r.headers
    assert not r.cookies.get(oauth.STATE_COOKIE)
    action = "link GitHub" if has_password else "re-authorize GitHub"
    assert f"Sign out and sign in again, then {action} within 15 minutes." in r.text
    assert "Sign-in failed" not in r.text

    fresh = await _session_client(make_client, mona)
    r = await _github_flow(fresh, "/auth/github/link")
    assert r.headers["location"] == "/settings?linked=1"
    assert (await _me(fresh))["github_login"] == "octocat"


async def test_unlinking_github_needs_a_recent_sign_in(make_client):
    await make_user("admin@example.com")
    mona = await make_user("mona@example.com", roles=["developer"])
    await _link_github(mona)

    stale = await _session_client(make_client, mona, age=timedelta(minutes=20))
    r = await stale.delete("/api/v1/auth/me/github")
    assert r.status_code == 403
    assert r.json()["detail"] == "Sign out and sign in again, then unlink GitHub within 15 minutes"
    assert await _github_of("mona@example.com") == "octocat"

    fresh = make_client()
    await login(fresh, "mona@example.com")
    assert (await fresh.delete("/api/v1/auth/me/github")).status_code == 204
    assert await _github_of("mona@example.com") is None


async def test_admin_can_unlink_another_users_github(admin_client, make_client, gh):
    dev = await make_user("dev@example.com", roles=["developer"])
    await _link_github(dev, "mallory")
    dev_client = make_client()
    await login(dev_client, "dev@example.com")

    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/github")).status_code == 204
    assert (await admin_client.get(f"/api/v1/users/{dev.id}")).json()["github_login"] is None
    events = (await admin_client.get("/api/v1/audit?action=user.github_unlinked")).json()
    assert [(e["summary"], e["actor"]) for e in events] == [("Unlinked @mallory from dev@example.com", "admin@example.com")]
    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/github")).status_code == 204  # nothing left
    assert len((await admin_client.get("/api/v1/audit?action=user.github_unlinked")).json()) == 1

    r = await _github_flow(make_client())
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"
    assert (await _me(dev_client))["email"] == "dev@example.com"  # only the link goes; sessions stay


async def test_admin_unlink_needs_users_write_and_dominance(admin_client, make_client):
    assert (await admin_client.post("/api/v1/roles", json=USER_MANAGER)).status_code == 201
    await make_user("um@example.com", roles=["user-manager"])
    um = make_client()
    await login(um, "um@example.com")
    admin = await _user("admin@example.com")
    await _link_github(admin)

    assert (await um.delete(f"/api/v1/users/{admin.id}/github")).status_code == 403  # admin holds more than um
    r = await admin_client.delete(f"/api/v1/users/{admin.id}/github")
    assert r.status_code == 400 and "/api/v1/auth/me/github" in r.json()["detail"]
    assert await _github_of("admin@example.com") == "octocat"

    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    assert (await viewer.delete(f"/api/v1/users/{admin.id}/github")).status_code == 403

    # The link is a GitHub-only user's only way in: the users page offers Reset password instead.
    github_only = await make_user("mona@example.com", roles=[], password=None)
    await _link_github(github_only, "mona", "2002")
    r = await um.delete(f"/api/v1/users/{github_only.id}/github")
    assert r.status_code == 400 and "reset their password" in r.json()["detail"]
    assert await _github_of("mona@example.com") == "mona"


async def test_reactivating_a_github_only_account_needs_a_password(admin_client, make_client, gh):
    mona = await make_user("mona@example.com", roles=["developer"], password=None)
    await _link_github(mona)
    assert (await _github_flow(make_client())).headers["location"] == "/hosts"
    r = await admin_client.patch(f"/api/v1/users/{mona.id}", json={"is_active": False})
    assert r.status_code == 200 and r.json()["github_login"] is None  # deactivation unlinked GitHub

    r = await admin_client.patch(f"/api/v1/users/{mona.id}", json={"is_active": True})
    assert r.status_code == 400
    assert r.json()["detail"] == (
        "mona@example.com has no password or GitHub link to sign in with (deactivating unlinks GitHub); "
        "set a password to reactivate it"
    )
    assert (await admin_client.get(f"/api/v1/users/{mona.id}")).json()["is_active"] is False

    r = await admin_client.patch(f"/api/v1/users/{mona.id}", json={"is_active": True, "password": "brand-new-password-123"})
    assert r.status_code == 200 and r.json()["is_active"] is True
    await login(make_client(), "mona@example.com", "brand-new-password-123")


async def test_create_admin_does_not_reactivate_an_account_with_no_way_in(admin_client, make_client):
    mona = await make_user("mona@example.com", roles=["developer"], password=None)
    await _link_github(mona)
    assert (await admin_client.patch(f"/api/v1/users/{mona.id}", json={"is_active": False})).status_code == 200

    with pytest.raises(UserError, match="add --reset-password to reactivate it"):
        await _create_admin("mona@example.com", "--activate")
    user = await _user("mona@example.com")
    assert not user.is_active and user.role_names == ["developer"]  # nothing was changed

    lines = await _create_admin("mona@example.com")  # grants admin, says nobody can sign in to it
    assert "It has no password or GitHub link, so nobody can sign in to it (use --reset-password)." in lines

    lines = await _create_admin("mona@example.com", "--activate", "--reset-password", "--password", "a-fresh-password")
    assert "Account reactivated." in lines
    assert (await login(make_client(), "mona@example.com", "a-fresh-password"))["user"]["roles"] == ["admin", "developer"]


# -------------------------------------------- 13: SLIPWAY_ADMIN_EMAIL reserves the first admin


@pytest.fixture
def reserve(monkeypatch, caplog):
    """Set SLIPWAY_ADMIN_EMAIL with a too-short password and run bootstrap, which creates no admin."""
    caplog.set_level(logging.INFO)

    async def run() -> None:
        monkeypatch.setattr(get_settings(), "admin_email", "ops@corp.example")
        monkeypatch.setattr(get_settings(), "admin_password", SHORT_PASSWORD)
        async with get_sessionmaker()() as db:
            await bootstrap(db)
        assert await _user_count() == 0

    return run


@pytest.mark.parametrize(
    "setting", [None, ("github_allowed_users", ["octocat"]), ("github_allowed_orgs", ["acme"]), ("allow_signup", True)]
)
async def test_reserved_admin_seat_is_not_claimable_with_github(client, gh, monkeypatch, reserve, caplog, setting):
    await reserve()
    if setting:
        monkeypatch.setattr(get_settings(), *setting)
    gh.orgs = [{"id": 77, "login": "acme"}]
    r = await _github_flow(client)
    assert r.headers["location"] == "/login?error=config"
    assert await _me(client) is None and await _user_count() == 0
    assert "SLIPWAY_ADMIN_EMAIL reserves the first account" in caplog.text


async def test_slipway_create_admin_fills_the_reserved_seat(make_client, gh, monkeypatch, reserve):
    await reserve()
    assert (await _github_flow(make_client())).headers["location"] == "/login?error=config"

    assert await _create_admin("ops@corp.example", "--password", ADMIN_PASSWORD) == ["Created admin ops@corp.example."]
    data = await login(make_client(), "ops@corp.example", ADMIN_PASSWORD)
    assert data["user"]["roles"] == ["admin"]
    r = await _github_flow(make_client())  # no allowlist, and Slipway has its admin now
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"
    monkeypatch.setattr(get_settings(), "github_allowed_users", ["octocat"])
    member = make_client()
    await _github_flow(member)
    assert (await _me(member))["roles"] == ["viewer"]


async def test_reserved_admin_seat_is_not_claimable_by_registering(make_client, monkeypatch, reserve):
    await reserve()
    monkeypatch.setattr(get_settings(), "allow_signup", True)
    body = {"email": "eve@evil.example", "password": "long-enough-pw"}
    r = await make_client().post("/api/v1/auth/register", json=body)
    assert r.status_code == 403
    assert "server log" in r.json()["detail"] and "slipway create-admin" in r.json()["detail"]
    assert await _user_count() == 0

    async with get_sessionmaker()() as db:
        await create_user(db, email="ops@corp.example", password=ADMIN_PASSWORD, allow_first_admin=True)
        await db.commit()
    r = await make_client().post("/api/v1/auth/register", json=body)
    assert r.status_code == 201 and r.json()["user"]["roles"] == ["viewer"]


async def test_create_user_keeps_the_first_admin_seat(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_email", "ops@corp.example")
    async with get_sessionmaker()() as db:
        for allow in (None, False):
            with pytest.raises(UserError, match="SLIPWAY_ADMIN_EMAIL"):
                await create_user(db, email="eve@evil.example", password=PASSWORD, allow_first_admin=allow)
        user = await create_user(db, email="ops@corp.example", password=PASSWORD, allow_first_admin=True)
        assert user.role_names == ["admin"]
        # Once an admin exists the flag no longer matters.
        assert (await create_user(db, email="dev@example.com", allow_first_admin=False)).role_names == ["viewer"]

    monkeypatch.setattr(get_settings(), "admin_email", None)
    async with get_sessionmaker()() as db:  # nothing was committed: still empty
        with pytest.raises(UserError, match="slipway create-admin"):
            await create_user(db, email="eve@evil.example", password=PASSWORD, allow_first_admin=False)
        assert (await create_user(db, email="first@example.com", password=PASSWORD)).role_names == ["admin"]


async def test_signup_check_refuses_the_reserved_seat(gh, monkeypatch):
    async with get_sessionmaker()() as db:
        assert await oauth._signup_allowed(db, gh("gho_test"), PROFILE) is True
        monkeypatch.setattr(get_settings(), "admin_email", "ops@corp.example")
        assert await oauth._signup_allowed(db, gh("gho_test"), PROFILE) is False


async def test_login_page_does_not_advertise_the_reserved_seat(client, reserve):
    assert "the first account becomes admin" in (await client.get("/login")).text
    await reserve()
    page = " ".join((await client.get("/login")).text.split())
    assert "the first account becomes admin" not in page
    assert "the configured admin was not created; check the server log" in page
    assert "ops@corp.example" not in page


async def test_bootstrap_logs_admin_email_without_password(make_client, gh, monkeypatch, caplog):
    monkeypatch.setattr(get_settings(), "admin_email", "ops@corp.example")
    with caplog.at_level(logging.ERROR, logger=users_service.log.name):
        async with get_sessionmaker()() as db:
            await bootstrap(db)
    assert "SLIPWAY_ADMIN_PASSWORD is not set" in caplog.text and "cannot create the first account" in caplog.text
    r = await _github_flow(make_client())
    assert r.headers["location"] == "/login?error=config"


async def test_bootstrap_warns_when_admin_email_matches_no_account(monkeypatch, caplog):
    await make_user("someone@example.com")  # say, a stranger who claimed the seat first
    monkeypatch.setattr(get_settings(), "admin_email", "ops@corp.example")
    monkeypatch.setattr(get_settings(), "admin_password", ADMIN_PASSWORD)

    async def warnings() -> list[str]:
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger=users_service.log.name):
            async with get_sessionmaker()() as db:
                await bootstrap(db)
        return [r.getMessage() for r in caplog.records if r.name == users_service.log.name]

    found = await warnings()
    assert len(found) == 1 and found[0].startswith("SLIPWAY_ADMIN_EMAIL=ops@corp.example is set, but Slipway already has users")
    assert await _user_count() == 1
    monkeypatch.setattr(get_settings(), "admin_email", "someone@example.com")
    assert await warnings() == []
