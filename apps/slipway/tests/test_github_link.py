"""Connecting GitHub for repository access, through the portal gateway."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select, text

from slipway.api.v1 import auth as auth_api
from slipway.db.session import get_sessionmaker
from slipway.models import OAuthAccount
from slipway.services.github import GitHubError
from tests.conftest import login, make_user

PROFILE = {"id": 1001, "login": "octocat", "avatar_url": "https://avatars.githubusercontent.com/u/1001"}


class FakeGH:
    profile: dict = PROFILE

    def __init__(self, token):
        assert token == "gho_test"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_user(self):
        return self.profile


@pytest.fixture
def gh(monkeypatch):
    async def exchange(code):
        assert code == "good-code"
        return "gho_test", "repo,read:user"

    monkeypatch.setattr(auth_api, "exchange_code", exchange)
    monkeypatch.setattr(auth_api, "GitHubClient", FakeGH)
    FakeGH.profile = PROFILE
    return FakeGH


async def _start(client: httpx.AsyncClient) -> tuple[str, dict]:
    r = await client.post("/api/v1/auth/github/link")
    assert r.status_code == 200, r.text
    url = urlparse(r.json()["authorize_url"])
    return url.geturl(), {k: v[0] for k, v in parse_qs(url.query).items()}


async def _callback(client, state: str, code: str = "good-code", **extra) -> httpx.Response:
    return await client.get("/api/v1/auth/github/callback", params={"code": code, "state": state, **extra})


async def _github_accounts() -> list[OAuthAccount]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(OAuthAccount).where(OAuthAccount.provider == "github"))).all())


async def test_link_points_github_back_at_the_portal_gateway(admin_client):
    url, params = await _start(admin_client)
    assert url.startswith("https://github.com/login/oauth/authorize?")
    assert params["redirect_uri"] == "http://testserver/api/slipway/auth/github/callback"
    assert params["client_id"] == "test-client" and "repo" in params["scope"]


async def test_link_flow_stores_the_token_encrypted_and_returns_to_the_portal(admin_client, gh):
    _, params = await _start(admin_client)
    r = await _callback(admin_client, params["state"])
    assert r.status_code == 302 and r.headers["location"] == "/portal?github=linked"
    [account] = await _github_accounts()
    assert (account.login, account.access_token) == ("octocat", "gho_test")
    async with get_sessionmaker()() as db:
        raw = await db.scalar(text("SELECT access_token FROM oauth_accounts WHERE provider = 'github'"))
    assert "gho_test" not in raw
    me = (await admin_client.get("/api/v1/auth/me")).json()
    assert me["github_login"] == "octocat" and me["avatar_url"] == PROFILE["avatar_url"]


async def test_state_minted_for_someone_else_is_refused(admin_client, make_client, gh):
    _, params = await _start(admin_client)
    await make_user("dev@example.com", roles=["developer"])
    victim = make_client()
    await login(victim, "dev@example.com")
    r = await _callback(victim, params["state"])
    assert r.headers["location"] == "/portal?github_error=state"
    assert await _github_accounts() == []


@pytest.mark.parametrize(
    "state", ["", "abc", "a.b.c", "x.notdigits.sig", "é.1.x", "nonce.9999999999.0000000000000000000000000000000000000000000000000000000000000000"]
)
async def test_forged_or_malformed_state_is_refused(admin_client, gh, state):
    r = await _callback(admin_client, state)
    assert r.status_code == 302 and r.headers["location"] == "/portal?github_error=state"


async def test_expired_state_is_refused(admin_client, gh):
    me = (await admin_client.get("/api/v1/auth/me")).json()
    old = auth_api.make_state(me["id"], now=time.time() - auth_api.STATE_TTL_SECONDS - 5)
    assert (await _callback(admin_client, old)).headers["location"] == "/portal?github_error=state"
    assert auth_api.state_valid(auth_api.make_state(me["id"]), me["id"])


async def test_github_cancel_and_failures_are_codes(admin_client, gh, monkeypatch):
    _, params = await _start(admin_client)
    r = await admin_client.get("/api/v1/auth/github/callback", params={"error": "access_denied", "state": params["state"]})
    assert r.headers["location"] == "/portal?github_error=cancelled"

    async def failing(code):
        raise GitHubError("down")

    monkeypatch.setattr(auth_api, "exchange_code", failing)
    assert (await _callback(admin_client, params["state"])).headers["location"] == "/portal?github_error=failed"


async def test_github_account_linked_to_someone_else_is_refused(admin_client, make_client, gh):
    _, params = await _start(admin_client)
    assert (await _callback(admin_client, params["state"])).headers["location"] == "/portal?github=linked"
    await make_user("dev@example.com", roles=["developer"])
    dev = make_client()
    await login(dev, "dev@example.com")
    _, params = await _start(dev)
    assert (await _callback(dev, params["state"])).headers["location"] == "/portal?github_error=already_linked"


async def test_linking_another_github_account_replaces_the_link(admin_client, gh):
    _, params = await _start(admin_client)
    await _callback(admin_client, params["state"])
    FakeGH.profile = {"id": 2002, "login": "hubot"}
    _, params = await _start(admin_client)
    assert (await _callback(admin_client, params["state"])).headers["location"] == "/portal?github=linked"
    [account] = await _github_accounts()
    assert account.login == "hubot"


async def test_unlink_needs_a_portal_sign_in(admin_client, make_client, gh):
    _, params = await _start(admin_client)
    await _callback(admin_client, params["state"])
    raw = (await admin_client.post("/api/v1/tokens", json={"name": "ci"})).json()["token"]
    bot = make_client()
    bot.headers["Authorization"] = f"Bearer {raw}"
    assert (await bot.delete("/api/v1/auth/me/github")).status_code == 403
    assert (await admin_client.delete("/api/v1/auth/me/github")).status_code == 204
    assert await _github_accounts() == []


async def test_admin_can_unlink_another_users_github(admin_client, make_client, gh):
    await make_user("dev@example.com", roles=["developer"])
    dev = make_client()
    await login(dev, "dev@example.com")
    _, params = await _start(dev)
    await _callback(dev, params["state"])
    dev_id = (await dev.get("/api/v1/auth/me")).json()["id"]
    assert (await dev.delete(f"/api/v1/users/{dev_id}/github")).status_code == 403  # developer: no users:write
    assert (await admin_client.delete(f"/api/v1/users/{dev_id}/github")).status_code == 204
    assert await _github_accounts() == []


async def test_link_is_unavailable_without_a_github_app(admin_client, monkeypatch):
    from slipway.core.config import get_settings

    monkeypatch.setattr(get_settings(), "github_client_id", None)
    assert (await admin_client.post("/api/v1/auth/github/link")).status_code == 404
