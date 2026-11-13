"""Regression tests for the accounts review: user management, credentials, rate limits."""

from __future__ import annotations

import uuid
from types import SimpleNamespace


from slipway.core import security
from slipway.db.session import get_sessionmaker
from slipway.models import OAuthAccount
from tests.conftest import login, make_user

USER_MANAGER = {"name": "user-manager", "permissions": ["users:read", "users:write"]}
NEW_PASSWORD = "attacker-chosen-pw"


async def _token_client(make_client, session_client):
    r = await session_client.post("/api/v1/tokens", json={"name": "ci"})
    assert r.status_code == 201, r.text
    bot = make_client()
    bot.headers["Authorization"] = f"Bearer {r.json()['token']}"
    return bot, r.json()


async def _link_github(user, login_name: str = "octocat") -> None:
    async with get_sessionmaker()() as db:
        db.add(OAuthAccount(user_id=user.id, provider="github", provider_user_id="1001", login=login_name))
        await db.commit()


# ------------------------------------------------------------ users:write dominance


# ------------------------------------------------------------- credential revocation


async def test_admin_lists_and_revokes_another_users_tokens(admin_client, make_client):
    dev = await make_user("dev@example.com", roles=["developer"])
    dev_client = make_client()
    await login(dev_client, "dev@example.com")
    bot, created = await _token_client(make_client, dev_client)
    _, admin_token = await _token_client(make_client, admin_client)

    tokens = (await admin_client.get(f"/api/v1/users/{dev.id}/tokens")).json()
    assert [t["id"] for t in tokens] == [created["id"]] and "token" not in tokens[0]
    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/tokens/{admin_token['id']}")).status_code == 404
    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/tokens/{uuid.uuid4()}")).status_code == 404
    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/tokens/{created['id']}")).status_code == 204
    assert (await bot.get("/api/v1/hosts")).status_code == 401
    actions = [e["action"] for e in (await admin_client.get("/api/v1/audit?action=token.revoke")).json()]
    assert actions == ["token.revoke"]


async def test_user_token_admin_requires_users_write(admin_client, make_client):
    maintainer = make_client()
    await make_user("ops@example.com", roles=["maintainer"])  # users:read, not users:write
    await login(maintainer, "ops@example.com")
    admin = (await admin_client.get("/api/v1/auth/me")).json()
    _, token = await _token_client(make_client, admin_client)
    assert (await maintainer.get(f"/api/v1/users/{admin['id']}/tokens")).status_code == 403
    assert (await maintainer.delete(f"/api/v1/users/{admin['id']}/tokens/{token['id']}")).status_code == 403
    viewer = make_client()
    await make_user("viewer@example.com", roles=["viewer"])
    await login(viewer, "viewer@example.com")
    assert (await viewer.get(f"/api/v1/users/{admin['id']}/tokens")).status_code == 403


# ------------------------------------------------- portal-only credential changes


async def test_api_token_cannot_unlink_github(admin_client, make_client):
    admin = (await admin_client.get("/api/v1/auth/me")).json()
    await _link_github(SimpleNamespace(id=uuid.UUID(admin["id"])))
    bot, _ = await _token_client(make_client, admin_client)
    assert (await bot.delete("/api/v1/auth/me/github")).status_code == 403
    assert (await admin_client.get("/api/v1/auth/me")).json()["github_login"] == "octocat"


# --------------------------------------------------------------------- bearer tokens


async def test_non_ascii_bearer_token_is_rejected(client):
    r = await client.get("/api/v1/auth/me", headers={"Authorization": b"Bearer slipway_pat_\xe9\xff"})
    assert r.status_code == 401


def test_safe_equals():
    assert security.safe_equals("abc", "abc")
    assert not security.safe_equals("éabc", "abc")
    assert not security.safe_equals("\ud800", "")
