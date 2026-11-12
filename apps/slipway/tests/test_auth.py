import pytest

from slipway.core.permissions import has_permission, validate_permissions
from tests.conftest import PASSWORD, login, make_user


async def test_first_user_is_admin_and_can_log_in(client):
    await make_user("first@example.com", roles=["viewer"])
    data = await login(client, "first@example.com")
    assert data["user"]["roles"] == ["admin"]
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["user"]["email"] == "first@example.com"
    assert "*" in me["user"]["permissions"]


async def test_later_users_get_requested_roles(client):
    await make_user("admin@example.com")
    await make_user("dev@example.com", roles=["developer"])
    data = await login(client, "dev@example.com")
    assert data["user"]["roles"] == ["developer"]


async def test_bad_password_and_unknown_user(client):
    await make_user("admin@example.com")
    r = await client.post("/api/v1/auth/login", json={"email": "admin@example.com", "password": "nope"})
    assert r.status_code == 401
    r = await client.post("/api/v1/auth/login", json={"email": "ghost@example.com", "password": "nope"})
    assert r.status_code == 401


async def test_login_rate_limited(client):
    await make_user("admin@example.com")
    for _ in range(10):
        await client.post("/api/v1/auth/login", json={"email": "admin@example.com", "password": "wrong"})
    r = await client.post("/api/v1/auth/login", json={"email": "admin@example.com", "password": PASSWORD})
    assert r.status_code == 429


async def test_unauthenticated_api_is_rejected(client):
    assert (await client.get("/api/v1/hosts")).status_code == 401


async def test_cookie_writes_require_csrf(admin_client):
    token = admin_client.headers.pop("X-CSRF-Token")
    r = await admin_client.post("/api/v1/tokens", json={"name": "ci"})
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]
    r = await admin_client.post("/api/v1/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403
    r = await admin_client.post("/api/v1/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": token})
    assert r.status_code == 201


async def test_api_token_auth_and_revocation(admin_client, make_client):
    created = (await admin_client.post("/api/v1/tokens", json={"name": "ci", "expires_in_days": 30})).json()
    assert created["token"].startswith("slipway_pat_")
    # The listed prefix keeps 7 random characters after "slipway_pat_" and fits the 20-character column.
    assert created["prefix"] == created["token"][:19]

    bot = make_client()
    bot.headers["Authorization"] = f"Bearer {created['token']}"
    assert (await bot.get("/api/v1/auth/me")).json()["user"]["email"] == "admin@example.com"
    # Bearer requests don't need CSRF...
    assert (await bot.post("/api/v1/hosts", json={"name": "h1", "hostname": "10.0.0.1", "username": "deploy"})).status_code == 201
    # ...but can't mint more tokens.
    assert (await bot.post("/api/v1/tokens", json={"name": "x"})).status_code == 403

    assert (await admin_client.delete(f"/api/v1/tokens/{created['id']}")).status_code == 204
    assert (await bot.get("/api/v1/auth/me")).status_code == 401


async def test_logout_kills_session(admin_client):
    assert (await admin_client.post("/api/v1/auth/logout")).status_code == 204
    assert (await admin_client.get("/api/v1/auth/me")).status_code == 401


async def test_password_change_revokes_other_sessions(admin_client, make_client):
    other = make_client()
    await login(other, "admin@example.com")
    r = await admin_client.post(
        "/api/v1/auth/me/password", json={"current_password": PASSWORD, "new_password": "a-new-long-password"}
    )
    assert r.status_code == 204
    assert (await other.get("/api/v1/auth/me")).status_code == 401
    assert (await admin_client.get("/api/v1/auth/me")).status_code == 200


async def test_registration_disabled_by_default(client):
    r = await client.post("/api/v1/auth/register", json={"email": "new@example.com", "password": "long-enough-pw"})
    assert r.status_code == 403


def test_permission_matching():
    assert has_permission(frozenset({"*"}), "hosts:write")
    assert has_permission(frozenset({"hosts:*"}), "hosts:write")
    assert has_permission(frozenset({"hosts:read"}), "hosts:read")
    assert not has_permission(frozenset({"hosts:read"}), "hosts:write")
    assert not has_permission(frozenset({"repos:*"}), "hosts:read")
    assert validate_permissions(["hosts:read", "hosts:read", "repos:*"]) == ["hosts:read", "repos:*"]


@pytest.mark.parametrize(
    ("base_url", "client_url", "secure"),
    [
        # Opened directly over http while the base URL is the proxy's https address: a Secure cookie would be
        # dropped by the browser and every sign-in would silently fail.
        ("https://slipway.example.com", "http://192.168.1.20:8000", False),
        # Through a proxy (Host is the public name) even when its forwarded scheme isn't trusted.
        ("https://slipway.example.com", "http://slipway.example.com", True),
        ("https://slipway.example.com", "https://192.168.1.20:8000", True),
        ("http://localhost:8000", "http://192.168.1.20:8000", False),
    ],
)
async def test_session_cookie_is_secure_only_where_the_browser_will_keep_it(app, base_url, client_url, secure, monkeypatch):
    import httpx

    from slipway.core.config import get_settings

    monkeypatch.setattr(get_settings(), "base_url", base_url)
    await make_user("cookie@example.com")
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
    async with httpx.AsyncClient(transport=transport, base_url=client_url) as c:
        r = await c.post("/api/v1/auth/login", json={"email": "cookie@example.com", "password": PASSWORD})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("slipway_session=")
    assert ("; secure" in cookie.lower()) is secure
