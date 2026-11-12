
from slipway.core.permissions import has_permission, validate_permissions


async def test_unauthenticated_api_is_rejected(client):
    assert (await client.get("/api/v1/hosts")).status_code == 401


async def test_api_token_auth_and_revocation(admin_client, make_client):
    created = (await admin_client.post("/api/v1/tokens", json={"name": "ci", "expires_in_days": 30})).json()
    assert created["token"].startswith("slipway_pat_")
    # The listed prefix keeps 7 random characters after "slipway_pat_" and fits the 20-character column.
    assert created["prefix"] == created["token"][:19]

    bot = make_client()
    bot.headers["Authorization"] = f"Bearer {created['token']}"
    assert (await bot.get("/api/v1/auth/me")).json()["email"] == "admin@example.com"
    # Bearer requests don't need CSRF...
    assert (await bot.post("/api/v1/hosts", json={"name": "h1", "hostname": "10.0.0.1", "username": "deploy"})).status_code == 201
    # ...but can't mint more tokens.
    assert (await bot.post("/api/v1/tokens", json={"name": "x"})).status_code == 403

    assert (await admin_client.delete(f"/api/v1/tokens/{created['id']}")).status_code == 204
    assert (await bot.get("/api/v1/auth/me")).status_code == 401


def test_permission_matching():
    assert has_permission(frozenset({"*"}), "hosts:write")
    assert has_permission(frozenset({"hosts:*"}), "hosts:write")
    assert has_permission(frozenset({"hosts:read"}), "hosts:read")
    assert not has_permission(frozenset({"hosts:read"}), "hosts:write")
    assert not has_permission(frozenset({"repos:*"}), "hosts:read")
    assert validate_permissions(["hosts:read", "hosts:read", "repos:*"]) == ["hosts:read", "repos:*"]


