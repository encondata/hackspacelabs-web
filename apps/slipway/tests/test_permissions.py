from tests.conftest import login, make_user

HOST = {"name": "prod-01", "hostname": "10.0.1.12", "username": "deploy"}


async def test_viewer_is_read_only(make_client):
    await make_user("admin@example.com")
    await make_user("viewer@example.com", roles=["viewer"])
    viewer = make_client()
    await login(viewer, "viewer@example.com")
    assert (await viewer.get("/api/v1/hosts")).status_code == 200
    r = await viewer.post("/api/v1/hosts", json=HOST)
    assert r.status_code == 403 and "hosts:write" in r.json()["detail"]
    assert (await viewer.get("/api/v1/users")).status_code == 403


async def test_maintainer_manages_hosts_not_users(make_client):
    await make_user("admin@example.com")
    await make_user("m@example.com", roles=["maintainer"])
    m = make_client()
    await login(m, "m@example.com")
    assert (await m.post("/api/v1/hosts", json=HOST)).status_code == 201
    assert (await m.get("/api/v1/users")).status_code == 200  # users:read
    r = await m.post("/api/v1/users", json={"email": "x@example.com", "password": "long-enough-pw"})
    assert r.status_code == 403


async def test_cannot_grant_roles_beyond_own_permissions(admin_client, make_client):
    # A custom role that can manage users but holds nothing else.
    r = await admin_client.post(
        "/api/v1/roles", json={"name": "user-manager", "permissions": ["users:read", "users:write", "roles:read"]}
    )
    assert r.status_code == 201
    await make_user("um@example.com", roles=["user-manager"])
    um = make_client()
    await login(um, "um@example.com")

    r = await um.post("/api/v1/users", json={"email": "evil@example.com", "password": "long-enough-pw", "roles": ["admin"]})
    assert r.status_code == 403
    r = await um.post("/api/v1/users", json={"email": "ok@example.com", "password": "long-enough-pw", "roles": ["user-manager"]})
    assert r.status_code == 201


async def test_last_admin_is_protected(admin_client):
    me = (await admin_client.get("/api/v1/auth/me")).json()["user"]
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"roles": ["viewer"]})
    assert r.status_code == 400 and "last active admin" in r.json()["detail"]
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"is_active": False})
    assert r.status_code == 400


async def test_deactivated_user_is_signed_out(admin_client, make_client):
    user = await make_user("dev@example.com", roles=["developer"])
    dev = make_client()
    await login(dev, "dev@example.com")
    r = await admin_client.patch(f"/api/v1/users/{user.id}", json={"is_active": False})
    assert r.status_code == 200
    assert (await dev.get("/api/v1/auth/me")).status_code == 401
    r = await dev.post("/api/v1/auth/login", json={"email": "dev@example.com", "password": "correct-horse-battery"})
    assert r.status_code == 401


async def test_builtin_roles_are_read_only(admin_client):
    roles = (await admin_client.get("/api/v1/roles")).json()
    admin = next(r for r in roles if r["name"] == "admin")
    assert (await admin_client.patch(f"/api/v1/roles/{admin['id']}", json={"permissions": []})).status_code == 400
    assert (await admin_client.delete(f"/api/v1/roles/{admin['id']}")).status_code == 400


async def test_unknown_permission_rejected(admin_client):
    r = await admin_client.post("/api/v1/roles", json={"name": "bad", "permissions": ["hosts:destroy"]})
    assert r.status_code == 422


async def test_audit_log_records_actions(admin_client):
    await admin_client.post("/api/v1/hosts", json=HOST)
    events = (await admin_client.get("/api/v1/audit")).json()
    actions = [e["action"] for e in events]
    assert "host.create" in actions and "auth.login" in actions
