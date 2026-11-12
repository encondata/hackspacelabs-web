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
    admin = next(u for u in (await m.get("/api/v1/users")).json() if u["username"] == "admin")
    assert (await m.get(f"/api/v1/users/{admin['id']}/tokens")).status_code == 403  # no users:write
    assert (await m.delete(f"/api/v1/users/{admin['id']}/github")).status_code == 403


async def test_audit_log_records_actions(admin_client):
    await admin_client.post("/api/v1/hosts", json=HOST)
    events = (await admin_client.get("/api/v1/audit")).json()
    actions = [e["action"] for e in events]
    assert "host.create" in actions
    assert next(e for e in events if e["action"] == "host.create")["actor"] == "admin"
