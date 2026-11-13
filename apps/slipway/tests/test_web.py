"""Page rendering smoke tests plus host/instance API flows."""

from __future__ import annotations

import pytest

from slipway.services import deployer, hosts, ssh
from slipway.db.session import get_sessionmaker
from slipway.models import Repository
from tests.conftest import login, make_user


def test_asyncssh_connection_chatter_is_kept_out_of_info_logs(app):
    import logging

    assert logging.getLogger("asyncssh").getEffectiveLevel() == logging.WARNING


async def _seed_repo() -> str:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        db.add(repo)
        await db.commit()
        return str(repo.id)


async def test_host_key_methods(admin_client):
    gen = (await admin_client.post("/api/v1/hosts", json={"name": "a", "hostname": "10.0.0.1", "username": "deploy"})).json()
    assert gen["auth_method"] == "key" and gen["public_key"].startswith("ssh-ed25519")
    priv, pub = ssh.generate_keypair("mine")
    pasted = (await admin_client.post("/api/v1/hosts", json={
        "name": "b", "hostname": "10.0.0.2", "username": "deploy", "auth_method": "key", "private_key": priv})).json()
    assert pasted["public_key"] == pub
    r = await admin_client.post("/api/v1/hosts", json={"name": "c", "hostname": "10.0.0.3", "username": "deploy", "auth_method": "key", "private_key": "junk"})
    assert r.status_code == 400
    r = await admin_client.post("/api/v1/hosts", json={"name": "d", "hostname": "10.0.0.3; rm -rf /", "username": "deploy"})
    assert r.status_code == 422
    assert "private_key" not in gen and "password" not in gen


async def test_host_check_pins_key_and_deploy_requires_pin(admin_client, monkeypatch):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "prod-01", "hostname": "10.0.0.5", "username": "deploy"})).json()

    submitted = []
    monkeypatch.setattr(deployer.runner, "submit", lambda dep_id, inst_id: submitted.append(dep_id))
    r = await admin_client.post("/api/v1/instances", json={"name": "web", "repository_id": repo_id, "host_id": host["id"]})
    assert r.status_code == 400 and "not been verified" in r.json()["detail"]

    key = ssh.generate_keypair()[1]

    async def fake_probe(target):
        return ssh.ProbeResult(host_key=key, fingerprint=ssh.fingerprint(key), os_info="Debian 13", cpus=2,
                               cpu_percent=10, mem_total_mb=4096, mem_percent=40, docker_version="27.0",
                               docker_error=None, containers_running=0)

    monkeypatch.setattr(hosts.ssh, "probe", fake_probe)
    checked = (await admin_client.post(f"/api/v1/hosts/{host['id']}/check")).json()
    assert checked["status"] == "healthy" and checked["host_key_fingerprint"].startswith("SHA256:")

    r = await admin_client.post("/api/v1/instances", json={"name": "web", "repository_id": repo_id, "host_id": host["id"]})
    assert r.status_code == 201, r.text
    assert len(submitted) == 1
    inst = r.json()
    assert inst["slug"] == "web" and inst["env_keys"] == []
    # A second deploy while one is queued is refused.
    assert (await admin_client.post(f"/api/v1/instances/{inst['id']}/deploy")).status_code == 409
    deps = (await admin_client.get(f"/api/v1/deployments?instance_id={inst['id']}")).json()
    assert deps[0]["status"] == "queued"
    detail = (await admin_client.get(f"/api/v1/deployments/{deps[0]['id']}?log_offset=0")).json()
    assert detail["log"] == "" and detail["log_offset"] == 0


@pytest.mark.parametrize("payload", [
    {"dockerfile_path": "../../etc/shadow"},
    {"env": {"BAD KEY": "x"}},
    {"volumes": [{"source": "relative/path", "target": "/data"}]},
    {"ports": [{"host": 70000, "container": 80}]},
])
async def test_instance_validation(admin_client, payload):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy"})).json()
    body = {"name": "web", "repository_id": repo_id, "host_id": host["id"], "deploy": False, **payload}
    assert (await admin_client.post("/api/v1/instances", json=body)).status_code == 422


async def test_env_values_need_write_permission(admin_client, make_client):
    repo_id = await _seed_repo()
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={
        "name": "web", "repository_id": repo_id, "host_id": host["id"], "deploy": False, "env": {"SECRET": "hunter2"}})).json()
    assert (await admin_client.get(f"/api/v1/instances/{inst['id']}/env")).json() == {"SECRET": "hunter2"}
    await make_user("dev@example.com", roles=["developer"])
    dev = make_client()
    await login(dev, "dev@example.com")
    assert (await dev.get(f"/api/v1/instances/{inst['id']}/env")).status_code == 403
    assert (await dev.get(f"/api/v1/instances/{inst['id']}")).json()["env_keys"] == ["SECRET"]


async def test_secrets_encrypted_at_rest(admin_client):
    await admin_client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.5", "username": "deploy", "auth_method": "password", "password": "pa55word"})
    async with get_sessionmaker()() as db:
        raw = (await db.execute(__import__("sqlalchemy").text("SELECT password FROM hosts"))).scalar_one()
    assert raw and "pa55word" not in raw
