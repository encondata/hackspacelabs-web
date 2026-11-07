"""Regression tests for the ops review batch: proxies, create-admin, encryption keys, config, limits."""

from __future__ import annotations

import importlib.util
import io
import logging
import os
import select as fd_select
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

import asyncssh
import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
from sqlalchemy.engine import make_url
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from kiln import cli
from kiln.core.config import Settings, get_settings
from kiln.core.crypto import reset_crypto_cache
from kiln.db.session import get_sessionmaker
from kiln.main import check_encryption_key
from kiln.models import AuditEvent, Host, Instance, OAuthAccount, Repository, User
from kiln.schemas import InstanceUpdate
from kiln.services.users import UserError
from tests.conftest import PASSWORD, login, make_user

ROOT = Path(__file__).resolve().parent.parent
K1, K2, K3 = (Fernet.generate_key().decode() for _ in range(3))
NEW_PASSWORD = "a-brand-new-password"


@pytest.fixture
def settings_env():
    """Set KILN_* environment variables for one test and rebuild the cached settings and keys."""
    saved: dict[str, str | None] = {}

    def apply(**values: str) -> None:
        for name, value in values.items():
            key = f"KILN_{name}"
            saved.setdefault(key, os.environ.get(key))
            os.environ[key] = value
        get_settings.cache_clear()
        reset_crypto_cache()

    yield apply
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()
    reset_crypto_cache()


def _settings(**kwargs) -> Settings:
    return Settings(_env_file=None, **kwargs)


# ------------------------------------------------------------------ trusted proxies


def _serve_kwargs(monkeypatch) -> dict:
    captured: dict = {}
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: captured.update(kwargs))
    cli.serve(cli.build_parser().parse_args(["serve"]))
    return captured


def _client_behind(app, trusted: str, peer: str) -> httpx.AsyncClient:
    proxied = ProxyHeadersMiddleware(app, trusted_hosts=trusted)
    transport = httpx.ASGITransport(app=proxied, client=(peer, 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def test_serve_ignores_forwarded_for_from_untrusted_clients(app, monkeypatch):
    kwargs = _serve_kwargs(monkeypatch)
    assert kwargs["proxy_headers"] is True and kwargs["forwarded_allow_ips"] == "127.0.0.1"

    await make_user("admin@example.com")
    attacker = _client_behind(app, kwargs["forwarded_allow_ips"], "203.0.113.7")
    codes = []
    for i in range(11):
        r = await attacker.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "wrong"},
            headers={"X-Forwarded-For": f"10.66.{i}.1"},
        )
        codes.append(r.status_code)
    assert codes[:10] == [401] * 10 and codes[10] == 429
    async with get_sessionmaker()() as db:
        ips = set((await db.scalars(select(AuditEvent.ip))).all())
    assert ips == {"203.0.113.7"}


async def test_serve_trusts_the_configured_proxy(app, monkeypatch, settings_env):
    settings_env(FORWARDED_ALLOW_IPS="192.0.2.10")
    kwargs = _serve_kwargs(monkeypatch)
    assert kwargs["forwarded_allow_ips"] == "192.0.2.10"

    via_proxy = _client_behind(app, kwargs["forwarded_allow_ips"], "192.0.2.10")
    r = await via_proxy.post(
        "/api/v1/auth/login",
        json={"email": "ghost@example.com", "password": "wrong"},
        headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.9"},
    )
    assert r.status_code == 401
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(AuditEvent.ip))).all() == ["198.51.100.9"]


# --------------------------------------------------------------------- create-admin


async def _run_create_admin(*argv: str) -> list[str]:
    """What ``cli.create_admin`` does, minus its own event loops."""
    args = cli.build_parser().parse_args(["create-admin", *argv])
    async with get_sessionmaker()() as db:
        if await cli._password_needed(db, args):
            args.password = cli._read_password()
        lines = await cli._ensure_admin(db, args)
        await db.commit()
    return lines


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def _prompts(monkeypatch, password: str | None) -> list[str]:
    asked: list[str] = []

    def fake(prompt: str = "") -> str:
        asked.append(prompt)
        if password is None:
            raise AssertionError("create-admin should not prompt for a password here")
        return password

    monkeypatch.setattr("getpass.getpass", fake)
    monkeypatch.setattr("sys.stdin", _Terminal())
    return asked


def _kiln(*argv: str, **kwargs) -> subprocess.Popen:
    """Run the real CLI against the test database, detached from any terminal (as in scripts and CI)."""
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    return subprocess.Popen(
        [sys.executable, "-m", "kiln.cli", *argv], cwd=ROOT, env=env, start_new_session=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs,
    )


async def test_create_admin_reads_a_piped_password(client):
    proc = _kiln("create-admin", "piped@example.com")
    out, err = proc.communicate(f"{NEW_PASSWORD}\n".encode(), timeout=60)
    assert proc.returncode == 0, err.decode()
    assert out.decode().strip() == "Created admin piped@example.com."
    data = await login(client, "piped@example.com", NEW_PASSWORD)
    assert data["user"]["roles"] == ["admin"]


async def test_create_admin_without_a_password_exits_cleanly():
    proc = _kiln("create-admin", "nobody@example.com")
    _, err = proc.communicate(b"", timeout=60)
    assert proc.returncode == 1
    assert "Error: No password given" in err.decode() and "Traceback" not in err.decode()
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(User).where(User.email == "nobody@example.com")) is None


def _read_until(stream, marker: bytes, timeout: float = 60) -> None:
    seen, deadline = b"", time.monotonic() + timeout
    while marker not in seen:
        ready, _, _ = fd_select.select([stream], [], [], max(0.0, deadline - time.monotonic()))
        chunk = os.read(stream.fileno(), 4096) if ready else b""
        assert chunk, f"no {marker!r} prompt; got {seen!r}"
        seen += chunk


async def test_create_admin_ctrl_c_at_the_prompt_stops_cleanly():
    proc = _kiln("create-admin", "cancel@example.com")
    try:
        _read_until(proc.stderr, b"Password (10+ characters): ")
        proc.send_signal(signal.SIGINT)
        _, err = proc.communicate(timeout=30)
    finally:
        proc.kill()
    assert proc.returncode == 1
    assert "Cancelled; nothing was changed." in err.decode() and "Traceback" not in err.decode()
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(User).where(User.email == "cancel@example.com")) is None


async def _get_user(email: str) -> User:
    async with get_sessionmaker()() as db:
        user = await db.scalar(select(User).where(User.email == email))
        assert user is not None
        return user


async def test_create_admin_for_existing_user_does_not_prompt_or_touch_password(client, monkeypatch):
    await make_user("admin@example.com")
    await make_user("ops@example.com", roles=["viewer"])
    _prompts(monkeypatch, None)

    lines = await _run_create_admin("ops@example.com")
    assert "Granted the admin role." in lines
    assert any("Password NOT changed" in line for line in lines)
    data = await login(client, "ops@example.com")  # original password still works
    assert "admin" in data["user"]["roles"]


async def test_create_admin_refuses_password_for_existing_user_without_reset(client, monkeypatch):
    await make_user("admin@example.com")
    await make_user("ops@example.com", roles=["viewer"])
    _prompts(monkeypatch, None)

    with pytest.raises(UserError, match="--reset-password"):
        await _run_create_admin("ops@example.com", "--password", NEW_PASSWORD)
    user = await _get_user("ops@example.com")
    assert user.role_names == ["viewer"]
    r = await client.post("/api/v1/auth/login", json={"email": "ops@example.com", "password": NEW_PASSWORD})
    assert r.status_code == 401


async def test_create_admin_reset_password_cuts_off_sessions_and_tokens(make_client, monkeypatch):
    await make_user("admin@example.com")
    await make_user("ops@example.com", roles=["viewer"])
    holder = make_client()
    await login(holder, "ops@example.com")
    token = (await holder.post("/api/v1/tokens", json={"name": "ci"})).json()["token"]
    bot = make_client()
    bot.headers["Authorization"] = f"Bearer {token}"
    assert (await bot.get("/api/v1/auth/me")).status_code == 200
    asked = _prompts(monkeypatch, NEW_PASSWORD)

    lines = await _run_create_admin("ops@example.com", "--reset-password")
    assert len(asked) == 2  # password + confirmation
    assert any("signed out 1 session(s) and deleted 1 API token(s)" in line for line in lines)
    assert (await holder.get("/api/v1/auth/me")).status_code == 401
    assert (await bot.get("/api/v1/auth/me")).status_code == 401
    fresh = make_client()
    r = await fresh.post("/api/v1/auth/login", json={"email": "ops@example.com", "password": PASSWORD})
    assert r.status_code == 401
    data = await login(fresh, "ops@example.com", NEW_PASSWORD)
    assert "admin" in data["user"]["roles"]


async def test_create_admin_reset_password_checks_strength(monkeypatch):
    await make_user("admin@example.com")
    _prompts(monkeypatch, "short")
    with pytest.raises(UserError, match="at least"):
        await _run_create_admin("admin@example.com", "--reset-password")


async def test_create_admin_activate_reactivates_account(client, monkeypatch):
    await make_user("admin@example.com")
    await make_user("ops@example.com", roles=["viewer"])
    async with get_sessionmaker()() as db:
        user = await db.scalar(select(User).where(User.email == "ops@example.com"))
        user.is_active = False
        await db.commit()
    _prompts(monkeypatch, None)

    lines = await _run_create_admin("ops@example.com")
    assert any("still INACTIVE" in line for line in lines)
    assert not (await _get_user("ops@example.com")).is_active

    lines = await _run_create_admin("ops@example.com", "--activate")
    assert "Account reactivated." in lines
    await login(client, "ops@example.com")


async def test_create_admin_new_user_prompts_and_creates_admin(client, monkeypatch):
    await make_user("admin@example.com")
    asked = _prompts(monkeypatch, NEW_PASSWORD)
    assert await _run_create_admin("new@example.com") == ["Created admin new@example.com."]
    assert len(asked) == 2
    data = await login(client, "new@example.com", NEW_PASSWORD)
    assert data["user"]["roles"] == ["admin"]


# ------------------------------------------------------------------ encryption keys


async def _store_secrets() -> None:
    """Under the current key: a GitHub-linked admin, a host with every secret, an instance with env."""
    admin = await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        host = Host(name="h1", hostname="10.0.0.1", username="deploy", private_key="PRIVATE", key_passphrase="PHRASE", password="PW")
        repo = Repository(github_id=1, full_name="acme/app", owner="acme", name="app", html_url="https://github.com/acme/app")
        db.add_all([
            host,
            Instance(name="app", slug="app", repository=repo, host=host, branch="main", env={"TOKEN": "abc"}),
            OAuthAccount(user_id=admin.id, provider="github", provider_user_id="1", login="octo", access_token="gho_secret"),
        ])
        await db.commit()


async def test_unreadable_secrets_load_as_none_instead_of_failing(client, settings_env, caplog):
    settings_env(ENCRYPTION_KEY=K1)
    await _store_secrets()
    settings_env(ENCRYPTION_KEY=K2)  # the old key is gone

    with caplog.at_level(logging.ERROR, logger="kiln.core.crypto"):
        await login(client, "admin@example.com")
        assert (await client.get("/api/v1/auth/me")).status_code == 200
        assert (await client.get("/api/v1/auth/me")).status_code == 200
        hosts = await client.get("/api/v1/hosts")
        assert hosts.status_code == 200 and hosts.json()[0]["name"] == "h1"
        instances = await client.get("/api/v1/instances")
        assert instances.status_code == 200 and instances.json()[0]["env_keys"] == []
    async with get_sessionmaker()() as db:
        host = await db.scalar(select(Host))
        assert host.private_key is None and host.password is None

    messages = [r.getMessage() for r in caplog.records if r.name == "kiln.core.crypto"]
    assert sum("oauth_accounts.access_token" in m for m in messages) == 1  # once per column
    assert any("hosts.private_key" in m for m in messages)
    assert not any(secret in caplog.text for secret in ("gho_secret", "PRIVATE", "abc"))


async def _raw(db, sql: str) -> str:
    return await db.scalar(text(sql))


async def test_rotate_encryption_key_reencrypts_every_secret(settings_env):
    settings_env(ENCRYPTION_KEY=K1)
    await _store_secrets()
    settings_env(ENCRYPTION_KEY=K3)
    async with get_sessionmaker()() as db:
        db.add(Host(name="lost", hostname="10.0.0.2", username="deploy", auth_method="password", password="LOST"))
        await db.commit()

    settings_env(ENCRYPTION_KEY=f"{K2},{K1}")
    async with get_sessionmaker()() as db:
        rotated, unreadable = await cli._rotate_secrets(db)
        await db.commit()
    assert rotated == 5
    assert len(unreadable) == 1 and unreadable[0].startswith("hosts.password")

    settings_env(ENCRYPTION_KEY=K2)  # old key removed after rotation
    async with get_sessionmaker()() as db:
        raw = await _raw(db, "SELECT private_key FROM hosts WHERE name = 'h1'")
        assert Fernet(K2.encode()).decrypt(raw.encode()) == b"PRIVATE"
        host = await db.scalar(select(Host).where(Host.name == "h1"))
        assert (host.private_key, host.key_passphrase, host.password) == ("PRIVATE", "PHRASE", "PW")
        assert (await db.scalar(select(Instance))).env == {"TOKEN": "abc"}
        assert (await db.scalar(select(OAuthAccount))).access_token == "gho_secret"
        lost_raw = await _raw(db, "SELECT password FROM hosts WHERE name = 'lost'")
        assert Fernet(K3.encode()).decrypt(lost_raw.encode()) == b"LOST"  # left untouched

    async with get_sessionmaker()() as db:
        rotated, unreadable = await cli._rotate_secrets(db, clear_unreadable=True)
        await db.commit()
    assert rotated == 5 and len(unreadable) == 1
    async with get_sessionmaker()() as db:
        assert await _raw(db, "SELECT password FROM hosts WHERE name = 'lost'") is None


async def test_startup_check_reports_a_key_that_cannot_decrypt(settings_env, caplog):
    settings_env(ENCRYPTION_KEY=K1)
    await _store_secrets()
    async with get_sessionmaker()() as db:
        assert await check_encryption_key(db) is True

    settings_env(ENCRYPTION_KEY=K2)
    with caplog.at_level(logging.ERROR, logger="kiln"):
        async with get_sessionmaker()() as db:
            assert await check_encryption_key(db) is False
    assert "KILN_ENCRYPTION_KEY cannot decrypt stored secrets" in caplog.text

    settings_env(ENCRYPTION_KEY=f"{K2},{K1}")
    async with get_sessionmaker()() as db:
        assert await check_encryption_key(db) is True


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("not-a-fernet-key", "entry 1 is not a valid Fernet key"),
        ("2ff4edbfe5a0879290803fe652c7fc10a977fafdae329491f7bde8c84594348f", "entry 1 is not a valid Fernet key"),
        (f"{K1},change-me", "entry 2 is not a valid Fernet key"),
        (" , ", "contains no keys"),
    ],
    ids=["placeholder", "hex", "second-entry", "empty-list"],
)
def test_production_rejects_malformed_encryption_keys(value, message):
    with pytest.raises(ValidationError) as exc:
        _settings(env="production", secret_key="x" * 48, encryption_key=value)
    assert message in str(exc.value)
    assert not any(part.strip() in str(exc.value) for part in value.split(",") if part.strip())


def test_valid_encryption_keys_are_accepted():
    assert _settings(env="production", secret_key="x" * 48, encryption_key=f"{K1}, {K2}").fernet_keys() == [
        K1.encode(), K2.encode()
    ]


# --------------------------------------------------------------------------- config


@pytest.mark.parametrize(("value", "expected"), [("info", "INFO"), ("debug", "DEBUG"), (" Warning ", "WARNING")])
def test_log_level_is_case_insensitive(value, expected):
    level = _settings(log_level=value).log_level
    assert level == expected
    logging.getLogger("kiln.test-level").setLevel(level)  # raised "Unknown level" for lowercase before


def test_log_level_rejects_unknown_names():
    with pytest.raises(ValidationError, match="KILN_LOG_LEVEL"):
        _settings(log_level="loud")


@pytest.mark.parametrize("password", ["ab@cd", "ab%41cd", "Xk9@q%2Fz!", "a/b:c#d?e"])
def test_database_password_may_contain_url_special_characters(password):
    settings = _settings(database_url="postgresql+asyncpg://kiln@db:5432/kiln", database_password=password)
    url = make_url(settings.database_url)
    assert (url.password, url.host, url.database) == (password, "db", "kiln")
    assert PGDialect_asyncpg().create_connect_args(url)[1]["password"] == password


def test_password_in_a_configured_database_url_wins():
    url = "postgresql+asyncpg://kiln:ExternalPw@db.internal:5432/kiln"
    settings = _settings(database_url=url, database_password="kiln")  # the compose default
    assert make_url(settings.database_url).password == "ExternalPw"


def test_database_password_applies_to_the_default_url(monkeypatch):
    monkeypatch.delenv("KILN_DATABASE_URL")
    settings = _settings(database_password="p@ss/word")
    assert make_url(settings.database_url).password == "p@ss/word"


def test_compose_passes_postgres_password_outside_the_url():
    compose = (ROOT / "docker-compose.yml").read_text()
    url_line = next(line for line in compose.splitlines() if "KILN_DATABASE_URL:" in line)
    assert "POSTGRES_PASSWORD" not in url_line
    assert "KILN_DATABASE_PASSWORD: ${POSTGRES_PASSWORD" in compose


def test_generate_secrets_prints_url_safe_postgres_password(capsys):
    cli.generate_secrets()
    values = dict(line.split("=", 1) for line in capsys.readouterr().out.splitlines())
    password = values["POSTGRES_PASSWORD"]
    assert len(password) >= 24 and quote(password, safe="") == password
    Fernet(values["KILN_ENCRYPTION_KEY"].encode())


# ---------------------------------------------------------------------- dependencies


async def test_passphrase_protected_openssh_key_is_accepted(admin_client):
    key = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh", passphrase="secret").decode()
    r = await admin_client.post(
        "/api/v1/hosts",
        json={"name": "h1", "hostname": "10.0.0.1", "username": "deploy", "auth_method": "key",
              "private_key": key, "key_passphrase": "secret"},
    )
    assert r.status_code == 201, r.text


# ----------------------------------------------------------------------- demo seeder


def _load_seeder():
    spec = importlib.util.spec_from_file_location("seed_demo", ROOT / "scripts" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_seeded_demo_users_have_no_password(client):
    await make_user("admin@example.com")
    await _load_seeder().main()
    demo = ["maria@example.com", "james@example.com", "sarah@example.com"]
    guess = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl"  # what every demo user used to share
    for email in demo:
        r = await client.post("/api/v1/auth/login", json={"email": email, "password": guess})
        assert r.status_code == 401
    async with get_sessionmaker()() as db:
        users = (await db.scalars(select(User).where(User.email.in_(demo)))).all()
    assert len(users) == 3 and all(u.password_hash is None for u in users)


async def test_seeder_refuses_to_make_a_demo_user_the_first_admin():
    with pytest.raises(SystemExit, match="admin"):
        await _load_seeder().main()
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(User))).all() == []


# ------------------------------------------------------------------- input bounds


@pytest.mark.parametrize(
    "query", ["limit=-1", "limit=0", "limit=501", "offset=-1", "offset=2147483648", f"action={'a' * 65}"]
)
async def test_audit_query_params_are_bounded(admin_client, query):
    assert (await admin_client.get(f"/api/v1/audit?{query}")).status_code == 422


async def test_audit_action_filter_is_a_literal_prefix(admin_client):
    assert (await admin_client.get("/api/v1/audit?action=auth.")).json()
    assert (await admin_client.get("/api/v1/audit?action=auth%25")).json() == []
    assert (await admin_client.get("/api/v1/audit?action=auth_login")).json() == []


@pytest.mark.parametrize("query", ["limit=-1", "limit=0", "limit=201", f"status={'x' * 17}"])
async def test_deployment_query_params_are_bounded(admin_client, query):
    assert (await admin_client.get(f"/api/v1/deployments?{query}")).status_code == 422


async def test_long_deploy_root_is_rejected(admin_client):
    r = await admin_client.post(
        "/api/v1/hosts", json={"name": "h1", "hostname": "10.0.0.1", "username": "deploy", "deploy_root": "/opt/" + "a" * 300}
    )
    assert r.status_code == 422


@pytest.mark.parametrize("field", ["dockerfile_path", "build_context", "compose_file"])
def test_long_instance_paths_are_rejected(field):
    with pytest.raises(ValidationError):
        InstanceUpdate(**{field: "a" * 300})


def test_instance_env_and_mappings_are_bounded():
    with pytest.raises(ValidationError):
        InstanceUpdate(env={f"K{i}": "v" for i in range(501)})
    with pytest.raises(ValidationError):
        InstanceUpdate(env={"K" * 256: "v"})
    with pytest.raises(ValidationError):
        InstanceUpdate(ports=[{"host": 8000, "container": 80}] * 101)


async def test_long_current_password_is_rejected(admin_client):
    r = await admin_client.post(
        "/api/v1/auth/me/password", json={"current_password": "x" * 501, "new_password": "a-new-long-password"}
    )
    assert r.status_code == 422


async def test_role_lists_are_bounded(admin_client):
    body = {"email": "new@example.com", "password": NEW_PASSWORD}
    r = await admin_client.post("/api/v1/users", json={**body, "roles": ["r" * 65]})
    assert r.status_code == 422
    r = await admin_client.post("/api/v1/users", json={**body, "roles": ["viewer"] * 51})
    assert r.status_code == 422
    r = await admin_client.post("/api/v1/roles", json={"name": "ops", "permissions": ["hosts:read"] * 201})
    assert r.status_code == 422
