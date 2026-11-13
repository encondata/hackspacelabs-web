"""Regression tests for the ops review batch: proxies, create-admin, encryption keys, config, limits."""

from __future__ import annotations

import importlib.util
import io
import logging
import os
import select as fd_select
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

from slipway import cli
from slipway.core.config import Settings, get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.session import get_sessionmaker
from slipway.main import check_encryption_key
from slipway.models import Host, Instance, OAuthAccount, Repository, User
from slipway.schemas import InstanceUpdate
from tests.conftest import login, make_user

ROOT = Path(__file__).resolve().parent.parent
K1, K2, K3 = (Fernet.generate_key().decode() for _ in range(3))
NEW_PASSWORD = "a-brand-new-password"


@pytest.fixture
def settings_env():
    """Set SLIPWAY_* environment variables for one test and rebuild the cached settings and keys."""
    saved: dict[str, str | None] = {}

    def apply(**values: str) -> None:
        for name, value in values.items():
            key = f"SLIPWAY_{name}"
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


def _slipway(*argv: str, **kwargs) -> subprocess.Popen:
    """Run the real CLI against the test database, detached from any terminal (as in scripts and CI)."""
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    return subprocess.Popen(
        [sys.executable, "-m", "slipway.cli", *argv], cwd=ROOT, env=env, start_new_session=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs,
    )


def _read_until(stream, marker: bytes, timeout: float = 60) -> None:
    seen, deadline = b"", time.monotonic() + timeout
    while marker not in seen:
        ready, _, _ = fd_select.select([stream], [], [], max(0.0, deadline - time.monotonic()))
        chunk = os.read(stream.fileno(), 4096) if ready else b""
        assert chunk, f"no {marker!r} prompt; got {seen!r}"
        seen += chunk


async def _get_user(email: str) -> User:
    async with get_sessionmaker()() as db:
        user = await db.scalar(select(User).where(User.email == email))
        assert user is not None
        return user


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

    with caplog.at_level(logging.ERROR, logger="slipway.core.crypto"):
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

    messages = [r.getMessage() for r in caplog.records if r.name == "slipway.core.crypto"]
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
        assert (await db.scalar(select(OAuthAccount).where(OAuthAccount.provider == "github"))).access_token == "gho_secret"
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
    with caplog.at_level(logging.ERROR, logger="slipway"):
        async with get_sessionmaker()() as db:
            assert await check_encryption_key(db) is False
    assert "SLIPWAY_ENCRYPTION_KEY cannot decrypt stored secrets" in caplog.text

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
    logging.getLogger("slipway.test-level").setLevel(level)  # raised "Unknown level" for lowercase before


def test_log_level_rejects_unknown_names():
    with pytest.raises(ValidationError, match="SLIPWAY_LOG_LEVEL"):
        _settings(log_level="loud")


@pytest.mark.parametrize("password", ["ab@cd", "ab%41cd", "Xk9@q%2Fz!", "a/b:c#d?e"])
def test_database_password_may_contain_url_special_characters(password):
    settings = _settings(database_url="postgresql+asyncpg://slipway@db:5432/slipway", database_password=password)
    url = make_url(settings.database_url)
    assert (url.password, url.host, url.database) == (password, "db", "slipway")
    assert PGDialect_asyncpg().create_connect_args(url)[1]["password"] == password


def test_password_in_a_configured_database_url_wins():
    url = "postgresql+asyncpg://slipway:ExternalPw@db.internal:5432/slipway"
    settings = _settings(database_url=url, database_password="slipway")  # the compose default
    assert make_url(settings.database_url).password == "ExternalPw"


def test_database_password_applies_to_the_default_url(monkeypatch):
    monkeypatch.delenv("SLIPWAY_DATABASE_URL")
    settings = _settings(database_password="p@ss/word")
    assert make_url(settings.database_url).password == "p@ss/word"


def test_compose_passes_the_database_password_outside_the_url():
    # Slipway runs in the HackSpaceLabs stack (deployment/compose.yaml at the repository root).
    compose = (ROOT.parent.parent / "deployment" / "compose.yaml").read_text()
    url_line = next(line for line in compose.splitlines() if "SLIPWAY_DATABASE_URL:" in line)
    assert "PASSWORD" not in url_line and "@postgres:5432/hsl_slipway" in url_line
    assert "SLIPWAY_DATABASE_PASSWORD: ${SLIPWAY_DB_PASSWORD" in compose


def test_generate_secrets_prints_url_safe_postgres_password(capsys):
    cli.generate_secrets()
    values = dict(line.split("=", 1) for line in capsys.readouterr().out.splitlines())
    password = values["POSTGRES_PASSWORD"]
    assert len(password) >= 24 and quote(password, safe="") == password
    Fernet(values["SLIPWAY_ENCRYPTION_KEY"].encode())


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


# ------------------------------------------------------------------- input bounds


@pytest.mark.parametrize(
    "query", ["limit=-1", "limit=0", "limit=501", "offset=-1", "offset=2147483648", f"action={'a' * 65}"]
)
async def test_audit_query_params_are_bounded(admin_client, query):
    assert (await admin_client.get(f"/api/v1/audit?{query}")).status_code == 422


async def test_audit_action_filter_is_a_literal_prefix(admin_client):
    await admin_client.post("/api/v1/hosts", json={"name": "h1", "hostname": "10.0.0.1", "username": "deploy"})
    assert (await admin_client.get("/api/v1/audit?action=host.")).json()
    assert (await admin_client.get("/api/v1/audit?action=host%25")).json() == []
    assert (await admin_client.get("/api/v1/audit?action=host_create")).json() == []


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


