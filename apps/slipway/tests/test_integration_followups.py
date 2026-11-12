"""Regression tests for the follow-ups that spanned several review batches."""

from __future__ import annotations

import re
import uuid

import pytest

from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import Instance, Repository, Role
from slipway.services.github import GitHubError
from tests.conftest import login, make_user


async def _role(name: str, permissions: list[str]) -> str:
    async with get_sessionmaker()() as db:
        role = Role(name=name, description="", permissions=permissions, is_system=False)
        db.add(role)
        await db.commit()
        return str(role.id)


async def _client(make_client, email: str, permissions: list[str]):
    await _role(email.split("@")[0], permissions)
    await make_user(email, roles=[email.split("@")[0]])
    c = make_client()
    await login(c, email)
    return c


class _FakeGitHub:
    error: GitHubError | None = None

    def __init__(self, token):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_user_by_login(self, login):
        raise self.error


async def test_instance_query_params_are_bounded(admin_client):
    some_id = uuid.uuid4()
    assert (await admin_client.get(f"/api/v1/instances/{some_id}/logs?tail=0")).status_code == 422
    assert (await admin_client.get(f"/api/v1/instances/{some_id}/logs?tail=100000")).status_code == 422
    assert (await admin_client.get(f"/api/v1/instances/{some_id}/deployments?limit=-1")).status_code == 422


async def _instance(admin_client) -> str:
    async with get_sessionmaker()() as db:
        repo = Repository(github_id=7, full_name="acme/app", owner="acme", name="app", html_url="https://github.com/acme/app",
                          detected_config={"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]})
        db.add(repo)
        await db.commit()
        repo_id = str(repo.id)
    host = (await admin_client.post("/api/v1/hosts", json={"name": "h1", "hostname": "10.0.0.5", "username": "deploy"})).json()
    inst = (await admin_client.post("/api/v1/instances", json={
        "name": "app", "repository_id": repo_id, "host_id": host["id"], "branch": "main", "deploy": False,
    })).json()
    return inst["id"]


def _disabled(page: str, name: str) -> bool:
    tag = re.search(rf'<input[^>]*name="{name}"[^>]*>', page).group(0)
    return re.search(r"\sdisabled(\s|>|=)", tag) is not None


async def test_lists_load_without_build_logs(admin_client):
    inst_id = await _instance(admin_client)
    from slipway.models import Deployment

    async with get_sessionmaker()() as db:
        db.add(Deployment(instance_id=uuid.UUID(inst_id), status="succeeded", branch="main", commit_sha="a" * 40, log="x" * 1000))
        await db.commit()
    for url in ("/api/v1/deployments", f"/api/v1/instances/{inst_id}", "/api/v1/instances"):
        assert (await admin_client.get(url)).status_code == 200, url


# ---------------------------------------------------------- second review round follow-ups

from slipway import cli  # noqa: E402
from slipway.api.v1.instances import env_unreadable  # noqa: E402
from slipway.models.repository import DEFAULT_BRANCH_TOO_LONG  # noqa: E402
from tests.test_review_ops import K1, K2, _store_secrets  # noqa: E402


@pytest.fixture
def key_env():
    """Switch SLIPWAY_ENCRYPTION_KEY for one test, rebuilding the cached settings and keys."""
    import os

    from slipway.core.config import get_settings
    from slipway.core.crypto import reset_crypto_cache

    saved = os.environ.get("SLIPWAY_ENCRYPTION_KEY")

    def apply(key: str) -> None:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = key
        get_settings.cache_clear()
        reset_crypto_cache()

    yield apply
    if saved is None:
        os.environ.pop("SLIPWAY_ENCRYPTION_KEY", None)
    else:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = saved
    get_settings.cache_clear()
    reset_crypto_cache()


async def test_clearing_unreadable_env_keeps_the_deploy_guard(key_env):
    key_env(K1)
    await _store_secrets()
    key_env(K2)  # the old key is lost
    async with get_sessionmaker()() as db:
        await cli._rotate_secrets(db, clear_unreadable=True)
        await db.commit()
    async with get_sessionmaker()() as db:
        instance = await db.scalar(select(Instance))
        # Still flagged as needing re-entry (the deployer refuses), rather than silently empty.
        assert instance.env is None and await env_unreadable(db, instance)


