"""Test fixtures. Tests run against SQLite; set SLIPWAY_TEST_DATABASE_URL to use PostgreSQL."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator, Callable
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="slipway-tests-"))
ISSUER = "http://keycloak.test/realms/hackspacelabs"
os.environ.update(
    SLIPWAY_ENV_FILE="",  # never read the developer's .env
    SLIPWAY_ENV="test",
    SLIPWAY_DATABASE_URL=os.environ.get("SLIPWAY_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{_tmp}/test.db"),
    SLIPWAY_SECRET_KEY="test-secret-key-that-is-long-enough-1234567890",
    SLIPWAY_HOST_POLL_INTERVAL="0",
    SLIPWAY_GITHUB_CLIENT_ID="test-client",
    SLIPWAY_GITHUB_CLIENT_SECRET="test-secret",
    SLIPWAY_BASE_URL="http://testserver",
    SLIPWAY_OIDC_ISSUER=ISSUER,
    SLIPWAY_INTERNAL_SECRET="test-internal-secret-that-is-long-enough",
)

import time  # noqa: E402
import uuid  # noqa: E402

import httpx  # noqa: E402
import jwt  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from sqlalchemy import select  # noqa: E402

from slipway.db.base import Base  # noqa: E402
from slipway.db.session import get_engine, get_sessionmaker, init_engine  # noqa: E402
from slipway.main import create_app  # noqa: E402
from slipway.models import KEYCLOAK, OAuthAccount, Role, User  # noqa: E402
from slipway.services import oidc  # noqa: E402
from slipway.services.oidc import OwnerStatus  # noqa: E402
from slipway.services.users import bootstrap  # noqa: E402

# Kept for call sites that still pass it; Slipway has no passwords.
PASSWORD = "unused-keycloak-signs-people-in"

# ---------------------------------------------------------------- a stand-in for the Keycloak realm
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "test-key"
_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(SIGNING_KEY.public_key(), as_dict=True) | {"kid": KID, "use": "sig", "alg": "RS256"}
JWKS = {"keys": [_jwk]}
# Keycloak's view of each account: sub -> OwnerStatus (what the admin API reports for API-token owners).
KEYCLOAK_ACCOUNTS: dict[str, OwnerStatus] = {}


async def _fake_jwks() -> dict:
    return JWKS


async def _fake_owner(sub: str) -> OwnerStatus:
    return KEYCLOAK_ACCOUNTS.get(sub, OwnerStatus(exists=False))


def sub_for(email: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, email))


def access_token(
    sub: str, *, roles: list[str] | None = None, username: str | None = None, email: str | None = None,
    name: str | None = None, key=None, kid: str = KID, **overrides,
) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": ["slipway"], "azp": "hackspacelabs-web", "typ": "Bearer", "sub": sub,
        "iat": now, "exp": now + 300, "slipway_roles": roles or [],
        "preferred_username": username, "email": email, "name": name,
    }
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, key or SIGNING_KEY, algorithm="RS256", headers={"kid": kid})


@pytest.fixture(scope="session")
def app():
    init_engine(os.environ["SLIPWAY_DATABASE_URL"])
    return create_app()


@pytest.fixture(autouse=True)
async def fresh_db(app) -> AsyncIterator[None]:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with get_sessionmaker()() as db:
        await bootstrap(db)
    KEYCLOAK_ACCOUNTS.clear()
    oidc.jwks.clear()
    oidc.jwks.fetch = _fake_jwks
    oidc.owners.clear()
    oidc.owners.lookup = _fake_owner
    yield


@pytest.fixture
def make_client(app) -> Callable[..., httpx.AsyncClient]:
    clients: list[httpx.AsyncClient] = []

    def factory(ip: str = "127.0.0.1") -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app, client=(ip, 123))
        c = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        clients.append(c)
        return c

    yield factory
    # httpx clients over ASGITransport hold no sockets; nothing to close explicitly.


@pytest.fixture
async def client(make_client) -> httpx.AsyncClient:
    return make_client()


async def make_user(email: str, roles: list[str] | None = None, password: str | None = None) -> User:
    """A Keycloak account that has used Slipway. ``roles=None``: admin for the first user, else viewer."""
    async with get_sessionmaker()() as db:
        if roles is None:
            roles = ["viewer"] if await db.scalar(select(User.id).limit(1)) else ["admin"]
        sub = sub_for(email)
        username = email.split("@")[0]
        KEYCLOAK_ACCOUNTS[sub] = OwnerStatus(exists=True, enabled=True, roles=tuple(sorted(roles)), username=username, email=email)
        user = User(
            email=email, username=username, full_name=username, roles=list(
                (await db.scalars(select(Role).where(Role.name.in_(roles)))).all()
            ), oauth_accounts=[OAuthAccount(provider=KEYCLOAK, provider_user_id=sub, login=username)],
        )
        db.add(user)
        await db.commit()
        return user


def set_keycloak_roles(email: str, roles: list[str], *, enabled: bool = True) -> None:
    """Change what Keycloak says about an account (takes effect on its next token / API-token use)."""
    sub = sub_for(email)
    old = KEYCLOAK_ACCOUNTS[sub]
    KEYCLOAK_ACCOUNTS[sub] = OwnerStatus(exists=True, enabled=enabled, roles=tuple(sorted(roles)), username=old.username, email=old.email)
    oidc.owners.clear()


async def login(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> dict:
    """Act as the gateway does for a signed-in person: attach their Keycloak access token."""
    owner = KEYCLOAK_ACCOUNTS[sub_for(email)]
    client.headers["Authorization"] = "Bearer " + access_token(
        sub_for(email), roles=list(owner.roles), username=owner.username, email=email, name=owner.username,
    )
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 200, resp.text
    return {"user": resp.json()}


@pytest.fixture
async def admin_client(client) -> httpx.AsyncClient:
    await make_user("admin@example.com")  # first user -> admin
    await login(client, "admin@example.com")
    return client
