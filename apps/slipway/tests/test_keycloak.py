"""Signing in through HackSpaceLabs: Keycloak access tokens, mirrored accounts and API-token owners."""

from __future__ import annotations

import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from slipway.core.config import Settings
from slipway.db.session import get_sessionmaker
from slipway.models import KEYCLOAK, AuditEvent, OAuthAccount, User
from slipway.services import oidc
from slipway.services.oidc import KeycloakAdmin, OwnerStatus
from tests.conftest import JWKS, KEYCLOAK_ACCOUNTS, access_token, login, make_user, set_keycloak_roles, sub_for

SUB = "4b9f2c1e-2d7a-4a8e-9f0b-1c2d3e4f5a6b"


def bearer(client: httpx.AsyncClient, token: str) -> httpx.AsyncClient:
    client.headers["Authorization"] = f"Bearer {token}"
    return client


async def _events(action: str) -> list[AuditEvent]:
    async with get_sessionmaker()() as db:
        return list((await db.scalars(select(AuditEvent).where(AuditEvent.action == action))).all())


# ----------------------------------------------------------------------------- accounts


async def test_first_request_creates_the_account_from_the_token(client):
    token = access_token(SUB, roles=["developer"], username="ada", email="Ada@Example.com", name="Ada Lovelace")
    me = (await bearer(client, token).get("/api/v1/auth/me")).json()
    assert (me["username"], me["email"], me["full_name"], me["roles"]) == ("ada", "ada@example.com", "Ada Lovelace", ["developer"])
    assert me["last_login_at"] is not None
    async with get_sessionmaker()() as db:
        account = await db.scalar(select(OAuthAccount).where(OAuthAccount.provider == KEYCLOAK))
        assert (account.provider_user_id, account.login) == (SUB, "ada")
    assert len(await _events("user.provisioned")) == 1
    # Later requests reuse the same account.
    await client.get("/api/v1/auth/me")
    async with get_sessionmaker()() as db:
        assert len((await db.scalars(select(User))).all()) == 1


async def test_accounts_without_email_use_the_username(client):
    me = (await bearer(client, access_token(SUB, roles=["viewer"], username="ops-bot")).get("/api/v1/auth/me")).json()
    assert me["email"] is None and me["display_name"] == "ops-bot"


async def test_roles_follow_the_token_and_changes_are_audited(client):
    await bearer(client, access_token(SUB, roles=["viewer"], username="ada")).get("/api/v1/auth/me")
    assert (await client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.1", "username": "d"})).status_code == 403
    bearer(client, access_token(SUB, roles=["maintainer", "root", 7], username="ada"))
    assert (await client.get("/api/v1/auth/me")).json()["roles"] == ["maintainer"]
    assert (await client.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.1", "username": "d"})).status_code == 201
    [event] = await _events("user.roles_synced")
    assert event.details == {"before": ["viewer"], "after": ["maintainer"]}


async def test_no_slipway_role_means_no_permissions(client):
    me = (await bearer(client, access_token(SUB, roles=[], username="ada")).get("/api/v1/auth/me")).json()
    assert me["roles"] == [] and me["permissions"] == []
    assert (await client.get("/api/v1/hosts")).status_code == 403


async def test_accounts_are_never_matched_by_email(client):
    await make_user("ada@example.com", roles=["admin"])
    other = "9d1c6c8e-0000-4000-8000-000000000001"
    me = (await bearer(client, access_token(other, roles=["viewer"], username="imposter", email="ada@example.com")).get("/api/v1/auth/me")).json()
    # A different Keycloak account with the same email address is a different (viewer) user, without the email.
    assert me["roles"] == ["viewer"] and me["email"] is None and me["username"] == "imposter"


async def test_profile_changes_in_keycloak_are_picked_up(client):
    await bearer(client, access_token(SUB, roles=["viewer"], username="ada", name="Ada")).get("/api/v1/auth/me")
    me = (await bearer(client, access_token(SUB, roles=["viewer"], username="ada.l", name="Ada L.", email="ada@x.org")).get("/api/v1/auth/me")).json()
    assert (me["username"], me["full_name"], me["email"]) == ("ada.l", "Ada L.", "ada@x.org")


# ----------------------------------------------------------------------- token checks


def _other_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(lambda: access_token(SUB, key=_other_key()), id="wrong-signature"),
        pytest.param(lambda: access_token(SUB, kid="rotated-away"), id="unknown-key"),
        pytest.param(lambda: access_token(SUB, iss="https://evil.example/realms/hackspacelabs"), id="issuer"),
        pytest.param(lambda: access_token(SUB, aud=["account"]), id="audience"),
        pytest.param(lambda: access_token(SUB, azp="some-other-app"), id="authorized-party"),
        pytest.param(lambda: access_token(SUB, typ="ID"), id="id-token"),
        pytest.param(lambda: access_token(SUB, typ="Refresh"), id="refresh-token"),
        pytest.param(lambda: access_token(SUB, exp=int(time.time()) - 120), id="expired"),
        pytest.param(lambda: access_token(None), id="no-subject"),
        pytest.param(lambda: access_token("x" * 65), id="oversized-subject"),
        pytest.param(lambda: jwt.encode({"sub": SUB, "iss": "x"}, "s" * 32, algorithm="HS256", headers={"kid": "test-key"}), id="hs256"),
        pytest.param(lambda: "not-a-jwt", id="garbage"),
    ],
)
async def test_invalid_access_tokens_are_401(client, token):
    r = await bearer(client, token()).get("/api/v1/auth/me")
    assert r.status_code == 401, r.text
    async with get_sessionmaker()() as db:
        assert (await db.scalars(select(User))).all() == []


async def test_unsigned_tokens_are_rejected(client):
    header = jwt.utils.base64url_encode(b'{"alg":"none","kid":"test-key"}').decode()
    body = jwt.utils.base64url_encode(f'{{"sub":"{SUB}"}}'.encode()).decode()
    assert (await bearer(client, f"{header}.{body}.").get("/api/v1/auth/me")).status_code == 401


async def test_signing_keys_unavailable_is_503_not_401(client):
    async def down():
        raise httpx.ConnectError("keycloak down")

    oidc.jwks.fetch = down
    r = await bearer(client, access_token(SUB, roles=["viewer"])).get("/api/v1/auth/me")
    assert r.status_code == 503


async def test_rotated_signing_key_is_fetched(client):
    await bearer(client, access_token(SUB, roles=["viewer"])).get("/api/v1/auth/me")
    new_key = _other_key()
    new_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(new_key.public_key(), as_dict=True) | {"kid": "next", "use": "sig"}

    async def rotated():
        return {"keys": [*JWKS["keys"], new_jwk]}

    oidc.jwks.fetch = rotated
    oidc.jwks._loaded_at -= 60  # past the refetch guard
    assert (await bearer(client, access_token(SUB, roles=["viewer"], key=new_key, kid="next")).get("/api/v1/auth/me")).status_code == 200


# ------------------------------------------------------------------- API-token owners


async def _api_token(admin_client, make_client) -> httpx.AsyncClient:
    raw = (await admin_client.post("/api/v1/tokens", json={"name": "ci"})).json()["token"]
    return bearer(make_client(), raw)


async def test_api_tokens_stop_working_when_the_owner_is_disabled(admin_client, make_client):
    bot = await _api_token(admin_client, make_client)
    assert (await bot.get("/api/v1/hosts")).status_code == 200
    set_keycloak_roles("admin@example.com", ["admin"], enabled=False)
    r = await bot.get("/api/v1/hosts")
    assert r.status_code == 401 and "disabled" in r.json()["detail"]


async def test_api_tokens_stop_working_when_the_owner_is_deleted(admin_client, make_client):
    bot = await _api_token(admin_client, make_client)
    KEYCLOAK_ACCOUNTS.pop(sub_for("admin@example.com"))
    oidc.owners.clear()
    assert (await bot.get("/api/v1/hosts")).status_code == 401


async def test_api_tokens_follow_the_owners_current_roles(admin_client, make_client):
    bot = await _api_token(admin_client, make_client)
    set_keycloak_roles("admin@example.com", ["viewer"])
    assert (await bot.get("/api/v1/hosts")).status_code == 200
    assert (await bot.post("/api/v1/hosts", json={"name": "h", "hostname": "10.0.0.1", "username": "d"})).status_code == 403
    set_keycloak_roles("admin@example.com", [])
    assert (await bot.get("/api/v1/hosts")).status_code == 403


async def test_api_tokens_fail_closed_when_keycloak_is_unreachable(admin_client, make_client):
    bot = await _api_token(admin_client, make_client)

    async def down(sub):
        raise oidc.IdentityUnavailable("down")

    oidc.owners.clear()
    oidc.owners.lookup = down
    assert (await bot.get("/api/v1/hosts")).status_code == 503


async def test_owner_lookups_are_cached(admin_client, make_client):
    bot = await _api_token(admin_client, make_client)
    calls = []
    real = oidc.owners.lookup

    async def counting(sub):
        calls.append(sub)
        return await real(sub)

    oidc.owners.clear()
    oidc.owners.lookup = counting
    for _ in range(3):
        assert (await bot.get("/api/v1/hosts")).status_code == 200
    assert len(calls) == 1


async def test_api_tokens_cannot_mint_tokens_or_link_github(admin_client, make_client):
    bot = await _api_token(admin_client, make_client)
    assert (await bot.post("/api/v1/tokens", json={"name": "x"})).status_code == 403
    assert (await bot.post("/api/v1/auth/github/link")).status_code == 403


# ----------------------------------------------------------- Keycloak admin lookups


def _keycloak(handler) -> KeycloakAdmin:
    return KeycloakAdmin(transport=httpx.MockTransport(handler))


async def test_owner_lookup_reads_enabled_flag_and_effective_roles():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.headers.get("authorization")))
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            assert b"grant_type=client_credentials" in request.content and b"client_id=slipway" in request.content
            return httpx.Response(200, json={"access_token": "svc", "expires_in": 300})
        if path == "/admin/realms/hackspacelabs/users":
            assert request.url.params["search"] == "service-account-slipway"
            return httpx.Response(200, json=[
                {"id": "other", "username": "service-account-slipway-old", "serviceAccountClientId": "wrong"},
                {"id": "sa-user", "username": "service-account-slipway", "serviceAccountClientId": "client-uuid"},
            ])
        if path == f"/admin/realms/hackspacelabs/users/{SUB}":
            return httpx.Response(200, json={"id": SUB, "username": "ada", "enabled": True, "firstName": "Ada", "lastName": "L"})
        if path == f"/admin/realms/hackspacelabs/users/{SUB}/role-mappings/clients/client-uuid/composite":
            return httpx.Response(200, json=[{"name": "developer"}, {"name": "uma_protection"}])
        return httpx.Response(500)

    status = await _keycloak(handler).owner(SUB)
    assert status == OwnerStatus(exists=True, enabled=True, roles=("developer",), username="ada", email=None, full_name="Ada L")
    assert all(auth == "Bearer svc" for method, path, auth in seen if "/admin/" in path)
    assert seen[0][1] == "/realms/hackspacelabs/protocol/openid-connect/token"


async def test_owner_lookup_reports_missing_accounts_and_outages():
    def missing(request):
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "svc", "expires_in": 300})
        return httpx.Response(404)

    assert (await _keycloak(missing).owner(SUB)).exists is False

    def broken(request):
        return httpx.Response(401)

    with pytest.raises(oidc.IdentityUnavailable):
        await _keycloak(broken).owner(SUB)


async def test_subjects_are_escaped_in_admin_paths():
    paths = []

    def handler(request):
        paths.append(request.url.raw_path)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "svc", "expires_in": 300})
        return httpx.Response(404)

    await _keycloak(handler).owner("../clients")
    assert b"/users/..%2Fclients" in paths[1]


# --------------------------------------------------------------------------- settings


def test_production_needs_the_keycloak_settings(monkeypatch):
    monkeypatch.delenv("SLIPWAY_OIDC_ISSUER")
    monkeypatch.delenv("SLIPWAY_OIDC_CLIENT_SECRET")
    base = {"env": "production", "secret_key": "s" * 40, "encryption_key": "0" * 43 + "=", "_env_file": None}
    with pytest.raises(ValueError, match="OIDC_ISSUER"):
        Settings(**base)
    with pytest.raises(ValueError, match="OIDC_CLIENT_SECRET"):
        Settings(**base, oidc_issuer="https://auth.example/realms/hackspacelabs")


def test_internal_realm_url_is_used_for_keys_and_admin():
    s = Settings(
        _env_file=None, oidc_issuer="https://auth.example/realms/hackspacelabs/",
        oidc_internal_url="http://keycloak:8080/realms/hackspacelabs",
    )
    assert s.oidc_issuer == "https://auth.example/realms/hackspacelabs"
    assert s.jwks_url == "http://keycloak:8080/realms/hackspacelabs/protocol/openid-connect/certs"
    assert s.oidc_admin_url == "http://keycloak:8080/admin/realms/hackspacelabs"
    assert s.github_callback_url == "http://testserver/api/slipway/auth/github/callback"


async def test_login_helper_matches_keycloak(client):
    # The conftest helper behaves like the gateway: the token carries the account's Keycloak roles.
    await make_user("dev@example.com", roles=["developer"])
    assert (await login(client, "dev@example.com"))["user"]["roles"] == ["developer"]


async def test_system_info_needs_sign_in_and_reports_features(admin_client, make_client):
    info = (await admin_client.get("/api/v1/system/info")).json()
    assert info["github_enabled"] is True and info["github_service_token"] is False
    assert info["default_deploy_root"] == "/opt/slipway" and "version" in info
    assert (await make_client().get("/api/v1/system/info")).status_code == 401
