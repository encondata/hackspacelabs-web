"""Regression tests for the accounts review: user management, credentials, rate limits."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from collections import Counter
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from slipway.core import ratelimit, security
from slipway.core.config import get_settings
from slipway.core.ratelimit import (
    RateLimiter,
    ip_bucket,
    login_email_limiter,
    login_ip_limiter,
    login_pair_limiter,
    password_change_limiter,
    password_change_user_limiter,
)
from slipway.db.base import utcnow
from slipway.db.session import get_engine, get_sessionmaker
from slipway.models import OAuthAccount, Role, User
from slipway.services import users as users_service
from slipway.services.audit import client_ip
from slipway.services.auth import SESSION_COOKIE, create_session
from slipway.services.users import bootstrap, create_user, ensure_not_last_admin
from tests.conftest import PASSWORD, login, make_user

USER_MANAGER = {"name": "user-manager", "permissions": ["users:read", "users:write"]}
NEW_PASSWORD = "attacker-chosen-pw"


async def _user_manager(admin_client, make_client):
    assert (await admin_client.post("/api/v1/roles", json=USER_MANAGER)).status_code == 201
    await make_user("um@example.com", roles=["user-manager"])
    um = make_client()
    await login(um, "um@example.com")
    return um


async def _session_client(make_client, user: User, *, age: timedelta = timedelta(0)):
    """A browser-like client signed in as ``user`` (works for accounts without a password)."""
    async with get_sessionmaker()() as db:
        raw, session = await create_session(db, await db.get(User, user.id), None)
        session.created_at = utcnow() - age
        await db.commit()
        csrf = session.csrf_token
    c = make_client()
    c.headers.update({"Cookie": f"{SESSION_COOKIE}={raw}", "X-CSRF-Token": csrf})
    return c


async def _token_client(make_client, session_client):
    r = await session_client.post("/api/v1/tokens", json={"name": "ci"})
    assert r.status_code == 201, r.text
    bot = make_client()
    bot.headers["Authorization"] = f"Bearer {r.json()['token']}"
    return bot, r.json()


async def _link_github(user, login_name: str = "octocat") -> None:
    async with get_sessionmaker()() as db:
        db.add(OAuthAccount(user_id=user.id, provider="github", provider_user_id="1001", login=login_name))
        await db.commit()


async def _fail_login(c, email: str):
    return await c.post("/api/v1/auth/login", json={"email": email, "password": "wrong-password"})


# ------------------------------------------------------------ users:write dominance


async def test_user_manager_cannot_take_over_or_remove_admins(admin_client, make_client):
    um = await _user_manager(admin_client, make_client)
    admin = (await admin_client.get("/api/v1/auth/me")).json()["user"]
    admin2 = await make_user("admin2@example.com", roles=["admin"])

    r = await um.patch(f"/api/v1/users/{admin['id']}", json={"password": NEW_PASSWORD})
    assert r.status_code == 403
    r = await make_client().post("/api/v1/auth/login", json={"email": "admin@example.com", "password": NEW_PASSWORD})
    assert r.status_code == 401
    assert (await admin_client.get("/api/v1/auth/me")).status_code == 200

    assert (await um.patch(f"/api/v1/users/{admin2.id}", json={"roles": []})).status_code == 403
    assert (await um.patch(f"/api/v1/users/{admin2.id}", json={"is_active": False})).status_code == 403
    assert (await um.patch(f"/api/v1/users/{admin2.id}", json={"full_name": "x"})).status_code == 403
    assert (await um.delete(f"/api/v1/users/{admin2.id}")).status_code == 403
    me2 = (await admin_client.get(f"/api/v1/users/{admin2.id}")).json()
    assert me2["roles"] == ["admin"] and me2["is_active"] and me2["full_name"] == "admin2"


async def test_user_manager_cannot_strip_roles_beyond_own(admin_client, make_client):
    um = await _user_manager(admin_client, make_client)
    dev = await make_user("dev@example.com", roles=["developer"])
    assert (await um.patch(f"/api/v1/users/{dev.id}", json={"roles": ["user-manager"]})).status_code == 403
    assert (await admin_client.get(f"/api/v1/users/{dev.id}")).json()["roles"] == ["developer"]


async def test_user_manager_still_manages_less_privileged_users(admin_client, make_client):
    um = await _user_manager(admin_client, make_client)
    assert (await admin_client.post("/api/v1/roles", json={"name": "auditor", "permissions": ["users:read"]})).status_code == 201
    peer = await make_user("peer@example.com", roles=["auditor"])
    r = await um.patch(f"/api/v1/users/{peer.id}", json={"password": "a-fresh-password", "roles": []})
    assert r.status_code == 200 and r.json()["roles"] == []
    assert (await um.delete(f"/api/v1/users/{peer.id}")).status_code == 204


async def test_own_password_cannot_be_reset_through_user_admin(admin_client):
    me = (await admin_client.get("/api/v1/auth/me")).json()["user"]
    r = await admin_client.patch(f"/api/v1/users/{me['id']}", json={"password": "a-new-long-password"})
    assert r.status_code == 400 and "/api/v1/auth/me/password" in r.json()["detail"]
    assert (await admin_client.patch(f"/api/v1/users/{me['id']}", json={"full_name": "Boss"})).status_code == 200


async def test_create_user_with_empty_roles_gets_no_roles(admin_client, make_client):
    um = await _user_manager(admin_client, make_client)
    r = await um.post("/api/v1/users", json={"email": "sock@example.com", "password": "long-enough-pw", "roles": []})
    assert r.status_code == 201 and r.json()["roles"] == []
    sock = make_client()
    await login(sock, "sock@example.com", "long-enough-pw")
    assert (await sock.get("/api/v1/hosts")).status_code == 403


async def test_create_user_without_roles_gets_default_role():
    await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        assert (await create_user(db, email="a@example.com", password=PASSWORD)).role_names == ["viewer"]
        assert (await create_user(db, email="b@example.com", password=PASSWORD, role_names=[])).role_names == []


# ------------------------------------------------------------- credential revocation


async def test_admin_reset_and_deactivation_revoke_api_tokens(admin_client, make_client):
    dev = await make_user("dev@example.com", roles=["developer"])
    dev_client = make_client()
    await login(dev_client, "dev@example.com")

    bot, _ = await _token_client(make_client, dev_client)
    assert (await bot.get("/api/v1/hosts")).status_code == 200
    assert (await admin_client.patch(f"/api/v1/users/{dev.id}", json={"password": "a-reset-password"})).status_code == 200
    assert (await bot.get("/api/v1/hosts")).status_code == 401
    assert (await dev_client.get("/api/v1/auth/me")).status_code == 401

    dev_client = make_client()
    await login(dev_client, "dev@example.com", "a-reset-password")
    bot, _ = await _token_client(make_client, dev_client)
    assert (await admin_client.patch(f"/api/v1/users/{dev.id}", json={"is_active": False})).status_code == 200
    assert (await admin_client.patch(f"/api/v1/users/{dev.id}", json={"is_active": True})).status_code == 200
    assert (await bot.get("/api/v1/hosts")).status_code == 401
    assert (await admin_client.get(f"/api/v1/users/{dev.id}/tokens")).json() == []


async def test_own_password_change_keeps_api_tokens(admin_client, make_client):
    bot, _ = await _token_client(make_client, admin_client)
    r = await admin_client.post(
        "/api/v1/auth/me/password", json={"current_password": PASSWORD, "new_password": "a-new-long-password"}
    )
    assert r.status_code == 204
    assert (await bot.get("/api/v1/auth/me")).status_code == 200


async def test_admin_lists_and_revokes_another_users_tokens(admin_client, make_client):
    dev = await make_user("dev@example.com", roles=["developer"])
    dev_client = make_client()
    await login(dev_client, "dev@example.com")
    bot, created = await _token_client(make_client, dev_client)
    _, admin_token = await _token_client(make_client, admin_client)

    tokens = (await admin_client.get(f"/api/v1/users/{dev.id}/tokens")).json()
    assert [t["id"] for t in tokens] == [created["id"]] and "token" not in tokens[0]
    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/tokens/{admin_token['id']}")).status_code == 404
    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/tokens/{uuid.uuid4()}")).status_code == 404
    assert (await admin_client.delete(f"/api/v1/users/{dev.id}/tokens/{created['id']}")).status_code == 204
    assert (await bot.get("/api/v1/hosts")).status_code == 401
    actions = [e["action"] for e in (await admin_client.get("/api/v1/audit?action=token.revoke")).json()]
    assert actions == ["token.revoke"]


async def test_user_token_admin_requires_dominance(admin_client, make_client):
    um = await _user_manager(admin_client, make_client)
    admin = (await admin_client.get("/api/v1/auth/me")).json()["user"]
    _, token = await _token_client(make_client, admin_client)
    assert (await um.get(f"/api/v1/users/{admin['id']}/tokens")).status_code == 403
    assert (await um.delete(f"/api/v1/users/{admin['id']}/tokens/{token['id']}")).status_code == 403
    viewer = make_client()
    await make_user("viewer@example.com", roles=["viewer"])
    await login(viewer, "viewer@example.com")
    assert (await viewer.get(f"/api/v1/users/{admin['id']}/tokens")).status_code == 403


# ------------------------------------------------------- session-only credential changes


async def test_api_token_cannot_set_password_or_unlink_github(make_client):
    await make_user("admin@example.com")
    mona = await make_user("mona@example.com", roles=["developer"], password=None)
    await _link_github(mona)
    owner = await _session_client(make_client, mona)
    bot, _ = await _token_client(make_client, owner)

    r = await bot.post("/api/v1/auth/me/password", json={"new_password": "set-by-token-holder"})
    assert r.status_code == 403
    assert (await bot.delete("/api/v1/auth/me/github")).status_code == 403
    me = (await owner.get("/api/v1/auth/me")).json()["user"]
    assert me["has_password"] is False and me["github_login"] == "octocat"


async def test_api_token_cannot_unlink_github_even_with_password(admin_client, make_client):
    admin = (await admin_client.get("/api/v1/auth/me")).json()["user"]
    await _link_github(SimpleNamespace(id=uuid.UUID(admin["id"])))
    bot, _ = await _token_client(make_client, admin_client)
    assert (await bot.delete("/api/v1/auth/me/github")).status_code == 403
    assert (await admin_client.get("/api/v1/auth/me")).json()["user"]["github_login"] == "octocat"


async def test_first_password_needs_recent_sign_in(make_client):
    await make_user("admin@example.com")
    mona = await make_user("mona@example.com", roles=["developer"], password=None)
    stale = await _session_client(make_client, mona, age=timedelta(minutes=20))
    r = await stale.post("/api/v1/auth/me/password", json={"new_password": "a-first-password"})
    assert r.status_code == 403 and "sign in again" in r.json()["detail"]

    fresh = await _session_client(make_client, mona)
    assert (await fresh.post("/api/v1/auth/me/password", json={"new_password": "a-first-password"})).status_code == 204
    await login(make_client(), "mona@example.com", "a-first-password")


async def test_wrong_current_password_is_throttled_and_audited(admin_client):
    for _ in range(5):
        r = await admin_client.post(
            "/api/v1/auth/me/password", json={"current_password": "a-wrong-guess", "new_password": NEW_PASSWORD}
        )
        assert r.status_code == 400
    for current in ("another-wrong-guess", PASSWORD):
        r = await admin_client.post(
            "/api/v1/auth/me/password", json={"current_password": current, "new_password": NEW_PASSWORD}
        )
        assert r.status_code == 429
    failed = (await admin_client.get("/api/v1/audit?action=auth.password_change_failed")).json()
    assert len(failed) == 5


async def test_stolen_session_cannot_block_the_owner_from_changing_password(admin_client, make_client):
    thief = make_client("203.0.113.66")
    await login(thief, "admin@example.com")  # stands in for a stolen session cookie
    for _ in range(5):
        r = await thief.post("/api/v1/auth/me/password", json={"current_password": "a-wrong-guess", "new_password": NEW_PASSWORD})
        assert r.status_code == 400
    r = await thief.post("/api/v1/auth/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 429
    r = await admin_client.post("/api/v1/auth/me/password", json={"current_password": PASSWORD, "new_password": "the-owners-new-pw"})
    assert r.status_code == 204
    assert (await thief.get("/api/v1/auth/me")).status_code == 401


async def test_password_guesses_are_capped_per_user_across_sessions(admin_client, make_client, monkeypatch):
    assert password_change_user_limiter.limit > password_change_limiter.limit
    monkeypatch.setattr(password_change_user_limiter, "limit", 7)
    codes = []
    for _ in range(2):
        c = make_client()
        await login(c, "admin@example.com")
        for _ in range(4):
            r = await c.post("/api/v1/auth/me/password", json={"current_password": "a-wrong-guess", "new_password": NEW_PASSWORD})
            codes.append(r.status_code)
    assert codes == [400] * 7 + [429]


async def test_correct_current_password_resets_the_throttle(admin_client):
    for _ in range(4):
        await admin_client.post("/api/v1/auth/me/password", json={"current_password": "nope-nope", "new_password": NEW_PASSWORD})
    r = await admin_client.post("/api/v1/auth/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 204
    for _ in range(5):
        r = await admin_client.post("/api/v1/auth/me/password", json={"current_password": "nope-nope", "new_password": PASSWORD})
        assert r.status_code == 400


# ----------------------------------------------------------------------- login limits


async def test_concurrent_login_burst_is_limited(client):
    await make_user("admin@example.com")
    responses = await asyncio.gather(*(_fail_login(client, "admin@example.com") for _ in range(25)))
    assert Counter(r.status_code for r in responses) == {401: 10, 429: 15}


async def test_attacker_cannot_lock_owner_out_from_another_ip(make_client):
    await make_user("admin@example.com")
    attacker = make_client("203.0.113.5")
    for _ in range(10):
        assert (await _fail_login(attacker, "admin@example.com")).status_code == 401
    assert (await attacker.post("/api/v1/auth/login", json={"email": "admin@example.com", "password": PASSWORD})).status_code == 429
    await login(make_client("198.51.100.7"), "admin@example.com")


async def test_login_success_resets_pair_limit(client):
    await make_user("admin@example.com")
    for _ in range(9):
        await _fail_login(client, "admin@example.com")
    await login(client, "admin@example.com")
    for _ in range(9):
        assert (await _fail_login(client, "admin@example.com")).status_code == 401


async def test_login_ip_limit_spans_emails(make_client, monkeypatch):
    monkeypatch.setattr(login_ip_limiter, "limit", 3)
    await make_user("admin@example.com")
    c = make_client("203.0.113.9")
    for i in range(3):
        assert (await _fail_login(c, f"guess{i}@example.com")).status_code == 401
    assert (await _fail_login(c, "admin@example.com")).status_code == 429
    assert (await _fail_login(make_client("203.0.113.10"), "admin@example.com")).status_code == 401


async def test_login_email_limit_spans_ips(make_client, monkeypatch):
    monkeypatch.setattr(login_email_limiter, "limit", 4)
    await make_user("admin@example.com")
    for i in range(4):
        assert (await _fail_login(make_client(f"203.0.113.{i + 1}"), "admin@example.com")).status_code == 401
    r = await make_client("198.51.100.7").post("/api/v1/auth/login", json={"email": "admin@example.com", "password": PASSWORD})
    assert r.status_code == 429


async def test_one_ipv6_site_cannot_lock_the_owner_out(make_client):
    await make_user("admin@example.com")
    codes: Counter[int] = Counter()
    for subnet in range(5):  # five /64s inside one /56
        c = make_client(f"2001:db8:0:ab0{subnet}::1")
        for _ in range(10):
            codes[(await _fail_login(c, "admin@example.com")).status_code] += 1
    assert codes == {401: 10, 429: 40}
    await login(make_client("198.51.100.7"), "admin@example.com")


async def test_successful_logins_do_not_use_up_the_ip_budget(make_client, monkeypatch):
    monkeypatch.setattr(login_ip_limiter, "limit", 3)
    await make_user("admin@example.com")
    for i in range(5):
        await make_user(f"u{i}@example.com", roles=["viewer"])
    behind_nat = make_client("192.0.2.77")
    for i in range(5):
        await login(behind_nat, f"u{i}@example.com")
    codes = [(await _fail_login(behind_nat, f"u{i}@example.com")).status_code for i in range(4)]
    assert codes == [401, 401, 401, 429]


async def test_successful_logins_do_not_use_up_the_email_budget(make_client, monkeypatch):
    monkeypatch.setattr(login_email_limiter, "limit", 3)
    await make_user("admin@example.com")
    for i in range(5):
        await login(make_client(f"198.51.100.{i + 1}"), "admin@example.com")
    for i in range(3):
        assert (await _fail_login(make_client(f"203.0.113.{i + 1}"), "admin@example.com")).status_code == 401
    assert (await _fail_login(make_client("203.0.113.9"), "admin@example.com")).status_code == 429


def test_one_client_cannot_trip_the_email_limit():
    per_client = login_pair_limiter.limit * login_email_limiter.window / login_pair_limiter.window
    assert per_client < login_email_limiter.limit
    assert login_pair_limiter.limit < login_ip_limiter.limit < login_email_limiter.limit


async def test_registration_is_rate_limited_per_ip(make_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "allow_signup", True)
    await make_user("admin@example.com")
    c = make_client("203.0.113.20")
    taken = {"email": "admin@example.com", "password": "long-enough-pw"}
    codes = [(await c.post("/api/v1/auth/register", json=taken)).status_code for _ in range(11)]
    assert codes == [400] * 10 + [429]
    r = await make_client("203.0.113.21").post(
        "/api/v1/auth/register", json={"email": "new@example.com", "password": "long-enough-pw"}
    )
    assert r.status_code == 201


async def test_register_checks_password_before_revealing_existing_email(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "allow_signup", True)
    await make_user("admin@example.com")
    r = await client.post("/api/v1/auth/register", json={"email": "admin@example.com", "password": "short"})
    assert r.status_code in (400, 422) and "already exists" not in r.text


# ------------------------------------------------------------------ limiter internals


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(ratelimit.time, "monotonic", lambda: now[0])
    return now


def test_limiter_checks_do_not_allocate(clock):
    lim = RateLimiter(limit=2, window_seconds=60)
    for i in range(500):
        assert not lim.blocked(f"ip:{i}", "email:victim")
    assert len(lim) == 0


def test_limiter_drops_expired_keys_and_keeps_live_ones(clock):
    lim = RateLimiter(limit=2, window_seconds=60)
    lim.hit("victim", "victim")
    assert lim.blocked("victim")
    for i in range(5000):
        lim.hit(f"ip:{i}")
    assert lim.blocked("victim")  # a flood of other keys never evicts a live entry
    clock[0] += 61
    lim.hit("fresh")
    for i in range(4000):  # growth triggers a sweep of the expired keys
        lim.hit(f"later:{i}")
    assert "ip:0" not in lim._hits and "victim" not in lim._hits
    assert len(lim) == 4001
    assert not lim.blocked("victim")


def test_limiter_keeps_at_most_limit_hits_per_key(clock):
    lim = RateLimiter(limit=3, window_seconds=60)
    for _ in range(100):
        lim.hit("k")
        clock[0] += 0.1
    assert len(lim._hits["k"]) == 3 and lim.blocked("k")


def test_acquire_is_all_or_nothing(clock):
    a, b = RateLimiter(limit=1, window_seconds=60), RateLimiter(limit=5, window_seconds=60)
    assert ratelimit.acquire((a, "x"), (b, "y"))
    assert not ratelimit.acquire((a, "x"), (b, "y"))
    assert len(b._hits["y"]) == 1


def test_undo_takes_back_the_newest_hit(clock):
    lim = RateLimiter(limit=2, window_seconds=60)
    lim.hit("k", "k")
    assert lim.blocked("k")
    lim.undo("k", "missing")
    assert not lim.blocked("k") and len(lim) == 1
    lim.undo("k")
    assert len(lim) == 0


def test_ip_bucket_groups_ipv6_by_64():
    assert ip_bucket("2001:db8::1") == ip_bucket("2001:db8::ffff:1") == "2001:db8::/64"
    assert ip_bucket("2001:db8:0:1::1") != ip_bucket("2001:db8::1")
    assert ip_bucket("::ffff:192.0.2.1") == ip_bucket("192.0.2.1") == "192.0.2.1"
    assert ip_bucket(None) == ip_bucket("not-an-ip") == "unknown"
    assert ip_bucket("2001:db8:0:ab04::1", 48) == ip_bucket("2001:db8:0:ab00::1", 48) == "2001:db8::/48"
    assert ip_bucket("192.0.2.1", 48) == "192.0.2.1"


def test_client_ip_is_validated_and_normalised():
    def req(host):
        return SimpleNamespace(client=SimpleNamespace(host=host))

    assert client_ip(req("2001:0db8:0000:0000:0000:0000:0000:0001")) == "2001:db8::1"
    assert client_ip(req("fe80::1%" + "x" * 200)) == "fe80::1"
    assert client_ip(req("192.0.2.1")) == "192.0.2.1"
    assert client_ip(req("x" * 500)) is None
    assert client_ip(req("")) is None
    assert client_ip(SimpleNamespace(client=None)) is None


async def test_non_ip_client_address_is_not_stored(make_client):
    await make_user("admin@example.com")
    c = make_client("unix-socket-peer")
    await login(c, "admin@example.com")
    events = (await c.get("/api/v1/audit?action=auth.login")).json()
    assert events[0]["ip"] is None


# --------------------------------------------------------------------------- argon2


async def test_password_checks_run_off_the_event_loop(client, monkeypatch):
    seen: list[int] = []
    real = security.verify_password

    def spy(password, password_hash):
        seen.append(threading.get_ident())
        return real(password, password_hash)

    monkeypatch.setattr(security, "verify_password", spy)
    await make_user("admin@example.com")
    await login(client, "admin@example.com")
    assert seen and threading.get_ident() not in seen


def _record_pool_use(monkeypatch, name: str) -> list[int]:
    """Wrap a sync argon2 helper to note how many pooled connections are checked out while it runs."""
    seen: list[int] = []
    real = getattr(security, name)

    def spy(*args):
        seen.append(get_engine().pool.checkedout())
        return real(*args)

    monkeypatch.setattr(security, name, spy)
    return seen


async def test_login_does_not_hold_a_db_connection_during_argon2(client, monkeypatch):
    seen = _record_pool_use(monkeypatch, "verify_password")
    await make_user("admin@example.com")
    await _fail_login(client, "admin@example.com")
    await login(client, "admin@example.com")
    assert seen == [0, 0]


async def test_login_burst_does_not_pin_the_connection_pool(make_client, monkeypatch):
    seen = _record_pool_use(monkeypatch, "verify_password")
    clients = [make_client(f"203.0.113.{i}") for i in range(1, 4)]
    burst = [_fail_login(c, f"nobody{n}@example.com") for c in clients for n in range(10)]
    assert {r.status_code for r in await asyncio.gather(*burst)} == {401}
    # Attempts queued for an argon2 slot hold no connection, so the pool stays free.
    assert len(seen) == 30 and max(seen[15:]) <= security.ARGON2_CONCURRENCY + 2


async def test_register_and_password_change_hash_without_holding_a_connection(admin_client, make_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "allow_signup", True)
    hashed = _record_pool_use(monkeypatch, "hash_password")
    verified = _record_pool_use(monkeypatch, "verify_password")
    r = await make_client("203.0.113.30").post(
        "/api/v1/auth/register", json={"email": "new@example.com", "password": "long-enough-pw"}
    )
    assert r.status_code == 201
    r = await admin_client.post("/api/v1/auth/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 204
    assert hashed == [0, 0] and verified == [0]


async def test_argon2_concurrency_is_bounded(monkeypatch):
    active, peak = 0, 0
    lock = threading.Lock()

    def slow_hash(password):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return "hash"

    monkeypatch.setattr(security, "hash_password", slow_hash)
    assert await asyncio.gather(*(security.hash_password_async("pw") for _ in range(8))) == ["hash"] * 8
    assert peak <= security.ARGON2_CONCURRENCY


# ----------------------------------------------------------------------------- CSRF


async def test_non_ascii_csrf_header_is_rejected_not_crashed(admin_client):
    r = await admin_client.post("/api/v1/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": b"\xe9abc"})
    assert r.status_code == 403


async def test_non_ascii_bearer_token_is_rejected(client):
    r = await client.get("/api/v1/auth/me", headers={"Authorization": b"Bearer slipway_pat_\xe9\xff"})
    assert r.status_code == 401


def test_safe_equals():
    assert security.safe_equals("abc", "abc")
    assert not security.safe_equals("éabc", "abc")
    assert not security.safe_equals("\ud800", "")


# -------------------------------------------------------------- first/last admin locks


class _RecordingDB:
    """Just enough of an AsyncSession to see which statements run, and in what order."""

    def __init__(self, dialect: str, scalars: list) -> None:
        self.dialect = dialect
        self.scalars_left = list(scalars)
        self.calls: list[str] = []

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect))

    async def execute(self, stmt, *args):
        self.calls.append(str(stmt))

    async def scalar(self, stmt):
        self.calls.append(str(stmt))
        return self.scalars_left.pop(0)

    def add(self, obj):
        pass

    async def flush(self):
        pass


@pytest.mark.parametrize("dialect", ["postgresql", "sqlite"])
async def test_last_admin_check_takes_advisory_lock_on_postgres(dialect):
    db = _RecordingDB(dialect, [1])
    await ensure_not_last_admin(db, SimpleNamespace(id=uuid.uuid4(), role_names=["admin"]))
    locks = [c for c in db.calls if "pg_advisory_xact_lock" in c]
    if dialect == "postgresql":
        assert len(locks) == 1 and db.calls.index(locks[0]) == 0 and "count" in db.calls[1].lower()
    else:
        assert locks == [] and len(db.calls) == 1


@pytest.mark.parametrize("dialect", ["postgresql", "sqlite"])
async def test_first_user_check_takes_advisory_lock_on_postgres(dialect):
    viewer = Role(name="viewer", permissions=[])
    db = _RecordingDB(dialect, [None, 3, viewer])  # no email clash, 3 users, the default role
    user = await create_user(db, email="x@example.com")
    assert user.roles == [viewer]
    locks = [i for i, c in enumerate(db.calls) if "pg_advisory_xact_lock" in c]
    count = next(i for i, c in enumerate(db.calls) if "count" in c.lower())
    assert (locks == [count - 1]) if dialect == "postgresql" else (locks == [])


async def test_non_admin_change_takes_no_lock():
    db = _RecordingDB("postgresql", [])
    await ensure_not_last_admin(db, SimpleNamespace(id=uuid.uuid4(), role_names=["viewer"]))
    assert db.calls == []


# ------------------------------------------------------------------------- bootstrap


async def test_short_admin_password_does_not_crash_startup(monkeypatch, caplog):
    monkeypatch.setattr(get_settings(), "admin_email", "me@example.com")
    monkeypatch.setattr(get_settings(), "admin_password", "hunter22")
    with caplog.at_level(logging.ERROR, logger=users_service.log.name):
        async with get_sessionmaker()() as db:
            await bootstrap(db)
    async with get_sessionmaker()() as db:
        assert await db.scalar(select(func.count()).select_from(User)) == 0
        assert await db.scalar(select(func.count()).select_from(Role)) == 4
    assert "SLIPWAY_ADMIN_PASSWORD" in caplog.text


async def test_missing_default_role_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(get_settings(), "default_role", "deployers")
    with caplog.at_level(logging.ERROR, logger=users_service.log.name):
        async with get_sessionmaker()() as db:
            await bootstrap(db)
    assert "SLIPWAY_DEFAULT_ROLE=deployers" in caplog.text


# ------------------------------------------------------------------------ default role


async def test_default_role_cannot_be_deleted(admin_client, monkeypatch):
    role = (await admin_client.post("/api/v1/roles", json={"name": "newbie", "permissions": ["repos:read"]})).json()
    monkeypatch.setattr(get_settings(), "default_role", "newbie")
    r = await admin_client.delete(f"/api/v1/roles/{role['id']}")
    assert r.status_code == 400 and "SLIPWAY_DEFAULT_ROLE" in r.json()["detail"]
    monkeypatch.setattr(get_settings(), "default_role", "viewer")
    assert (await admin_client.delete(f"/api/v1/roles/{role['id']}")).status_code == 204
