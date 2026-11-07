"""Regression tests for the GitHub review findings: OAuth sign-up and state, redirects,
repository identity, transport errors, detection, truncation and log hygiene."""

from __future__ import annotations

import base64
import http.server
import json
import logging
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select

from kiln.api.v1 import repositories as repositories_api
from kiln.core.config import get_settings
from kiln.db.session import get_sessionmaker
from kiln.models import OAuthAccount, Repository, User
from kiln.services.github import GitHubClient, GitHubError, exchange_code
from kiln.services.repos import GitHubNotLinked, github_token_for, sync_repositories
from kiln.services.users import create_user
from kiln.web import oauth
from tests.conftest import login, make_user

SHA = "a" * 40
PROFILE = {"id": 1001, "login": "octocat", "name": "Mona Octocat", "avatar_url": "https://avatars.githubusercontent.com/u/1001"}


# ----------------------------------------------------------------- OAuth helpers


class FakeGH:
    profile: dict = PROFILE
    email = ("mona@example.com", True)
    orgs: list[dict] = []

    def __init__(self, token):
        assert token == "gho_test"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_user(self):
        return self.profile

    async def get_primary_email(self):
        return self.email

    async def get_orgs(self):
        return self.orgs


@pytest.fixture
def gh(monkeypatch):
    async def exchange(code):
        assert code == "good-code"
        return "gho_test", "read:user,user:email,repo"

    monkeypatch.setattr(oauth, "exchange_code", exchange)
    monkeypatch.setattr(oauth, "GitHubClient", FakeGH)
    FakeGH.profile, FakeGH.email, FakeGH.orgs = PROFILE, ("mona@example.com", True), []
    return FakeGH


async def _start(client, path="/auth/github/login?next=/hosts") -> str:
    r = await client.get(path)
    assert r.status_code == 302
    return parse_qs(urlparse(r.headers["location"]).query)["state"][0]


async def _callback(client, state: str, cookies: str | bytes | None = None) -> httpx.Response:
    headers = {"Cookie": cookies} if cookies is not None else {}
    return await client.get(f"/auth/github/callback?code=good-code&state={state}", headers=headers)


async def _me(client) -> dict | None:
    r = await client.get("/api/v1/auth/me")
    return r.json()["user"] if r.status_code == 200 else None


async def _user(email: str) -> User | None:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(User).where(User.email == email))


# ------------------------------------------- first sign-in vs. allowlists (17, 6)


async def test_empty_db_does_not_bypass_user_allowlist(client, gh, monkeypatch):
    monkeypatch.setattr(get_settings(), "github_allowed_users", ["alice"])
    r = await _callback(client, await _start(client))
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"
    assert await _me(client) is None


async def test_empty_db_does_not_bypass_org_allowlist(client, gh, monkeypatch):
    monkeypatch.setattr(get_settings(), "github_allowed_orgs", ["alice-org"])
    gh.orgs = [{"id": 5, "login": "other-org"}]
    r = await _callback(client, await _start(client))
    assert r.headers["location"] == "/login?error=not_allowed&login=octocat"


async def test_allowlisted_first_user_still_becomes_admin(client, gh, monkeypatch):
    monkeypatch.setattr(get_settings(), "github_allowed_users", ["octocat"])
    await _callback(client, await _start(client))
    assert (await _me(client))["roles"] == ["admin"]


# ------------------------------------------------ id-based allowlists (26, 14)


async def test_user_allowlist_matches_immutable_id(client, gh, monkeypatch):
    await make_user("admin@example.com")
    monkeypatch.setattr(get_settings(), "github_allowed_users", ["id:1001"])
    await _callback(client, await _start(client))
    assert (await _me(client))["github_login"] == "octocat"


async def test_user_id_entry_rejects_squatter_of_the_name(make_client, gh, monkeypatch):
    await make_user("admin@example.com")
    monkeypatch.setattr(get_settings(), "github_allowed_users", ["id:1001"])
    gh.profile = {"id": 6666, "login": "1001", "name": "Squatter"}
    client = make_client()
    r = await _callback(client, await _start(client))
    assert r.headers["location"] == "/login?error=not_allowed&login=1001"


async def test_org_allowlist_matches_immutable_id(make_client, gh, monkeypatch):
    await make_user("admin@example.com")
    monkeypatch.setattr(get_settings(), "github_allowed_orgs", ["id:77"])

    gh.orgs = [{"id": 99, "login": "id:77"}, {"id": 12, "login": "acme"}]
    blocked = make_client()
    r = await _callback(blocked, await _start(blocked))
    assert r.headers["location"].startswith("/login?error=not_allowed")

    gh.orgs = [{"id": 77, "login": "acme-renamed"}]
    allowed = make_client()
    await _callback(allowed, await _start(allowed))
    assert (await _me(allowed))["roles"] == ["viewer"]


@pytest.mark.parametrize(
    ("status", "location"),
    [(None, "/login?error=failed"), (502, "/login?error=failed"), (403, "/login?error=not_allowed&login=octocat")],
)
async def test_org_check_hiccup_is_a_retry_not_a_refusal(make_client, gh, monkeypatch, status, location):
    await make_user("admin@example.com")
    monkeypatch.setattr(get_settings(), "github_allowed_orgs", ["acme"])

    async def get_orgs(self):
        raise GitHubError("GitHub API /user/orgs: request failed (ReadTimeout)", status)

    monkeypatch.setattr(gh, "get_orgs", get_orgs)
    client = make_client()
    r = await _callback(client, await _start(client))
    assert r.headers["location"] == location


# ---------------------------------------------------- OAuth state binding (24)


def _forge(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


async def test_unsigned_link_cookie_cannot_link_victim(make_client, gh):
    await make_user("victim@example.com")
    victim = make_client()
    await login(victim, "victim@example.com")
    session = victim.cookies["kiln_session"]
    forged = _forge({"s": "attacker-chosen-state", "m": "link", "n": "/settings"})
    r = await _callback(victim, "attacker-chosen-state", f"kiln_session={session}; kiln_oauth={forged}")
    assert "error=state" in r.headers["location"]
    assert (await _me(victim))["github_login"] is None


async def test_link_state_from_another_session_is_rejected(make_client, gh):
    await make_user("victim@example.com")
    await make_user("attacker@example.com")
    attacker, victim = make_client(), make_client()
    await login(attacker, "attacker@example.com")
    await login(victim, "victim@example.com")
    state = await _start(attacker, "/auth/github/link")
    tossed = attacker.cookies[oauth.STATE_COOKIE]
    r = await _callback(victim, state, f"kiln_session={victim.cookies['kiln_session']}; kiln_oauth={tossed}")
    assert r.headers["location"] == "/settings?error=state"
    assert (await _me(victim))["github_login"] is None
    assert (await _me(attacker))["github_login"] is None


async def test_link_without_session_reports_session_expired(client, gh):
    await make_user("admin@example.com")
    await login(client, "admin@example.com")
    state = await _start(client, "/auth/github/link")
    r = await _callback(client, state, f"kiln_oauth={client.cookies[oauth.STATE_COOKIE]}")
    assert r.headers["location"] == "/login?error=session_expired"


async def test_signed_cookie_mode_cannot_be_changed(client, gh):
    await make_user("admin@example.com")
    state = await _start(client)
    body, _, sig = client.cookies[oauth.STATE_COOKIE].strip('"').partition(".")
    payload = json.loads(base64.urlsafe_b64decode(body))
    tampered = f"{_forge({**payload, 'm': 'link', 'n': '/evil'})}.{sig}"
    r = await _callback(client, state, f"kiln_oauth={tampered}")
    assert r.headers["location"] == "/login?error=state"


async def test_link_flow_still_works_and_reports_codes(make_client, gh):
    await make_user("admin@example.com")
    await make_user("other@example.com")
    owner, other = make_client(), make_client()
    await login(owner, "admin@example.com")
    r = await _callback(owner, await _start(owner, "/auth/github/link"))
    assert r.headers["location"] == "/settings?linked=1"

    await login(other, "other@example.com")
    r = await _callback(other, await _start(other, "/auth/github/link"))
    assert r.headers["location"] == "/settings?error=already_linked&login=octocat"


# --------------------------------------------- malformed state / cookie (27)


async def test_non_ascii_state_fails_cleanly(client, gh):
    r = await client.get("/auth/github/callback?code=good-code&state=%C3%A9")
    assert r.status_code == 302 and r.headers["location"] == "/login?error=state"
    await _start(client)
    r = await client.get("/auth/github/callback?code=good-code&state=%C3%A9")
    assert r.status_code == 302 and r.headers["location"] == "/login?error=state"


@pytest.mark.parametrize("cookie", [_forge([]), "not-base64!!", "%C3%A9.%C3%A9", "é.é"])
async def test_malformed_state_cookie_fails_cleanly(client, gh, cookie):
    r = await _callback(client, "abc", f"kiln_oauth={cookie}".encode())
    assert r.status_code == 302 and r.headers["location"] == "/login?error=state"


async def test_signed_cookie_that_is_not_an_object_fails_cleanly(client, gh):
    body = _forge(["abc"])
    r = await _callback(client, "abc", f"kiln_oauth={body}.{oauth._sign('cookie', body)}")
    assert r.status_code == 302 and r.headers["location"] == "/login?error=state"


async def test_github_cancel_is_a_code(client, gh):
    r = await client.get("/auth/github/callback?error=access_denied")
    assert r.headers["location"] == "/login?error=cancelled"


def test_login_param_only_for_valid_github_logins():
    assert oauth._fail("not_allowed", login="octo-cat").headers["location"] == "/login?error=not_allowed&login=octo-cat"
    assert oauth._fail("not_allowed", login="<b>x</b>").headers["location"] == "/login?error=not_allowed"
    assert oauth._fail("not_allowed", login="a" * 40).headers["location"] == "/login?error=not_allowed"


# --------------------------------------- sign-up errors are not "email in use" (15, 28)


async def test_missing_default_role_is_a_config_error(client, gh, monkeypatch):
    await make_user("admin@example.com")
    monkeypatch.setattr(get_settings(), "allow_signup", True)
    monkeypatch.setattr(get_settings(), "default_role", "deployers")
    r = await _callback(client, await _start(client))
    assert r.headers["location"] == "/login?error=config"
    assert await _user("mona@example.com") is None


async def test_real_email_collision_is_email_in_use(client, gh, monkeypatch):
    await make_user("admin@example.com")
    await make_user("mona@example.com")
    monkeypatch.setattr(get_settings(), "allow_signup", True)
    r = await _callback(client, await _start(client))
    assert r.headers["location"] == "/login?error=email_in_use"


# -------------------------------------------------------- safe_next (36, 18)


@pytest.mark.parametrize(
    "value",
    ["/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "/\x00x", "/x\x7f", "/\\evil.example",
     "//evil.example", "https://evil.example", "evil.example", "javascript:alert(1)", ""],
)
def test_safe_next_rejects_unsafe_values(value):
    assert oauth.safe_next(value) == "/"


def test_safe_next_keeps_relative_paths():
    assert oauth.safe_next("/instances?x=1#top") == "/instances?x=1#top"
    assert oauth.safe_next("/a:b/c") == "/a:b/c"


async def test_login_page_drops_control_character_next(client):
    r = await client.get("/login?next=%2F%09%2Fevil.example%2Flogin")
    assert r.status_code == 200 and "evil.example" not in r.text


# ------------------------------------------------- truncation in OAuth (29, 70)


async def test_oauth_signup_fits_columns(client, gh):
    gh.profile = {**PROFILE, "name": "N" * 250, "avatar_url": "https://avatars.example/" + "a" * 600}
    await _callback(client, await _start(client))
    user = await _user("mona@example.com")
    assert user is not None and len(user.full_name) == 200 and user.avatar_url is None


async def test_oauth_rejects_email_longer_than_column(client, gh):
    gh.email = ("m" * 320 + "@example.com", True)
    r = await _callback(client, await _start(client))
    assert r.headers["location"] == "/login?error=no_verified_email"


# ------------------------------------------------ GitHub client over MockTransport


def _client(handler, token: str | None = "gho_x") -> GitHubClient:
    return GitHubClient(token, transport=httpx.MockTransport(handler))


def _commit_json(message: str, author_name: str = "Some Person", login: str | None = "octocat") -> dict:
    return {
        "sha": SHA,
        "commit": {"message": message, "author": {"name": author_name, "date": "2026-11-01T10:00:00Z"}},
        "author": {"login": login} if login else None,
    }


# ------------------------------------------------- repository identity (19)


async def test_repo_methods_address_github_by_id(tmp_path: Path):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        path = request.url.path
        if path.endswith("/tarball/" + SHA):
            return httpx.Response(200, content=b"tar")
        if "/commits/" in path:
            return httpx.Response(200, json=_commit_json("feat: x"))
        if path.endswith("/branches"):
            return httpx.Response(200, json=[{"name": "main"}])
        return httpx.Response(200, json={"id": 42, "full_name": "acme/app"})

    async with _client(handler) as gh:
        assert (await gh.get_repository(42))["full_name"] == "acme/app"
        assert (await gh.get_commit(42, "feature/x")).sha == SHA
        assert await gh.download_tarball(42, SHA, tmp_path / "src.tgz") == 3
        assert await gh.list_branches("acme/app") == ["main"]
    assert seen == [
        "/repositories/42",
        "/repositories/42/commits/feature/x",
        f"/repositories/42/tarball/{SHA}",
        "/repos/acme/app/branches",
    ]


async def _seed_repo(**config) -> Repository:
    async with get_sessionmaker()() as db:
        repo = Repository(
            github_id=42, full_name="acme-old/app", owner="acme-old", name="app",
            html_url="https://github.com/acme-old/app", default_branch="main",
            detected_config=config or {"dockerfile": True, "compose_file": "compose.yaml", "files": ["Dockerfile"]},
        )
        db.add(repo)
        await db.commit()
        return repo


def _patch_api_client(monkeypatch, handler) -> None:
    monkeypatch.setattr(repositories_api, "GitHubClient", lambda token: _client(handler, token))


async def test_repo_endpoints_use_github_id(admin_client, monkeypatch):
    repo = await _seed_repo()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path.endswith("/readme"):
            return httpx.Response(200, text="# App")
        if request.url.path.endswith("/branches"):
            return httpx.Response(200, json=[{"name": "dev"}, {"name": "main"}])
        return httpx.Response(200, json=[{"name": "Dockerfile", "type": "file"}])

    _patch_api_client(monkeypatch, handler)
    assert (await admin_client.get(f"/api/v1/repositories/{repo.id}/branches")).json() == ["main", "dev"]
    assert (await admin_client.get(f"/api/v1/repositories/{repo.id}/readme")).json() == {"content": "# App"}
    assert (await admin_client.post(f"/api/v1/repositories/{repo.id}/detect")).status_code == 200
    assert seen == ["/repositories/42/branches", "/repositories/42/readme", "/repositories/42/contents/"]


# ---------------------------------------------- transport errors -> GitHubError (21)


async def test_primary_email_server_error_is_not_no_verified_email():
    async with _client(lambda request: httpx.Response(502, json={"message": "Server Error"})) as gh:
        with pytest.raises(GitHubError):
            await gh.get_primary_email()
    async with _client(lambda request: httpx.Response(404, json={"message": "Not Found"})) as gh:
        assert await gh.get_primary_email() == (None, False)


def _timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("timed out", request=request)


async def test_transport_errors_become_github_errors(tmp_path: Path):
    async with _client(_timeout) as gh:
        with pytest.raises(GitHubError):
            await gh.get_user()
        with pytest.raises(GitHubError):
            await gh.get_readme(42)
        with pytest.raises(GitHubError):
            await gh.download_tarball(42, SHA, tmp_path / "src.tgz")
    with pytest.raises(GitHubError):
        await exchange_code("code", transport=httpx.MockTransport(_timeout))


async def test_oauth_callback_survives_transport_error(client, gh, monkeypatch):
    async def failing_exchange(code):
        return await exchange_code(code, transport=httpx.MockTransport(_timeout))

    monkeypatch.setattr(oauth, "exchange_code", failing_exchange)
    r = await _callback(client, await _start(client))
    assert r.status_code == 302 and r.headers["location"] == "/login?error=failed"


async def test_readme_endpoint_reports_transport_error(admin_client, monkeypatch):
    repo = await _seed_repo()
    _patch_api_client(monkeypatch, _timeout)
    r = await admin_client.get(f"/api/v1/repositories/{repo.id}/readme")
    assert r.status_code == 502


def _repo_json(github_id: int, **extra) -> dict:
    name = f"repo-{github_id}"
    return {
        "id": github_id, "full_name": f"acme/{name}", "owner": {"login": "acme"}, "name": name,
        "html_url": f"https://github.com/acme/{name}", "default_branch": "main",
        "pushed_at": "2026-11-01T10:00:00Z", "visibility": "public", **extra,
    }


async def _linked_user(db) -> User:
    user = await create_user(db, email="dev@example.com", full_name="Dev")
    user.oauth_accounts.append(OAuthAccount(provider="github", provider_user_id="1", login="dev", access_token="gho_x"))
    await db.commit()
    return user


async def test_one_detection_timeout_does_not_abort_sync():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=[_repo_json(i) for i in (1, 2, 3)])
        if request.url.path in ("/repositories/2/contents/", "/repos/acme/repo-2/contents/"):
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json=[{"name": "Dockerfile", "type": "file"}])

    async with get_sessionmaker()() as db:
        user = await _linked_user(db)
        async with _client(handler) as gh:
            result = await sync_repositories(db, user, client=gh)
        repos = {r.github_id: r for r in (await db.scalars(select(Repository))).all()}
    assert result.total == 3 and set(repos) == {1, 2, 3}
    assert repos[1].has_dockerfile and repos[3].has_dockerfile
    assert repos[2].detected_at is None


# -------------------------------------------------- detect_config 404s (22)


async def test_detect_config_only_treats_empty_repo_as_empty():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repositories/1/contents/":
            return httpx.Response(404, json={"message": "This repository is empty."})
        return httpx.Response(404, json={"message": "No commit found for the ref typo"})

    async with _client(handler) as gh:
        assert await gh.detect_config(1, "main") == {"dockerfile": False, "compose_file": None, "files": []}
        with pytest.raises(GitHubError):
            await gh.detect_config(2, "typo")


async def test_detect_endpoint_keeps_config_on_404(admin_client, monkeypatch):
    repo = await _seed_repo()
    _patch_api_client(monkeypatch, lambda request: httpx.Response(404, json={"message": "Not Found"}))
    r = await admin_client.post(f"/api/v1/repositories/{repo.id}/detect?branch=typo")
    assert r.status_code == 502
    async with get_sessionmaker()() as db:
        stored = await db.get(Repository, repo.id)
        assert stored.detected_config["dockerfile"] is True and stored.detected_at is None


# ------------------------------------------------ commit edge cases (23, 57, 71, 29, 70)


async def test_get_commit_handles_empty_message_and_long_author():
    long_name = "x" * 150
    async with _client(lambda request: httpx.Response(200, json=_commit_json("", long_name, login=None))) as gh:
        commit = await gh.get_commit(42, "main")
    assert commit.message == "" and commit.author == "x" * 100


async def test_get_commit_first_line_and_message_cap():
    async with _client(lambda request: httpx.Response(200, json=_commit_json("m" * 600 + "\r\nbody"))) as gh:
        commit = await gh.get_commit(42, "main")
    assert commit.message == "m" * 500 and commit.author == "octocat"


async def test_sync_fits_repository_columns():
    long = _repo_json(9, default_branch="b" * 150, language="L" * 80, visibility="v" * 30)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=[long])
        return httpx.Response(404, json={"message": "Not Found"})

    async with get_sessionmaker()() as db:
        user = await _linked_user(db)
        async with _client(handler) as gh:
            await sync_repositories(db, user, client=gh)
        repo = await db.scalar(select(Repository))
    assert repo.default_branch == "b" * 150 and len(repo.language) == 50 and len(repo.visibility) == 16


# ------------------------------------------------- codeload token in logs (30)


class _TarballRedirect(http.server.BaseHTTPRequestHandler):
    """Real HTTP, so httpcore's own DEBUG trace (response headers included) runs too."""

    def do_GET(self) -> None:
        if self.path.startswith("/codeload/"):
            self._reply(200, b"tarball")
        else:
            location = f"http://127.0.0.1:{self.server.server_port}/codeload/app.tar.gz?token=SECRETDOWNLOADTOKEN"
            self._reply(302, b"", Location=location)

    def _reply(self, status: int, body: bytes, **headers: str) -> None:
        self.send_response(status)
        for name, value in {"Content-Length": str(len(body)), **headers}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def local_github(monkeypatch):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TarballRedirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(get_settings(), "github_api_url", f"http://127.0.0.1:{server.server_port}")
    yield
    server.shutdown()
    server.server_close()


async def test_codeload_token_is_not_logged(tmp_path: Path, caplog, local_github):
    caplog.set_level(logging.DEBUG)
    # An explicit transport keeps any HTTP(S)_PROXY in the environment out of the way.
    async with GitHubClient("gho_x", transport=httpx.AsyncHTTPTransport()) as gh:
        assert await gh.download_tarball(42, SHA, tmp_path / "src.tgz") == 7
    assert "SECRETDOWNLOADTOKEN" not in caplog.text


# ------------------------------------------------ sync dedupe (20, 64)


async def test_sync_dedupes_repeated_repos():
    class PagedGH:
        async def list_repos(self):
            # Page 1 ends with repo 100; a push shifts it onto page 2 as well.
            return [_repo_json(i) for i in range(1, 101)] + [_repo_json(i) for i in range(100, 150)]

        async def detect_config(self, repo, ref=None):
            return {"dockerfile": True, "compose_file": None, "files": ["Dockerfile"]}

    async with get_sessionmaker()() as db:
        user = await _linked_user(db)
        result = await sync_repositories(db, user, client=PagedGH())
        count = len((await db.scalars(select(Repository))).all())
    assert (result.created, result.updated, result.total) == (149, 0, 149) and count == 149


# --------------------------------------- undecryptable token counts as not linked


async def test_missing_token_counts_as_not_linked(monkeypatch):
    monkeypatch.setattr(get_settings(), "github_service_token", None)
    async with get_sessionmaker()() as db:
        user = await _linked_user(db)
        user.github.access_token = None
        assert github_token_for(user) == (None, "no credentials (public repositories only)")
        with pytest.raises(GitHubNotLinked):
            await sync_repositories(db, user)
