"""Regression tests for the GitHub review findings: OAuth sign-up and state, redirects,
repository identity, transport errors, detection, truncation and log hygiene."""

from __future__ import annotations

import http.server
import logging
import threading
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from slipway.api.v1 import repositories as repositories_api
from slipway.core.config import get_settings
from slipway.db.session import get_sessionmaker
from slipway.models import OAuthAccount, Repository, User
from slipway.services.github import GitHubClient, GitHubError, exchange_code
from slipway.services.repos import GitHubNotLinked, github_token_for, sync_repositories

SHA = "a" * 40
PROFILE = {"id": 1001, "login": "octocat", "name": "Mona Octocat", "avatar_url": "https://avatars.githubusercontent.com/u/1001"}


# ----------------------------------------------------------------- OAuth helpers


async def _me(client) -> dict | None:
    r = await client.get("/api/v1/auth/me")
    return r.json()["user"] if r.status_code == 200 else None


async def _user(email: str) -> User | None:
    async with get_sessionmaker()() as db:
        return await db.scalar(select(User).where(User.email == email))


# ------------------------------------------- first sign-in vs. allowlists (17, 6)


# ------------------------------------------------ id-based allowlists (26, 14)


# ---------------------------------------------------- OAuth state binding (24)


# --------------------------------------------- malformed state / cookie (27)


# --------------------------------------- sign-up errors are not "email in use" (15, 28)


# -------------------------------------------------------- safe_next (36, 18)


# ------------------------------------------------- truncation in OAuth (29, 70)


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
    user = User(email="dev@example.com", full_name="Dev", roles=[], oauth_accounts=[])
    db.add(user)
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
