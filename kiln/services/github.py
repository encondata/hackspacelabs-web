"""GitHub OAuth and REST API client."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from kiln.core.config import get_settings

log = logging.getLogger(__name__)

COMPOSE_FILENAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


class GitHubError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class CommitInfo:
    sha: str
    message: str
    author: str
    date: datetime | None


def authorize_url(state: str) -> str:
    s = get_settings()
    params = {
        "client_id": s.github_client_id,
        "redirect_uri": s.github_callback_url,
        "scope": s.oauth_scopes,
        "state": state,
        "allow_signup": "false",
    }
    return f"{s.github_web_url}/login/oauth/authorize?{urlencode(params)}"


async def exchange_code(code: str, *, transport: httpx.AsyncBaseTransport | None = None) -> tuple[str, str]:
    """Exchange an OAuth code for (access_token, granted_scopes)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=15, transport=transport) as client:
        resp = await client.post(
            f"{s.github_web_url}/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": s.github_client_id,
                "client_secret": s.github_client_secret,
                "code": code,
                "redirect_uri": s.github_callback_url,
            },
        )
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if resp.status_code != 200 or "access_token" not in data:
        raise GitHubError(data.get("error_description") or "GitHub did not return an access token")
    return data["access_token"], data.get("scope", "")


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


class GitHubClient:
    """Thin async wrapper over the REST API. ``token`` may be None for public data."""

    def __init__(self, token: str | None, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Kiln",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=get_settings().github_api_url,
            headers=headers,
            timeout=30,
            transport=transport,
            follow_redirects=True,
        )

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _get(self, path: str, **params: Any) -> Any:
        resp = await self._client.get(path, params=params or None)
        if resp.status_code >= 400:
            try:
                message = resp.json().get("message", resp.text)
            except (ValueError, AttributeError):
                message = resp.text[:200] or resp.reason_phrase
            raise GitHubError(f"GitHub API {path}: {message}", resp.status_code)
        return resp.json()

    async def _paginate(self, path: str, **params: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = await self._get(path, per_page=100, page=page, **params)
            items.extend(batch)
            if len(batch) < 100 or page >= 20:
                return items
            page += 1

    async def get_user(self) -> dict[str, Any]:
        return await self._get("/user")

    async def get_user_by_login(self, login: str) -> dict[str, Any]:
        return await self._get(f"/users/{quote(login, safe='')}")

    async def get_primary_email(self) -> tuple[str | None, bool]:
        """Return (email, verified) for the user's primary address."""
        try:
            emails = await self._get("/user/emails")
        except GitHubError:
            return None, False
        primary = next((e for e in emails if e.get("primary")), None)
        return (primary["email"], bool(primary.get("verified"))) if primary else (None, False)

    async def get_org_logins(self) -> set[str]:
        orgs = await self._paginate("/user/orgs")
        return {o["login"].lower() for o in orgs}

    async def list_repos(self) -> list[dict[str, Any]]:
        return await self._paginate(
            "/user/repos", affiliation="owner,collaborator,organization_member", sort="pushed"
        )

    async def list_branches(self, full_name: str) -> list[str]:
        branches = await self._paginate(f"/repos/{full_name}/branches")
        return [b["name"] for b in branches]

    async def get_commit(self, full_name: str, ref: str) -> CommitInfo:
        data = await self._get(f"/repos/{full_name}/commits/{quote(ref, safe='')}")
        commit = data["commit"]
        author = (data.get("author") or {}).get("login") or commit["author"]["name"]
        return CommitInfo(
            sha=data["sha"],
            message=commit["message"].splitlines()[0][:500],
            author=author,
            date=_parse_dt(commit["author"].get("date")),
        )

    async def detect_config(self, full_name: str, ref: str | None = None) -> dict[str, Any]:
        """Look at the repo root for a Dockerfile / compose file."""
        try:
            entries = await self._get(f"/repos/{full_name}/contents/", **({"ref": ref} if ref else {}))
        except GitHubError as exc:
            if exc.status_code in (404, 409):  # empty repository
                return {"dockerfile": False, "compose_file": None, "files": []}
            raise
        names = [e["name"] for e in entries if e.get("type") == "file"]
        return {
            "dockerfile": "Dockerfile" in names,
            "compose_file": next((n for n in COMPOSE_FILENAMES if n in names), None),
            "files": sorted(names)[:50],
        }

    async def get_readme(self, full_name: str) -> str | None:
        resp = await self._client.get(
            f"/repos/{full_name}/readme", headers={"Accept": "application/vnd.github.raw+json"}
        )
        return resp.text[:20000] if resp.status_code == 200 else None

    async def download_tarball(self, full_name: str, sha: str, dest: Path) -> int:
        """Stream the repository tarball at ``sha`` to ``dest``. Returns bytes written."""
        size = 0
        async with self._client.stream("GET", f"/repos/{full_name}/tarball/{sha}") as resp:
            if resp.status_code >= 400:
                raise GitHubError(f"Could not download {full_name}@{sha[:7]} ({resp.status_code})")
            with dest.open("wb") as fh:
                async for chunk in resp.aiter_bytes():
                    fh.write(chunk)
                    size += len(chunk)
        return size


async def detect_many(client: GitHubClient, repos: list[tuple[str, str]], concurrency: int = 8) -> dict[str, dict]:
    """Detect build config for many (full_name, branch) pairs concurrently."""
    sem = asyncio.Semaphore(concurrency)
    results: dict[str, dict] = {}

    async def one(full_name: str, branch: str) -> None:
        async with sem:
            try:
                results[full_name] = await client.detect_config(full_name, branch)
            except GitHubError as exc:
                log.info("Config detection failed for %s: %s", full_name, exc)

    await asyncio.gather(*(one(f, b) for f, b in repos))
    return results
