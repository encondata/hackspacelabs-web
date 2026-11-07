"""Sync GitHub repositories into Kiln and pick credentials for GitHub access."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kiln.core.config import get_settings
from kiln.db.base import utcnow
from kiln.models import Repository, User
from kiln.services.github import GitHubClient, _parse_dt, detect_many


class GitHubNotLinked(RuntimeError):
    pass


@dataclass
class SyncResult:
    created: int
    updated: int
    total: int


def github_token_for(user: User | None) -> tuple[str | None, str]:
    """Return (token, description) to use for GitHub calls made on behalf of ``user``."""
    if user is not None and user.github and user.github.access_token:
        return user.github.access_token, f"@{user.github.login}"
    service = get_settings().github_service_token
    if service:
        return service, "the Kiln service token"
    return None, "no credentials (public repositories only)"


async def sync_repositories(db: AsyncSession, user: User, *, client: GitHubClient | None = None) -> SyncResult:
    account = user.github
    if account is None or not account.access_token:
        raise GitHubNotLinked("Link your GitHub account (Settings → Profile) to sync repositories")

    own_client = client is None
    client = client or GitHubClient(account.access_token)
    try:
        remote = await client.list_repos()
        existing = {
            r.github_id: r
            for r in (
                await db.scalars(select(Repository).where(Repository.github_id.in_([g["id"] for g in remote])))
            ).all()
        }
        now = utcnow()
        created = updated = 0
        needs_detection: list[tuple[str, str]] = []
        by_name: dict[str, Repository] = {}

        for data in remote:
            repo = existing.get(data["id"])
            pushed_at = _parse_dt(data.get("pushed_at"))
            if repo is None:
                repo = Repository(github_id=data["id"], detected_config={})
                db.add(repo)
                created += 1
            else:
                updated += 1
            changed = repo.pushed_at != pushed_at or repo.detected_at is None
            repo.full_name = data["full_name"]
            repo.owner = data["owner"]["login"]
            repo.name = data["name"]
            repo.description = data.get("description") or ""
            repo.visibility = data.get("visibility") or ("private" if data.get("private") else "public")
            repo.default_branch = data.get("default_branch") or "main"
            repo.html_url = data["html_url"]
            repo.language = data.get("language")
            repo.archived = bool(data.get("archived"))
            repo.pushed_at = pushed_at
            repo.synced_at = now
            repo.synced_by_id = user.id
            by_name[repo.full_name] = repo
            if changed and not repo.archived:
                needs_detection.append((repo.full_name, repo.default_branch))

        for full_name, config in (await detect_many(client, needs_detection)).items():
            by_name[full_name].detected_config = config
            by_name[full_name].detected_at = now

        await db.commit()
        return SyncResult(created=created, updated=updated, total=len(remote))
    finally:
        if own_client:
            await client.__aexit__(None, None, None)
