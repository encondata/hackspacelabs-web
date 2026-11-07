"""Sync GitHub repositories into Kiln and pick credentials for GitHub access."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kiln.core.config import get_settings
from kiln.db.base import utcnow
from kiln.models import Repository, User
from kiln.services.github import GitHubClient, RepoRef, _parse_dt, detect_many


class GitHubNotLinked(RuntimeError):
    pass


@dataclass
class SyncResult:
    created: int
    updated: int
    total: int


def github_token_for(user: User | None) -> tuple[str | None, str]:
    """Return (token, description) to use for GitHub calls made on behalf of ``user``.

    A linked account whose token is missing or could not be decrypted counts as not linked.
    """
    account = user.github if user is not None else None
    if account is not None and account.access_token:
        return account.access_token, f"@{account.login}"
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
        # Offset pagination sorted by push time can return a repo twice; keep one per id.
        remote = list({g["id"]: g for g in await client.list_repos()}.values())
        existing = {
            r.github_id: r
            for r in (
                await db.scalars(select(Repository).where(Repository.github_id.in_([g["id"] for g in remote])))
            ).all()
        }
        now = utcnow()
        created = updated = 0
        needs_detection: list[tuple[RepoRef, str]] = []
        by_id: dict[RepoRef, Repository] = {}

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
            # Clip to the column widths: PostgreSQL rejects over-long VARCHAR values.
            repo.full_name = data["full_name"][:200]
            repo.owner = data["owner"]["login"][:100]
            repo.name = data["name"][:100]
            repo.description = data.get("description") or ""
            repo.visibility = (data.get("visibility") or ("private" if data.get("private") else "public"))[:16]
            repo.default_branch = (data.get("default_branch") or "main")[:100]
            repo.html_url = data["html_url"][:300]
            repo.language = (data.get("language") or "")[:50] or None
            repo.archived = bool(data.get("archived"))
            repo.pushed_at = pushed_at
            repo.synced_at = now
            repo.synced_by_id = user.id
            by_id[repo.github_id] = repo
            if changed and not repo.archived:
                needs_detection.append((repo.github_id, repo.default_branch))

        for github_id, config in (await detect_many(client, needs_detection)).items():
            by_id[github_id].detected_config = config
            by_id[github_id].detected_at = now

        await db.commit()
        return SyncResult(created=created, updated=updated, total=len(remote))
    finally:
        if own_client:
            await client.__aexit__(None, None, None)
