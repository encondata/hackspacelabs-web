"""GitHub repositories known to Kiln."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import or_, select

from kiln.api.deps import DB, not_found, require
from kiln.core.permissions import Perm
from kiln.db.base import utcnow
from kiln.models import Repository
from kiln.schemas import RepoOut, SyncOut
from kiln.services import audit
from kiln.services.auth import AuthContext
from kiln.services.github import GitHubClient, GitHubError
from kiln.services.repos import GitHubNotLinked, github_token_for, sync_repositories

router = APIRouter(prefix="/repositories", tags=["repositories"])

Reader = Annotated[AuthContext, require(Perm.REPOS_READ)]
Syncer = Annotated[AuthContext, require(Perm.REPOS_SYNC)]


async def _get(db: DB, repo_id: uuid.UUID) -> Repository:
    repo = await db.get(Repository, repo_id)
    if repo is None:
        raise not_found("Repository")
    return repo


def _gh_error(exc: GitHubError) -> HTTPException:
    return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


@router.get("")
async def list_repos(ctx: Reader, db: DB, q: str | None = None, deployable: bool | None = None) -> list[RepoOut]:
    stmt = select(Repository).order_by(Repository.pushed_at.desc().nulls_last())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(Repository.full_name.ilike(like), Repository.description.ilike(like)))
    repos = [RepoOut.of(r) for r in (await db.scalars(stmt)).all()]
    if deployable is not None:
        repos = [r for r in repos if r.deployable == deployable]
    return repos


@router.post("/sync")
async def sync(ctx: Syncer, request: Request, db: DB) -> SyncOut:
    try:
        result = await sync_repositories(db, ctx.user)
    except GitHubNotLinked as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    audit.record(
        db, "repos.sync", actor=ctx.user,
        summary=f"Synced {result.total} repositories ({result.created} new)", request=request,
    )
    await db.commit()
    return SyncOut(created=result.created, updated=result.updated, total=result.total)


@router.get("/{repo_id}")
async def get_repo(repo_id: uuid.UUID, ctx: Reader, db: DB) -> RepoOut:
    return RepoOut.of(await _get(db, repo_id))


@router.get("/{repo_id}/branches")
async def branches(repo_id: uuid.UUID, ctx: Reader, db: DB) -> list[str]:
    repo = await _get(db, repo_id)
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            names = await gh.list_branches(repo.github_id)
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    # Default branch first.
    return sorted(names, key=lambda n: (n != repo.default_branch, n))


@router.get("/{repo_id}/readme")
async def readme(repo_id: uuid.UUID, ctx: Reader, db: DB) -> dict[str, str | None]:
    repo = await _get(db, repo_id)
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            return {"content": await gh.get_readme(repo.github_id)}
    except GitHubError as exc:
        raise _gh_error(exc) from exc


@router.post("/{repo_id}/detect")
async def detect(repo_id: uuid.UUID, ctx: Syncer, db: DB, branch: str | None = None) -> RepoOut:
    repo = await _get(db, repo_id)
    token, _ = github_token_for(ctx.user)
    try:
        async with GitHubClient(token) as gh:
            config = await gh.detect_config(repo.github_id, branch or repo.default_branch)
    except GitHubError as exc:
        raise _gh_error(exc) from exc
    repo.detected_config = config
    repo.detected_at = utcnow()
    await db.commit()
    return RepoOut.of(repo)
