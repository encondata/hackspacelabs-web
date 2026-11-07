"""Deployment history and build output."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter
from sqlalchemy import select

from kiln.api.deps import DB, not_found, require
from kiln.core.permissions import Perm
from kiln.models import Deployment
from kiln.schemas import DeploymentDetail, DeploymentOut
from kiln.services.auth import AuthContext

router = APIRouter(prefix="/deployments", tags=["deployments"])

Reader = Annotated[AuthContext, require(Perm.DEPLOYMENTS_READ)]


@router.get("")
async def list_deployments(
    ctx: Reader, db: DB, instance_id: uuid.UUID | None = None, status: str | None = None, limit: int = 50
) -> list[DeploymentOut]:
    stmt = select(Deployment).order_by(Deployment.created_at.desc()).limit(max(1, min(limit, 200)))
    if instance_id:
        stmt = stmt.where(Deployment.instance_id == instance_id)
    if status:
        stmt = stmt.where(Deployment.status == status)
    return [DeploymentOut.of(d) for d in (await db.scalars(stmt)).all()]


@router.get("/{deployment_id}")
async def get_deployment(deployment_id: uuid.UUID, ctx: Reader, db: DB, log_offset: int = 0) -> DeploymentDetail:
    """``log_offset`` lets the UI poll for only the new part of the build log."""
    dep = await db.get(Deployment, deployment_id, populate_existing=True)
    if dep is None:
        raise not_found("Deployment")
    log = dep.log or ""
    offset = max(0, min(log_offset, len(log)))
    return DeploymentDetail(**DeploymentOut.of(dep).model_dump(), log=log[offset:], log_offset=len(log))
