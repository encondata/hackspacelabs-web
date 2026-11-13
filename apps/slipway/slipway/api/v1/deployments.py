"""Deployment history and build output."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select
from sqlalchemy.orm import defer

from slipway.api.deps import DB, not_found, require
from slipway.core.permissions import Perm
from slipway.models import Deployment
from slipway.schemas import DeploymentDetail, DeploymentOut
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/deployments", tags=["deployments"])

Reader = Annotated[AuthContext, require(Perm.DEPLOYMENTS_READ)]


@router.get("")
async def list_deployments(
    ctx: Reader,
    db: DB,
    instance_id: uuid.UUID | None = None,
    status: Annotated[str | None, Query(max_length=16)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeploymentOut]:
    stmt = select(Deployment).options(defer(Deployment.log, raiseload=True)).order_by(Deployment.created_at.desc()).limit(limit)
    if instance_id:
        stmt = stmt.where(Deployment.instance_id == instance_id)
    if status:
        stmt = stmt.where(Deployment.status == status)
    return [DeploymentOut.of(d) for d in (await db.scalars(stmt)).all()]


@router.get("/{deployment_id}")
async def get_deployment(
    deployment_id: uuid.UUID, ctx: Reader, db: DB, log_offset: Annotated[int, Query(ge=0)] = 0
) -> DeploymentDetail:
    """``log_offset`` lets the UI poll for only the new part of the build log."""
    dep = await db.get(Deployment, deployment_id, populate_existing=True)
    if dep is None:
        raise not_found("Deployment")
    log = dep.log or ""
    offset = max(0, min(log_offset, len(log)))
    return DeploymentDetail(**DeploymentOut.of(dep).model_dump(), log=log[offset:], log_offset=len(log))
