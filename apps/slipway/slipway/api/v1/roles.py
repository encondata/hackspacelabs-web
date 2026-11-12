"""Slipway's built-in roles. Who holds which role is managed in Keycloak (the HackSpaceLabs portal)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter
from sqlalchemy import select

from slipway.api.deps import DB, require
from slipway.core.permissions import PERMISSION_DESCRIPTIONS, Perm
from slipway.models import Role
from slipway.schemas import PermissionOut, RoleOut
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/roles", tags=["roles"])

Reader = Annotated[AuthContext, require(Perm.ROLES_READ)]


@router.get("/permissions")
async def permission_catalog(ctx: Reader) -> list[PermissionOut]:
    return [PermissionOut(name=k, description=v) for k, v in PERMISSION_DESCRIPTIONS.items()]


@router.get("")
async def list_roles(ctx: Reader, db: DB) -> list[RoleOut]:
    roles = (await db.scalars(select(Role).order_by(Role.is_system.desc(), Role.name))).all()
    return [RoleOut.model_validate(r) for r in roles]
