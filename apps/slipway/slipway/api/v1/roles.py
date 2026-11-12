"""Role management. Built-in roles are read-only; custom roles can be created freely."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from slipway.api.deps import DB, not_found, require
from slipway.core.config import get_settings
from slipway.core.permissions import PERMISSION_DESCRIPTIONS, Perm, has_permission
from slipway.models import Role
from slipway.schemas import PermissionOut, RoleIn, RoleOut, RoleUpdate
from slipway.services import audit
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/roles", tags=["roles"])

Reader = Annotated[AuthContext, require(Perm.ROLES_READ)]
Writer = Annotated[AuthContext, require(Perm.ROLES_WRITE)]


def _check_grantable(ctx: AuthContext, perms: list[str]) -> None:
    denied = [p for p in perms if not has_permission(ctx.user.permissions, p)]
    if denied:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"You cannot grant: {', '.join(denied)}")


@router.get("/permissions")
async def permission_catalog(ctx: Reader) -> list[PermissionOut]:
    return [PermissionOut(name=k, description=v) for k, v in PERMISSION_DESCRIPTIONS.items()]


@router.get("")
async def list_roles(ctx: Reader, db: DB) -> list[RoleOut]:
    roles = (await db.scalars(select(Role).order_by(Role.is_system.desc(), Role.name))).all()
    return [RoleOut.model_validate(r) for r in roles]


@router.post("", status_code=201)
async def create_role(body: RoleIn, ctx: Writer, request: Request, db: DB) -> RoleOut:
    _check_grantable(ctx, body.permissions)
    if await db.scalar(select(Role).where(Role.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A role with this name already exists")
    role = Role(name=body.name, description=body.description, permissions=body.permissions, is_system=False)
    db.add(role)
    await db.flush()
    audit.record(db, "role.create", actor=ctx.user, target=role, summary=f"Created role {role.name}", request=request)
    await db.commit()
    return RoleOut.model_validate(role)


async def _custom_role(db: DB, role_id: uuid.UUID) -> Role:
    role = await db.get(Role, role_id)
    if role is None:
        raise not_found("Role")
    if role.is_system:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Built-in roles cannot be changed")
    return role


@router.patch("/{role_id}")
async def update_role(role_id: uuid.UUID, body: RoleUpdate, ctx: Writer, request: Request, db: DB) -> RoleOut:
    role = await _custom_role(db, role_id)
    if body.permissions is not None:
        # Only newly added permissions need to be grantable; untouched ones (e.g. a wildcard) may stay.
        _check_grantable(ctx, [p for p in body.permissions if p not in role.permissions])
        role.permissions = body.permissions
    if body.description is not None:
        role.description = body.description
    audit.record(db, "role.update", actor=ctx.user, target=role, summary=f"Updated role {role.name}", request=request)
    await db.commit()
    return RoleOut.model_validate(role)


@router.delete("/{role_id}", status_code=204)
async def delete_role(role_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    role = await _custom_role(db, role_id)
    if role.name == get_settings().default_role:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"'{role.name}' is the role new accounts get (SLIPWAY_DEFAULT_ROLE); change that setting first",
        )
    audit.record(db, "role.delete", actor=ctx.user, target=role, summary=f"Deleted role {role.name}", request=request)
    await db.delete(role)
    await db.commit()
