"""Docker hosts reached over SSH."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func, select

from kiln.api.deps import DB, Auth, not_found, require
from kiln.core.permissions import Perm
from kiln.models import Host, HostAuthMethod, HostStatus, Instance
from kiln.schemas import HostCreate, HostOut, HostUpdate, host_out
from kiln.services import audit, ssh
from kiln.services.auth import AuthContext
from kiln.services.hosts import check_host

router = APIRouter(prefix="/hosts", tags=["hosts"])

Reader = Annotated[AuthContext, require(Perm.HOSTS_READ)]
Writer = Annotated[AuthContext, require(Perm.HOSTS_WRITE)]


def _apply_credentials(host: Host, body: HostCreate | HostUpdate) -> None:
    method = body.auth_method
    if method is None:
        # Update without changing method: allow replacing the key / password in place.
        if body.private_key and host.auth_method == HostAuthMethod.KEY:
            method = "key"
        elif body.password and host.auth_method == HostAuthMethod.PASSWORD:
            method = "password"
        else:
            return
    if method == "generate":
        host.private_key, host.public_key = ssh.generate_keypair(comment=f"kiln@{host.name}")
        host.key_passphrase = None
        host.password = None
        host.auth_method = HostAuthMethod.KEY
    elif method == "key":
        if not body.private_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Paste the private key Kiln should use")
        try:
            host.public_key = ssh.public_key_from_private(body.private_key, body.key_passphrase)
        except ssh.SSHError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        host.private_key = body.private_key.strip() + "\n"
        host.key_passphrase = body.key_passphrase or None
        host.password = None
        host.auth_method = HostAuthMethod.KEY
    elif method == "password":
        if not body.password:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "A password is required")
        host.password = body.password
        host.private_key = host.key_passphrase = host.public_key = None
        host.auth_method = HostAuthMethod.PASSWORD


async def _get(db: DB, host_id: uuid.UUID) -> Host:
    host = await db.get(Host, host_id)
    if host is None:
        raise not_found("Host")
    return host


@router.get("")
async def list_hosts(ctx: Reader, db: DB) -> list[HostOut]:
    return [host_out(h) for h in (await db.scalars(select(Host).order_by(Host.name))).all()]


@router.post("", status_code=201)
async def create_host(body: HostCreate, ctx: Writer, request: Request, db: DB) -> HostOut:
    if await db.scalar(select(Host).where(Host.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A host with this name already exists")
    host = Host(
        name=body.name,
        hostname=body.hostname,
        port=body.port,
        username=body.username,
        environment=body.environment or "",
        description=body.description or "",
        deploy_root=body.deploy_root or "/opt/kiln",
        metrics={},
        created_by_id=ctx.user.id,
    )
    _apply_credentials(host, body)
    db.add(host)
    await db.flush()
    audit.record(db, "host.create", actor=ctx.user, target=host, summary=f"Added host {host.name} ({host.address})", request=request)
    await db.commit()
    return host_out(host)


@router.get("/{host_id}")
async def get_host(host_id: uuid.UUID, ctx: Reader, db: DB) -> HostOut:
    return host_out(await _get(db, host_id))


@router.patch("/{host_id}")
async def update_host(host_id: uuid.UUID, body: HostUpdate, ctx: Writer, request: Request, db: DB) -> HostOut:
    host = await _get(db, host_id)
    if body.name and body.name != host.name:
        if await db.scalar(select(Host).where(Host.name == body.name)):
            raise HTTPException(status.HTTP_409_CONFLICT, "A host with this name already exists")
        host.name = body.name
    moved = (body.hostname and body.hostname != host.hostname) or (body.port and body.port != host.port)
    for field in ("hostname", "port", "username", "environment", "description", "deploy_root"):
        value = getattr(body, field)
        if value is not None:
            setattr(host, field, value)
    if moved:  # a different machine: forget the pinned host key
        host.host_key = host.host_key_fingerprint = None
        host.status = HostStatus.UNKNOWN
    _apply_credentials(host, body)
    audit.record(db, "host.update", actor=ctx.user, target=host, summary=f"Updated host {host.name}", request=request)
    await db.commit()
    return host_out(host)


@router.delete("/{host_id}", status_code=204)
async def delete_host(host_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> None:
    host = await _get(db, host_id)
    in_use = await db.scalar(select(func.count()).select_from(Instance).where(Instance.host_id == host.id))
    if in_use:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{in_use} instance(s) still run on this host; remove them first")
    audit.record(db, "host.delete", actor=ctx.user, target=host, summary=f"Removed host {host.name}", request=request)
    await db.delete(host)
    await db.commit()


@router.post("/{host_id}/check")
async def check(host_id: uuid.UUID, ctx: Auth, request: Request, db: DB) -> HostOut:
    """Probe the host. The first successful check pins its SSH host key, which needs hosts:write."""
    host = await _get(db, host_id)
    needed = Perm.HOSTS_READ if host.is_pinned else Perm.HOSTS_WRITE
    if not ctx.can(needed):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {needed}")
    was_pinned = host.is_pinned
    await check_host(db, host)
    if host.is_pinned and not was_pinned:
        audit.record(
            db, "host.key_pinned", actor=ctx.user, target=host,
            summary=f"Pinned host key {host.host_key_fingerprint} for {host.name}", request=request,
        )
        await db.commit()
    return host_out(host)


@router.post("/{host_id}/reset-host-key")
async def reset_host_key(host_id: uuid.UUID, ctx: Writer, request: Request, db: DB) -> HostOut:
    host = await _get(db, host_id)
    old = host.host_key_fingerprint
    host.host_key = host.host_key_fingerprint = None
    host.status = HostStatus.UNKNOWN
    audit.record(db, "host.key_reset", actor=ctx.user, target=host, summary=f"Reset pinned key {old} for {host.name}", request=request)
    await db.commit()
    return host_out(host)
