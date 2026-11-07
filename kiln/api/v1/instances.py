"""Instances: a repository + branch running on a host. Create, configure, deploy, operate."""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from kiln.api.deps import DB, Auth, not_found, require
from kiln.core.permissions import Perm
from kiln.models import Deployment, DeploymentStatus, Host, Instance, InstanceStatus, Repository, User
from kiln.schemas import ActionOut, DeploymentOut, InstanceCreate, InstanceOut, InstanceUpdate
from kiln.services import audit, deployer, ssh
from kiln.services.auth import AuthContext

router = APIRouter(prefix="/instances", tags=["instances"])

Reader = Annotated[AuthContext, require(Perm.INSTANCES_READ)]
Writer = Annotated[AuthContext, require(Perm.INSTANCES_WRITE)]
Operator = Annotated[AuthContext, require(Perm.INSTANCES_OPERATE)]
Deployer = Annotated[AuthContext, require(Perm.DEPLOYMENTS_CREATE)]
LogReader = Annotated[AuthContext, require(Perm.INSTANCES_READ, Perm.LOGS_READ)]


async def _get(db: DB, instance_id: uuid.UUID) -> Instance:
    instance = await db.get(Instance, instance_id)
    if instance is None:
        raise not_found("Instance")
    return instance


async def queue_deployment(db: DB, instance: Instance, user: User) -> Deployment:
    active = await db.scalar(
        select(Deployment).where(
            Deployment.instance_id == instance.id,
            Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING]),
        )
    )
    if active is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "A deployment is already in progress for this instance")
    if not instance.host.is_pinned:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Host {instance.host.name} has not been verified yet; run a connection check first",
        )
    dep = Deployment(instance_id=instance.id, branch=instance.branch, triggered_by_id=user.id, log="")
    db.add(dep)
    await db.flush()
    return dep


def _ssh_error(exc: ssh.SSHError) -> HTTPException:
    return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


@router.get("")
async def list_instances(ctx: Reader, db: DB, host_id: uuid.UUID | None = None, repository_id: uuid.UUID | None = None) -> list[InstanceOut]:
    stmt = select(Instance).order_by(Instance.name)
    if host_id:
        stmt = stmt.where(Instance.host_id == host_id)
    if repository_id:
        stmt = stmt.where(Instance.repository_id == repository_id)
    return [InstanceOut.of(i) for i in (await db.scalars(stmt)).all()]


@router.post("", status_code=201)
async def create_instance(body: InstanceCreate, ctx: Writer, request: Request, db: DB) -> InstanceOut:
    if body.deploy and not ctx.can(Perm.DEPLOYMENTS_CREATE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {Perm.DEPLOYMENTS_CREATE}")
    repo = await db.get(Repository, body.repository_id)
    host = await db.get(Host, body.host_id)
    if repo is None or host is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown repository or host")
    try:
        slug = deployer.slugify(body.name)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if await db.scalar(select(Instance).where(Instance.slug == slug)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"An instance named '{slug}' already exists")

    instance = Instance(
        name=body.name.strip(),
        slug=slug,
        repository=repo,
        host=host,
        branch=body.branch or repo.default_branch,
        build_source=body.build_source,
        dockerfile_path=body.dockerfile_path or "Dockerfile",
        build_context=body.build_context or ".",
        compose_file=body.compose_file or repo.compose_file or "docker-compose.yml",
        env=body.env or {},
        ports=[p.model_dump() for p in body.ports or []],
        volumes=[v.model_dump() for v in body.volumes or []],
        status=InstanceStatus.CREATED,
        created_by_id=ctx.user.id,
    )
    db.add(instance)
    await db.flush()
    audit.record(
        db, "instance.create", actor=ctx.user, target=instance,
        summary=f"Created instance {instance.name} ({repo.full_name}@{instance.branch} on {host.name})", request=request,
    )
    dep = await queue_deployment(db, instance, ctx.user) if body.deploy else None
    await db.commit()
    if dep is not None:
        deployer.runner.submit(dep.id, instance.id)
    return InstanceOut.of(instance)


@router.get("/{instance_id}")
async def get_instance(instance_id: uuid.UUID, ctx: Reader, db: DB) -> InstanceOut:
    return InstanceOut.of(await _get(db, instance_id))


@router.get("/{instance_id}/env")
async def get_env(instance_id: uuid.UUID, ctx: Writer, db: DB) -> dict[str, str]:
    """Environment variable values are only visible to people who can edit the instance."""
    return (await _get(db, instance_id)).env or {}


@router.patch("/{instance_id}")
async def update_instance(instance_id: uuid.UUID, body: InstanceUpdate, ctx: Writer, request: Request, db: DB) -> InstanceOut:
    instance = await _get(db, instance_id)
    data = body.model_dump(exclude_unset=True)
    if "host_id" in data and data["host_id"] != instance.host_id:
        if instance.status not in (InstanceStatus.CREATED, InstanceStatus.FAILED):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Destroy the running instance before moving it to another host")
        host = await db.get(Host, data["host_id"])
        if host is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown host")
        instance.host = host
    for field in ("name", "branch", "build_source", "dockerfile_path", "build_context", "compose_file", "env"):
        if data.get(field) is not None:
            setattr(instance, field, data[field])
    if body.ports is not None:
        instance.ports = [p.model_dump() for p in body.ports]
    if body.volumes is not None:
        instance.volumes = [v.model_dump() for v in body.volumes]
    changed = sorted(k for k in data if k != "env") + (["env"] if "env" in data else [])
    audit.record(
        db, "instance.update", actor=ctx.user, target=instance,
        summary=f"Updated {instance.name}: {', '.join(changed) or 'no changes'}", request=request,
    )
    await db.commit()
    return InstanceOut.of(instance)


@router.delete("/{instance_id}", status_code=204)
async def delete_instance(instance_id: uuid.UUID, ctx: Writer, request: Request, db: DB, purge: bool = True) -> None:
    """Delete the instance. With ``purge`` (default) its containers and files are removed from the host."""
    instance = await _get(db, instance_id)
    if purge and instance.status != InstanceStatus.CREATED:
        try:
            await deployer.run_on_instance(instance, deployer.destroy_command(instance))
        except ssh.SSHError as exc:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, f"{exc}. Retry, or delete with purge=false to keep the host untouched."
            ) from exc
    audit.record(db, "instance.delete", actor=ctx.user, target=instance, summary=f"Deleted instance {instance.name}", request=request)
    await db.delete(instance)
    await db.commit()


@router.post("/{instance_id}/deploy", status_code=202)
async def deploy(instance_id: uuid.UUID, ctx: Deployer, request: Request, db: DB) -> DeploymentOut:
    instance = await _get(db, instance_id)
    dep = await queue_deployment(db, instance, ctx.user)
    audit.record(db, "deployment.create", actor=ctx.user, target=dep, summary=f"Deploy {instance.name}@{instance.branch}", request=request)
    await db.commit()
    await db.refresh(dep)
    deployer.runner.submit(dep.id, instance.id)
    return DeploymentOut.of(dep)


@router.post("/{instance_id}/actions/{action}")
async def control(
    instance_id: uuid.UUID, action: Literal["start", "stop", "restart"], ctx: Operator, request: Request, db: DB
) -> ActionOut:
    instance = await _get(db, instance_id)
    if instance.status in (InstanceStatus.CREATED, InstanceStatus.DEPLOYING):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Instance is {instance.status}")
    try:
        output = await deployer.run_on_instance(instance, deployer.control_command(instance, action))
    except ssh.SSHError as exc:
        raise _ssh_error(exc) from exc
    instance.status = InstanceStatus.STOPPED if action == "stop" else InstanceStatus.RUNNING
    audit.record(db, f"instance.{action}", actor=ctx.user, target=instance, summary=f"{action.title()} {instance.name}", request=request)
    await db.commit()
    return ActionOut(ok=True, output=output)


@router.get("/{instance_id}/containers")
async def containers(instance_id: uuid.UUID, ctx: Reader, db: DB) -> list[dict[str, str]]:
    instance = await _get(db, instance_id)
    if instance.status == InstanceStatus.CREATED:
        return []
    try:
        output = await deployer.run_on_instance(instance, deployer.status_command(instance))
    except ssh.SSHError as exc:
        raise _ssh_error(exc) from exc
    rows = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        rows.append({k: str(data.get(k, "")) for k in ("Names", "Image", "State", "Status", "Ports", "RunningFor")})
    return rows


@router.get("/{instance_id}/logs")
async def logs(instance_id: uuid.UUID, ctx: LogReader, db: DB, tail: int = 200) -> ActionOut:
    instance = await _get(db, instance_id)
    if instance.status == InstanceStatus.CREATED:
        return ActionOut(ok=True, output="")
    try:
        output = await deployer.run_on_instance(instance, deployer.logs_command(instance, tail), check=False)
    except ssh.SSHError as exc:
        raise _ssh_error(exc) from exc
    return ActionOut(ok=True, output=output)


@router.get("/{instance_id}/deployments")
async def instance_deployments(instance_id: uuid.UUID, ctx: Auth, db: DB, limit: int = 20) -> list[DeploymentOut]:
    if not ctx.can(Perm.DEPLOYMENTS_READ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {Perm.DEPLOYMENTS_READ}")
    deps = await db.scalars(
        select(Deployment)
        .where(Deployment.instance_id == instance_id)
        .order_by(Deployment.created_at.desc())
        .limit(min(limit, 100))
    )
    return [DeploymentOut.of(d) for d in deps]
