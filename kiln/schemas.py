"""Pydantic request/response models for the JSON API."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from kiln.core.permissions import validate_permissions
from kiln.models import Deployment, Host, Instance, Repository, User
from kiln.services import deployer

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- auth


class LoginIn(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=500)


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=500)
    full_name: str = Field("", max_length=200)


class ProfileUpdate(BaseModel):
    full_name: str = Field(max_length=200)


class PasswordChange(BaseModel):
    current_password: str | None = None
    new_password: str = Field(max_length=500)


# -------------------------------------------------------------------------- users


class UserOut(Out):
    id: uuid.UUID
    email: str
    full_name: str
    display_name: str
    avatar_url: str | None
    is_active: bool
    roles: list[str]
    permissions: list[str]
    github_login: str | None
    has_password: bool
    created_at: datetime
    last_login_at: datetime | None

    @classmethod
    def of(cls, user: User) -> UserOut:
        return cls(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            roles=user.role_names,
            permissions=sorted(user.permissions),
            github_login=user.github.login if user.github else None,
            has_password=user.password_hash is not None,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )


class SessionOut(BaseModel):
    user: UserOut
    csrf_token: str


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field("", max_length=200)
    password: str | None = Field(None, max_length=500)
    # Pre-link a GitHub account so the user can sign in with GitHub straight away.
    github_login: str | None = Field(None, max_length=39, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
    roles: list[str] = Field(default_factory=lambda: ["viewer"])


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=200)
    is_active: bool | None = None
    roles: list[str] | None = None
    password: str | None = Field(None, max_length=500)


# -------------------------------------------------------------------------- roles


class RoleOut(Out):
    id: uuid.UUID
    name: str
    description: str
    permissions: list[str]
    is_system: bool


class RoleIn(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    description: str = Field("", max_length=255)
    permissions: list[str]

    @field_validator("permissions")
    @classmethod
    def _perms(cls, v: list[str]) -> list[str]:
        return validate_permissions(v)


class RoleUpdate(BaseModel):
    description: str | None = Field(None, max_length=255)
    permissions: list[str] | None = None

    @field_validator("permissions")
    @classmethod
    def _perms(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else validate_permissions(v)


class PermissionOut(BaseModel):
    name: str
    description: str


# ------------------------------------------------------------------------- tokens


class TokenOut(Out):
    id: uuid.UUID
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    expires_in_days: int | None = Field(None, ge=1, le=3650)


class TokenCreated(TokenOut):
    token: str


# -------------------------------------------------------------------------- hosts


class HostOut(Out):
    id: uuid.UUID
    name: str
    hostname: str
    port: int
    username: str
    environment: str
    description: str
    deploy_root: str
    auth_method: str
    public_key: str | None
    host_key_fingerprint: str | None
    status: str
    last_checked_at: datetime | None
    last_error: str | None
    docker_version: str | None
    os_info: str | None
    metrics: dict[str, Any]
    created_at: datetime


class _HostFields(BaseModel):
    hostname: str | None = Field(None, min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.:\-\[\]]+$")
    port: int | None = Field(None, ge=1, le=65535)
    username: str | None = Field(None, min_length=1, max_length=64, pattern=r"^[a-z_][a-z0-9_.-]*$")
    environment: str | None = Field(None, max_length=32)
    description: str | None = Field(None, max_length=255)
    deploy_root: str | None = None
    private_key: str | None = Field(None, max_length=20000)
    key_passphrase: str | None = Field(None, max_length=500)
    password: str | None = Field(None, max_length=500)

    @field_validator("deploy_root")
    @classmethod
    def _root(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_deploy_root(v)


class HostCreate(_HostFields):
    name: str = Field(pattern=_NAME_RE.pattern)
    hostname: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.:\-\[\]]+$")
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-z_][a-z0-9_.-]*$")
    port: int = Field(22, ge=1, le=65535)
    # "generate" asks Kiln to create an ed25519 key pair and show the public key.
    auth_method: Literal["generate", "key", "password"] = "generate"


class HostUpdate(_HostFields):
    name: str | None = Field(None, pattern=_NAME_RE.pattern)
    auth_method: Literal["generate", "key", "password"] | None = None


# --------------------------------------------------------------------------- repos


class RepoOut(Out):
    id: uuid.UUID
    github_id: int
    full_name: str
    owner: str
    name: str
    description: str
    visibility: str
    default_branch: str
    html_url: str
    language: str | None
    archived: bool
    pushed_at: datetime | None
    detected_config: dict[str, Any]
    deployable: bool
    synced_at: datetime | None

    @classmethod
    def of(cls, repo: Repository) -> RepoOut:
        return cls.model_validate(repo)


class SyncOut(BaseModel):
    created: int
    updated: int
    total: int


# ----------------------------------------------------------------------- instances


class PortMapping(BaseModel):
    host: int = Field(ge=1, le=65535)
    container: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"


class VolumeMapping(BaseModel):
    source: str = Field(min_length=1, max_length=255)
    target: str = Field(min_length=1, max_length=255)

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        v = v.strip()
        if ":" in v or not (v.startswith("/") or _VOLUME_NAME_RE.match(v)):
            raise ValueError("Volume source must be an absolute host path or a named volume")
        return v

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        v = v.strip()
        if ":" in v or not v.startswith("/"):
            raise ValueError("Volume target must be an absolute path inside the container")
        return v


class _InstanceFields(BaseModel):
    branch: str | None = Field(None, min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._/-]+$")
    build_source: Literal["dockerfile", "compose"] | None = None
    dockerfile_path: str | None = None
    build_context: str | None = None
    compose_file: str | None = None
    env: dict[str, str] | None = None
    ports: list[PortMapping] | None = None
    volumes: list[VolumeMapping] | None = None

    @field_validator("dockerfile_path", "compose_file")
    @classmethod
    def _rel(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_relative_path(v)

    @field_validator("build_context")
    @classmethod
    def _ctx(cls, v: str | None) -> str | None:
        return None if v is None else deployer.clean_relative_path(v, allow_dot=True)

    @field_validator("env")
    @classmethod
    def _env(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return None if v is None else deployer.clean_env(v)


class InstanceCreate(_InstanceFields):
    name: str = Field(min_length=1, max_length=100)
    repository_id: uuid.UUID
    host_id: uuid.UUID
    build_source: Literal["dockerfile", "compose"] = "dockerfile"
    deploy: bool = True


class InstanceUpdate(_InstanceFields):
    name: str | None = Field(None, min_length=1, max_length=100)
    host_id: uuid.UUID | None = None


class InstanceOut(Out):
    id: uuid.UUID
    name: str
    slug: str
    repository_id: uuid.UUID
    repository: str
    host_id: uuid.UUID
    host: str
    branch: str
    build_source: str
    dockerfile_path: str
    build_context: str
    compose_file: str
    env_keys: list[str]
    ports: list[dict[str, Any]]
    volumes: list[dict[str, Any]]
    status: str
    current_commit_sha: str | None
    last_deployed_at: datetime | None
    created_at: datetime

    @classmethod
    def of(cls, i: Instance) -> InstanceOut:
        return cls(
            id=i.id,
            name=i.name,
            slug=i.slug,
            repository_id=i.repository_id,
            repository=i.repository.full_name,
            host_id=i.host_id,
            host=i.host.name,
            branch=i.branch,
            build_source=i.build_source,
            dockerfile_path=i.dockerfile_path,
            build_context=i.build_context,
            compose_file=i.compose_file,
            env_keys=sorted((i.env or {}).keys()),
            ports=i.ports,
            volumes=i.volumes,
            status=i.status,
            current_commit_sha=i.current_commit_sha,
            last_deployed_at=i.last_deployed_at,
            created_at=i.created_at,
        )


class ActionOut(BaseModel):
    ok: bool
    output: str = ""


# --------------------------------------------------------------------- deployments


class DeploymentOut(BaseModel):
    id: uuid.UUID
    instance_id: uuid.UUID
    instance_name: str
    status: str
    branch: str
    commit_sha: str | None
    commit_message: str | None
    commit_author: str | None
    triggered_by: str | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime

    @classmethod
    def of(cls, d: Deployment) -> DeploymentOut:
        return cls(
            id=d.id,
            instance_id=d.instance_id,
            instance_name=d.instance.name,
            status=d.status,
            branch=d.branch,
            commit_sha=d.commit_sha,
            commit_message=d.commit_message,
            commit_author=d.commit_author,
            triggered_by=d.triggered_by.display_name if d.triggered_by else None,
            started_at=d.started_at,
            finished_at=d.finished_at,
            error=d.error,
            created_at=d.created_at,
        )


class DeploymentDetail(DeploymentOut):
    log: str
    log_offset: int


# --------------------------------------------------------------------------- audit


class AuditOut(BaseModel):
    id: uuid.UUID
    action: str
    actor: str | None
    target_type: str | None
    target_id: str | None
    summary: str
    ip: str | None
    created_at: datetime


def host_out(host: Host) -> HostOut:
    return HostOut.model_validate(host)
