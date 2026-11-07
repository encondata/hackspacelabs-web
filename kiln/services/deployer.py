"""Build and run instances on remote Docker hosts over SSH.

Pipeline for one deployment:

1. Resolve the branch to a commit SHA through the GitHub API.
2. Download the source tarball on the Kiln server (the GitHub token never reaches the host).
3. Upload it over SFTP and unpack into ``<deploy_root>/<slug>/releases/<sha12>``.
4. Write ``shared/.env`` (mode 600) from the instance's encrypted environment variables.
5. ``docker build`` + ``docker run`` (Dockerfile mode) or ``docker compose up -d --build``.
6. Point ``current`` at the new release and prune old releases/images.

Persistent data must live in named volumes or absolute host paths: each release gets a
fresh directory, so relative bind mounts (``./data``) do not survive a redeploy.
"""

from __future__ import annotations

import asyncio
import logging
import posixpath
import re
import shlex
import tempfile
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update

from kiln.db.base import utcnow
from kiln.db.session import session_scope
from kiln.models import BuildSource, Deployment, DeploymentStatus, Instance, InstanceStatus
from kiln.services import ssh
from kiln.services.github import GitHubClient
from kiln.services.repos import github_token_for

log = logging.getLogger(__name__)

q = shlex.quote
KEEP_RELEASES = 3
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/@+-]+$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

ConnectFactory = Callable[[ssh.SSHTarget], AbstractAsyncContextManager[ssh.RemoteSession]]
GitHubFactory = Callable[[str | None], GitHubClient]


class DeployError(RuntimeError):
    pass


# ---------------------------------------------------------------------- validation


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:63].strip("-")
    if not SLUG_RE.match(slug):
        raise ValueError("Name must contain letters or numbers")
    return slug


def clean_relative_path(value: str, *, allow_dot: bool = False) -> str:
    """Normalise a repository-relative path, rejecting absolute paths and traversal."""
    value = (value or "").strip()
    norm = posixpath.normpath(value) if value else "."
    if norm == ".":
        if allow_dot:
            return "."
        raise ValueError("Path is required")
    if norm.startswith("/") or norm.split("/")[0] == ".." or not _SAFE_PATH.match(norm):
        raise ValueError(f"'{value}' is not a safe relative path")
    return norm


def clean_deploy_root(value: str) -> str:
    raw = (value or "").strip()
    norm = posixpath.normpath(raw) if raw else ""
    if not norm.startswith("/") or norm == "/" or ".." in raw.split("/") or not _SAFE_PATH.match(norm):
        raise ValueError("Deploy root must be an absolute path such as /opt/kiln")
    return norm


def clean_env(env: dict[str, str]) -> dict[str, str]:
    for key, value in env.items():
        if not ENV_KEY_RE.match(key):
            raise ValueError(f"'{key}' is not a valid environment variable name")
        if "\n" in value or "\r" in value:
            raise ValueError(f"Value for {key} must be a single line")
    return env


def render_env(env: dict[str, str]) -> str:
    return "".join(f"{k}={v}\n" for k, v in sorted(clean_env(dict(env)).items()))


# ------------------------------------------------------------------------ commands


@dataclass(frozen=True)
class InstancePaths:
    root: str
    slug: str

    @property
    def base(self) -> str:
        return f"{self.root}/{self.slug}"

    @property
    def releases(self) -> str:
        return f"{self.base}/releases"

    @property
    def shared(self) -> str:
        return f"{self.base}/shared"

    @property
    def env_file(self) -> str:
        return f"{self.shared}/.env"

    @property
    def current(self) -> str:
        return f"{self.base}/current"

    def release(self, sha: str) -> str:
        return f"{self.releases}/{sha[:12]}"


def paths_for(instance: Instance) -> InstancePaths:
    if not SLUG_RE.match(instance.slug):
        raise DeployError(f"Invalid instance slug {instance.slug!r}")
    return InstancePaths(clean_deploy_root(instance.host.deploy_root), instance.slug)


def _compose(instance: Instance) -> str:
    return f"docker compose -p {q(instance.compose_project)} -f {q(instance.compose_file)}"


def build_commands(instance: Instance, release_dir: str, sha: str) -> list[str]:
    """Commands (run in order) that build and start a release."""
    paths = paths_for(instance)
    label = f"kiln.instance={instance.id}"
    if instance.build_source == BuildSource.COMPOSE:
        return [
            f"cd {q(release_dir)} && ln -sfn {q(paths.env_file)} .env && "
            f"{_compose(instance)} up -d --build --remove-orphans"
        ]

    image = f"kiln/{instance.slug}:{sha[:12]}"
    run = [
        "docker run -d",
        f"--name {q(instance.container_name)}",
        "--restart unless-stopped",
        f"--env-file {q(paths.env_file)}",
        f"--label {q(label)} --label kiln.managed=true",
    ]
    for p in instance.ports:
        run.append(f"-p {int(p['host'])}:{int(p['container'])}/{'udp' if p.get('protocol') == 'udp' else 'tcp'}")
    for v in instance.volumes:
        run.append(f"-v {q(str(v['source']) + ':' + str(v['target']))}")
    run.append(q(image))
    return [
        f"cd {q(release_dir)} && BUILDKIT_PROGRESS=plain docker build --pull "
        f"-t {q(image)} -f {q(instance.dockerfile_path)} --label {q(label)} {q(instance.build_context)}",
        f"docker rm -f {q(instance.container_name)} >/dev/null 2>&1 || true",
        " ".join(run),
    ]


def finalize_command(instance: Instance, release_dir: str) -> str:
    paths = paths_for(instance)
    cmd = (
        f"ln -sfn {q(release_dir)} {q(paths.current)} && cd {q(paths.releases)} && "
        f"ls -1t | tail -n +{KEEP_RELEASES + 1} | while IFS= read -r d; do rm -rf -- \"$d\"; done"
    )
    if instance.build_source == BuildSource.DOCKERFILE:
        cmd += (
            f"; docker image ls --format '{{{{.Repository}}}}:{{{{.Tag}}}}' {q('kiln/' + instance.slug)} "
            f"| tail -n +{KEEP_RELEASES + 1} | xargs -r docker image rm >/dev/null 2>&1 || true"
        )
    return cmd


ACTIONS = ("start", "stop", "restart")


def control_command(instance: Instance, action: str) -> str:
    if action not in ACTIONS:
        raise ValueError(f"Unknown action {action}")
    if instance.build_source == BuildSource.COMPOSE:
        return f"cd {q(paths_for(instance).current)} && {_compose(instance)} {action}"
    return f"docker {action} {q(instance.container_name)}"


def status_command(instance: Instance) -> str:
    if instance.build_source == BuildSource.COMPOSE:
        flt = f"label=com.docker.compose.project={instance.compose_project}"
    else:
        flt = f"label=kiln.instance={instance.id}"
    return f"docker ps -a --filter {q(flt)} --format '{{{{json .}}}}'"


def logs_command(instance: Instance, tail: int = 200) -> str:
    tail = max(1, min(int(tail), 5000))
    if instance.build_source == BuildSource.COMPOSE:
        return (
            f"cd {q(paths_for(instance).current)} && "
            f"{_compose(instance)} logs --tail {tail} --timestamps --no-color 2>&1"
        )
    return f"docker logs --tail {tail} --timestamps {q(instance.container_name)} 2>&1"


def destroy_command(instance: Instance) -> str:
    paths = paths_for(instance)
    if instance.build_source == BuildSource.COMPOSE:
        stop = (
            f"(cd {q(paths.current)} && {_compose(instance)} down --remove-orphans) || "
            f"docker compose -p {q(instance.compose_project)} down --remove-orphans || true"
        )
    else:
        stop = (
            f"docker rm -f {q(instance.container_name)} >/dev/null 2>&1 || true; "
            f"docker image ls -q {q('kiln/' + instance.slug)} | xargs -r docker image rm -f >/dev/null 2>&1 || true"
        )
    return f"{stop}; rm -rf -- {q(paths.base)}"


# ------------------------------------------------------------------------- logging


class LogSink:
    """Buffers build output and appends it to ``deployments.log`` about once a second."""

    def __init__(self, deployment_id: uuid.UUID, flush_interval: float = 1.0) -> None:
        self.deployment_id = deployment_id
        self.flush_interval = flush_interval
        self._buf: list[str] = []
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def line(self, text: str) -> None:
        self._buf.append(f"[{utcnow():%H:%M:%S}] {text}\n")
        if time.monotonic() - self._last >= self.flush_interval or len(self._buf) >= 200:
            await self.flush()

    async def flush(self) -> None:
        async with self._lock:
            if not self._buf:
                return
            chunk = "".join(self._buf)
            self._buf.clear()
            self._last = time.monotonic()
            async with session_scope() as db:
                await db.execute(
                    update(Deployment)
                    .where(Deployment.id == self.deployment_id)
                    .values(log=func.coalesce(Deployment.log, "") + chunk)
                )


# ------------------------------------------------------------------------ pipeline


async def _finish(
    deployment_id: uuid.UUID, dep_status: DeploymentStatus, *, error: str | None = None, **instance_fields: Any
) -> None:
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None:
            return
        dep.status = dep_status
        dep.error = error
        dep.finished_at = utcnow()
        for key, value in instance_fields.items():
            setattr(dep.instance, key, value)


async def run_deployment(
    deployment_id: uuid.UUID,
    *,
    connect: ConnectFactory = ssh.open_session,
    github: GitHubFactory = GitHubClient,
) -> None:
    async with session_scope() as db:
        dep = await db.get(Deployment, deployment_id)
        if dep is None or dep.status != DeploymentStatus.QUEUED:
            return
        dep.status = DeploymentStatus.RUNNING
        dep.started_at = utcnow()
        dep.instance.status = InstanceStatus.DEPLOYING
        instance, branch, user = dep.instance, dep.branch, dep.triggered_by
        repo, host = instance.repository, instance.host

    sink = LogSink(deployment_id)
    try:
        token, source = github_token_for(user)
        await sink.line(f"Resolving {repo.full_name}@{branch} using {source}")
        async with github(token) as gh:
            commit = await gh.get_commit(repo.full_name, branch)
            async with session_scope() as db:
                await db.execute(
                    update(Deployment)
                    .where(Deployment.id == deployment_id)
                    .values(commit_sha=commit.sha, commit_message=commit.message, commit_author=commit.author)
                )
            await sink.line(f"Commit {commit.sha[:7]} — {commit.message} ({commit.author})")

            with tempfile.TemporaryDirectory(prefix="kiln-") as tmp:
                tarball = Path(tmp) / "source.tar.gz"
                size = await gh.download_tarball(repo.full_name, commit.sha, tarball)
                await sink.line(f"Downloaded source archive ({size / 1024:.0f} KiB)")

                await sink.line(f"Connecting to {host.username}@{host.address}")
                async with connect(ssh.SSHTarget.from_host(host)) as remote:
                    paths = paths_for(instance)
                    release = paths.release(commit.sha)
                    remote_tar = f"{paths.releases}/{commit.sha[:12]}.tar.gz"
                    await remote.run(f"mkdir -p {q(paths.releases)} {q(paths.shared)}")
                    await remote.put(tarball, remote_tar)
                    await remote.run(
                        f"rm -rf {q(release)} && mkdir -p {q(release)} && "
                        f"tar -xzf {q(remote_tar)} -C {q(release)} --strip-components=1 && rm -f {q(remote_tar)}"
                    )
                    await sink.line(f"Unpacked release into {release}")
                    await remote.write_text(paths.env_file, render_env(instance.env or {}))
                    await sink.line(f"Wrote {len(instance.env or {})} environment variable(s) to {paths.env_file}")

                    for command in build_commands(instance, release, commit.sha):
                        await sink.line(f"$ {command}")
                        await remote.run(command, on_line=sink.line, timeout=3600)
                    await remote.run(finalize_command(instance, release), check=False)

        await sink.line("Deployment succeeded")
        await sink.flush()
        await _finish(
            deployment_id,
            DeploymentStatus.SUCCEEDED,
            status=InstanceStatus.RUNNING,
            current_commit_sha=commit.sha,
            last_deployed_at=utcnow(),
        )
    except asyncio.CancelledError:
        await sink.line("Deployment interrupted: Kiln is shutting down")
        await sink.flush()
        await _finish(deployment_id, DeploymentStatus.CANCELLED, error="Interrupted", status=InstanceStatus.FAILED)
        raise
    except Exception as exc:
        log.info("Deployment %s failed: %s", deployment_id, exc)
        await sink.line(f"Deployment failed: {exc}")
        await sink.flush()
        await _finish(deployment_id, DeploymentStatus.FAILED, error=str(exc)[:2000], status=InstanceStatus.FAILED)


class DeployRunner:
    """Runs deployments as in-process asyncio tasks, one at a time per instance.

    Good enough for a single Kiln container. Swap for a queue + worker (arq, Celery...)
    if you need deployments to survive restarts or run on several Kiln replicas.
    """

    def __init__(self) -> None:
        self._tasks: set[asyncio.Task[None]] = set()
        self._locks: defaultdict[uuid.UUID, asyncio.Lock] = defaultdict(asyncio.Lock)

    def submit(self, deployment_id: uuid.UUID, instance_id: uuid.UUID) -> None:
        async def _run() -> None:
            async with self._locks[instance_id]:
                await run_deployment(deployment_id)

        task = asyncio.create_task(_run(), name=f"deploy-{deployment_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def recover_interrupted(self) -> None:
        """Mark deployments left queued/running by a previous process as failed."""
        async with session_scope() as db:
            stale = (
                await db.scalars(
                    select(Deployment).where(
                        Deployment.status.in_([DeploymentStatus.QUEUED, DeploymentStatus.RUNNING])
                    )
                )
            ).all()
            for dep in stale:
                dep.status = DeploymentStatus.FAILED
                dep.error = "Interrupted by a Kiln restart"
                dep.finished_at = utcnow()
                if dep.instance.status == InstanceStatus.DEPLOYING:
                    dep.instance.status = InstanceStatus.FAILED

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


runner = DeployRunner()


async def run_on_instance(
    instance: Instance, command: str, *, connect: ConnectFactory = ssh.open_session, check: bool = True
) -> str:
    async with connect(ssh.SSHTarget.from_host(instance.host)) as remote:
        _, output = await remote.run(command, check=check, timeout=120)
    return output
