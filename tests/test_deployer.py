"""Deployment pipeline tests with fake GitHub and SSH backends."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from kiln.db.session import get_sessionmaker
from kiln.models import Deployment, Host, Instance, Repository
from kiln.services import deployer, ssh
from kiln.services.github import CommitInfo
from tests.conftest import make_user

SHA = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0"


def test_validation_helpers():
    assert deployer.slugify("Kiln Web (prod)") == "kiln-web-prod"
    with pytest.raises(ValueError):
        deployer.slugify("!!!")
    assert deployer.clean_relative_path("./docker/Dockerfile") == "docker/Dockerfile"
    assert deployer.clean_relative_path(".", allow_dot=True) == "."
    for bad in ("../etc/passwd", "/etc/passwd", "a/../../b", "x; rm -rf /", "$(id)"):
        with pytest.raises(ValueError):
            deployer.clean_relative_path(bad)
    assert deployer.clean_deploy_root("/opt/kiln/") == "/opt/kiln"
    for bad in ("/", "relative", "/opt/../etc"):
        with pytest.raises(ValueError):
            deployer.clean_deploy_root(bad)
    with pytest.raises(ValueError):
        deployer.clean_env({"BAD-KEY": "x"})
    with pytest.raises(ValueError):
        deployer.clean_env({"KEY": "line1\nline2"})
    assert deployer.render_env({"B": "2", "A": "x y"}) == "A=x y\nB=2\n"


def _instance(**kw) -> Instance:
    host = Host(name="prod-01", hostname="10.0.0.1", port=22, username="deploy", deploy_root="/opt/kiln")
    repo = Repository(github_id=1, full_name="acme/web", owner="acme", name="web", html_url="https://github.com/acme/web")
    defaults = dict(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"), name="web", slug="web-prod", branch="main",
        build_source="dockerfile", dockerfile_path="Dockerfile", build_context=".", compose_file="docker-compose.yml",
        ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}], volumes=[{"source": "/var/lib/web", "target": "/data"}],
        env={}, host=host, repository=repo,
    )
    defaults.update(kw)
    return Instance(**defaults)


def test_dockerfile_commands_are_quoted():
    inst = _instance(dockerfile_path="docker/Dockerfile prod", build_context="src")
    build, rm, run = deployer.build_commands(inst, "/opt/kiln/web-prod/releases/a1b2c3d4e5f6", SHA)
    assert "-f 'docker/Dockerfile prod'" in build and build.endswith(" src")
    assert "kiln/web-prod:a1b2c3d4e5f6" in build
    assert rm.startswith("docker rm -f kiln-web-prod")
    assert "-p 8080:3000/tcp" in run and "-v /var/lib/web:/data" in run
    assert "--env-file /opt/kiln/web-prod/shared/.env" in run
    assert "--label kiln.instance=00000000-0000-0000-0000-000000000001" in run


def test_compose_commands():
    inst = _instance(build_source="compose", compose_file="compose.yaml")
    [cmd] = deployer.build_commands(inst, "/opt/kiln/web-prod/releases/x", SHA)
    assert "docker compose -p kiln-web-prod -f compose.yaml up -d --build" in cmd
    assert "ln -sfn /opt/kiln/web-prod/shared/.env .env" in cmd
    assert deployer.control_command(inst, "stop").endswith("docker compose -p kiln-web-prod -f compose.yaml stop")
    assert "rm -rf -- /opt/kiln/web-prod" in deployer.destroy_command(inst)
    with pytest.raises(ValueError):
        deployer.control_command(inst, "explode")


# ------------------------------------------------------------------- pipeline


class FakeGitHub:
    calls: list[str] = []

    def __init__(self, token):
        self.token = token

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_commit(self, full_name, ref):
        FakeGitHub.calls.append(f"commit {full_name}@{ref}")
        return CommitInfo(sha=SHA, message="feat: ship it", author="octocat", date=None)

    async def download_tarball(self, full_name, sha, dest: Path):
        dest.write_bytes(b"fake-tarball")
        return 12


class FakeRemote:
    def __init__(self, fail_on: str | None = None):
        self.commands: list[str] = []
        self.files: dict[str, str] = {}
        self.fail_on = fail_on

    async def run(self, command, *, check=True, on_line=None, timeout=None):
        self.commands.append(command)
        if on_line and "docker build" in command:
            await on_line("Step 1/3 : FROM node:22")
        if self.fail_on and self.fail_on in command:
            raise ssh.CommandFailed(command, 1, "build exploded")
        return 0, ""

    async def put(self, local, remote):
        self.files[remote] = Path(local).read_text()

    async def write_text(self, remote, content, mode=0o600):
        self.files[remote] = content


async def _seed(env: dict[str, str]) -> uuid.UUID:
    user = await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        repo = Repository(github_id=42, full_name="acme/web", owner="acme", name="web",
                          html_url="https://github.com/acme/web", detected_config={})
        inst = Instance(name="web", slug="web-prod", branch="main", host=host, repository=repo, env=env,
                        ports=[{"host": 8080, "container": 3000, "protocol": "tcp"}], volumes=[])
        db.add(inst)
        await db.flush()
        dep = Deployment(instance_id=inst.id, branch="main", triggered_by_id=user.id, log="")
        db.add(dep)
        await db.commit()
        return dep.id


def _connect(remote: FakeRemote):
    @asynccontextmanager
    async def factory(target):
        assert target.hostname == "10.0.0.1"
        yield remote
    return factory


async def test_successful_deployment():
    dep_id = await _seed({"NODE_ENV": "production"})
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)

    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "succeeded", dep.log
        assert dep.commit_sha == SHA and dep.commit_message == "feat: ship it"
        assert dep.instance.status == "running" and dep.instance.current_commit_sha == SHA
        assert "Step 1/3" in dep.log and "Deployment succeeded" in dep.log
    assert remote.files["/opt/kiln/web-prod/shared/.env"] == "NODE_ENV=production\n"
    assert remote.files["/opt/kiln/web-prod/releases/a1b2c3d4e5f6.tar.gz"] == "fake-tarball"
    assert any("docker build" in c for c in remote.commands)
    assert any(c.startswith("ln -sfn /opt/kiln/web-prod/releases/a1b2c3d4e5f6 /opt/kiln/web-prod/current") for c in remote.commands)
    # The GitHub token never appears in anything sent to the host.
    assert not any("token" in c.lower() for c in remote.commands)


async def test_failed_deployment_records_error():
    dep_id = await _seed({})
    remote = FakeRemote(fail_on="docker build")
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "failed" and "build exploded" in dep.error
        assert dep.instance.status == "failed"
        assert not any(c.startswith("docker run") for c in remote.commands)


async def test_recover_interrupted_marks_stale_deployments():
    dep_id = await _seed({})
    await deployer.runner.recover_interrupted()
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "failed" and "restart" in dep.error
