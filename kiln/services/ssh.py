"""SSH access to deployment hosts.

Host keys are pinned on first successful connection (trust on first use). Every later
connection must present the same key, otherwise it is refused with ``HostKeyMismatch``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import asyncssh

from kiln.core.config import get_settings

if TYPE_CHECKING:
    from kiln.models import Host

LineCallback = Callable[[str], Awaitable[None]]
_SEP = "::kiln::"


class SSHError(RuntimeError):
    pass


class HostKeyMismatch(SSHError):
    pass


class HostKeyNotPinned(SSHError):
    pass


class CommandFailed(SSHError):
    def __init__(self, command: str, exit_status: int, output: str) -> None:
        tail = "\n".join(output.strip().splitlines()[-15:])
        super().__init__(f"Command exited with status {exit_status}:\n{tail}")
        self.command = command
        self.exit_status = exit_status
        self.output = output


@dataclass
class SSHTarget:
    hostname: str
    port: int
    username: str
    private_key: str | None = None
    key_passphrase: str | None = None
    password: str | None = None
    pinned_host_key: str | None = None

    @classmethod
    def from_host(cls, host: Host) -> SSHTarget:
        return cls(
            hostname=host.hostname,
            port=host.port,
            username=host.username,
            private_key=host.private_key if host.auth_method == "key" else None,
            key_passphrase=host.key_passphrase,
            password=host.password if host.auth_method == "password" else None,
            pinned_host_key=host.host_key,
        )


@dataclass
class ProbeResult:
    host_key: str
    fingerprint: str
    os_info: str
    cpus: int
    cpu_percent: float
    mem_total_mb: int
    mem_percent: float
    docker_version: str | None
    docker_error: str | None
    containers_running: int

    @property
    def metrics(self) -> dict[str, float | int]:
        return {
            "cpus": self.cpus,
            "cpu_percent": round(self.cpu_percent, 1),
            "mem_total_mb": self.mem_total_mb,
            "mem_percent": round(self.mem_percent, 1),
            "containers_running": self.containers_running,
        }


# ---------------------------------------------------------------------------- keys


def generate_keypair(comment: str = "kiln") -> tuple[str, str]:
    """Return (private_key_openssh, public_key_openssh) for a new ed25519 key."""
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    return key.export_private_key("openssh").decode(), key.export_public_key("openssh").decode().strip()


def public_key_from_private(private_key: str, passphrase: str | None = None) -> str:
    try:
        key = asyncssh.import_private_key(private_key, passphrase)
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise SSHError(f"Invalid private key: {exc}") from exc
    return key.export_public_key("openssh").decode().strip()


def fingerprint(public_key: str) -> str:
    return asyncssh.import_public_key(public_key).get_fingerprint("sha256")


# ---------------------------------------------------------------------- connection


class RemoteSession:
    """An open SSH connection with the helpers the deployer needs."""

    def __init__(self, conn: asyncssh.SSHClientConnection) -> None:
        self.conn = conn

    async def run(
        self,
        command: str,
        *,
        check: bool = True,
        on_line: LineCallback | None = None,
        timeout: float | None = None,
    ) -> tuple[int, str]:
        lines: list[str] = []
        async with self.conn.create_process(
            command, stderr=asyncssh.STDOUT, encoding="utf-8", errors="replace"
        ) as proc:

            async def pump() -> None:
                async for raw in proc.stdout:
                    if not raw:  # EOF marker; a real blank line arrives as "\n"
                        continue
                    line = raw.rstrip("\r\n")
                    lines.append(line)
                    if on_line is not None:
                        await on_line(line)

            try:
                await asyncio.wait_for(pump(), timeout)
            except TimeoutError as exc:
                proc.kill()
                raise SSHError(f"Command timed out after {timeout}s") from exc
            await proc.wait()
            status = proc.exit_status if proc.exit_status is not None else -1
        output = "\n".join(lines)
        if check and status != 0:
            raise CommandFailed(command, status, output)
        return status, output

    async def put(self, local: Path, remote: str) -> None:
        async with self.conn.start_sftp_client() as sftp:
            await sftp.put(str(local), remote)

    async def write_text(self, remote: str, content: str, mode: int = 0o600) -> None:
        async with self.conn.start_sftp_client() as sftp:
            attrs = asyncssh.SFTPAttrs(permissions=mode)
            async with sftp.open(remote, "w", attrs) as fh:
                await fh.write(content)
            await sftp.chmod(remote, mode)

    def server_host_key(self) -> str:
        key = self.conn.get_server_host_key()
        if key is None:  # pragma: no cover - asyncssh always sets this for clients
            raise SSHError("Server did not present a host key")
        return key.export_public_key("openssh").decode().strip()


async def connect(target: SSHTarget, *, allow_unpinned: bool = False) -> RemoteSession:
    if target.pinned_host_key:
        known_hosts: object = ([asyncssh.import_public_key(target.pinned_host_key)], [], [])
    elif allow_unpinned:
        known_hosts = None
    else:
        raise HostKeyNotPinned("Host key not verified yet: run a connection test on this host first")

    client_keys = None
    if target.private_key:
        try:
            client_keys = [asyncssh.import_private_key(target.private_key, target.key_passphrase)]
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise SSHError(f"Stored private key could not be loaded: {exc}") from exc

    timeout = get_settings().ssh_connect_timeout
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                target.hostname,
                port=target.port,
                username=target.username,
                known_hosts=known_hosts,
                client_keys=client_keys,
                password=target.password,
                agent_path=None,
                config=None,
                keepalive_interval=30,
                connect_timeout=timeout,
            ),
            timeout=timeout + 5,
        )
    except asyncssh.HostKeyNotVerifiable as exc:
        raise HostKeyMismatch(
            "The host key presented by the server does not match the pinned key. "
            "If the server was rebuilt, reset the pinned key; otherwise this may be an attack."
        ) from exc
    except asyncssh.PermissionDenied as exc:
        raise SSHError(f"Authentication failed for {target.username}@{target.hostname}") from exc
    except (OSError, TimeoutError, asyncssh.Error) as exc:
        raise SSHError(f"Could not connect to {target.hostname}:{target.port}: {exc}") from exc
    return RemoteSession(conn)


@asynccontextmanager
async def open_session(target: SSHTarget, *, allow_unpinned: bool = False) -> AsyncIterator[RemoteSession]:
    session = await connect(target, allow_unpinned=allow_unpinned)
    try:
        yield session
    finally:
        session.conn.close()
        await session.conn.wait_closed()


# --------------------------------------------------------------------------- probe

PROBE_COMMAND = f"""
( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" ) || uname -sr; echo '{_SEP}'
nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1; echo '{_SEP}'
cat /proc/loadavg 2>/dev/null; echo '{_SEP}'
grep -E '^(MemTotal|MemAvailable):' /proc/meminfo 2>/dev/null; echo '{_SEP}'
docker version --format '{{{{.Server.Version}}}}' 2>&1; echo "rc=$?"; echo '{_SEP}'
docker ps -q 2>/dev/null | wc -l
""".strip()


def parse_probe(output: str, host_key: str) -> ProbeResult:
    parts = [p.strip() for p in output.split(_SEP)]
    parts += [""] * (6 - len(parts))
    os_info, nproc_s, loadavg, meminfo, docker_s, containers_s = parts[:6]

    cpus = int(nproc_s.split()[0]) if nproc_s.split() and nproc_s.split()[0].isdigit() else 1
    load1 = float(loadavg.split()[0]) if loadavg else 0.0
    mem: dict[str, int] = {}
    for line in meminfo.splitlines():
        key, _, rest = line.partition(":")
        if rest.split():
            mem[key] = int(rest.split()[0])  # kB
    total = mem.get("MemTotal", 0)
    available = mem.get("MemAvailable", total)

    docker_lines = docker_s.splitlines()
    rc_ok = bool(docker_lines) and docker_lines[-1] == "rc=0"
    docker_out = "\n".join(docker_lines[:-1]).strip()
    return ProbeResult(
        host_key=host_key,
        fingerprint=fingerprint(host_key),
        os_info=os_info.splitlines()[0][:255] if os_info else "",
        cpus=cpus,
        cpu_percent=min(100.0, load1 / max(cpus, 1) * 100),
        mem_total_mb=total // 1024,
        mem_percent=((total - available) / total * 100) if total else 0.0,
        docker_version=docker_out if rc_ok else None,
        docker_error=None if rc_ok else (docker_out or "docker not found")[:500],
        containers_running=int(containers_s) if containers_s.isdigit() else 0,
    )


async def probe(target: SSHTarget) -> ProbeResult:
    """Connect (pinning the host key if none is stored yet) and gather health information."""
    async with open_session(target, allow_unpinned=True) as session:
        host_key = session.server_host_key()
        _, output = await session.run(PROBE_COMMAND, check=False, timeout=30)
    return parse_probe(output, host_key)
