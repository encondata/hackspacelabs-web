"""Host health checks and the optional background poller."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kiln.core.config import get_settings
from kiln.db.base import utcnow
from kiln.db.session import session_scope
from kiln.models import Host, HostStatus
from kiln.services import ssh

log = logging.getLogger(__name__)

CPU_WARN = 85.0
MEM_WARN = 90.0


def status_from_probe(result: ssh.ProbeResult) -> HostStatus:
    if result.docker_version is None:
        return HostStatus.WARNING
    if result.cpu_percent >= CPU_WARN or result.mem_percent >= MEM_WARN:
        return HostStatus.WARNING
    return HostStatus.HEALTHY


async def check_host(db: AsyncSession, host: Host) -> Host:
    """Probe a host over SSH and store the result. Pins the host key on first contact."""
    host.last_checked_at = utcnow()
    try:
        result = await ssh.probe(ssh.SSHTarget.from_host(host))
    except ssh.HostKeyMismatch as exc:
        host.status = HostStatus.ERROR
        host.last_error = str(exc)
    except ssh.SSHError as exc:
        host.status = HostStatus.UNREACHABLE
        host.last_error = str(exc)
    else:
        if not host.host_key:
            host.host_key = result.host_key
            host.host_key_fingerprint = result.fingerprint
        host.status = status_from_probe(result)
        host.last_error = result.docker_error
        host.docker_version = result.docker_version
        host.os_info = result.os_info
        host.metrics = result.metrics
    await db.commit()
    return host


async def poll_hosts_forever() -> None:
    interval = get_settings().host_poll_interval
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval)
        try:
            async with session_scope() as db:
                hosts = (await db.scalars(select(Host).where(Host.host_key.is_not(None)))).all()
                for host in hosts:
                    await check_host(db, host)
        except asyncio.CancelledError:
            raise
        except Exception:  # keep polling whatever happens
            log.exception("Host health poll failed")
