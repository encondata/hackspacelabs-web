"""SSH layer tests against a real in-process asyncssh server."""

from __future__ import annotations

import shlex

import asyncssh
import pytest

from kiln.services import ssh

PROBE_OUTPUT = """Ubuntu 24.04 LTS
::kiln::
4
::kiln::
1.00 0.50 0.25 1/200 1234
::kiln::
MemTotal:        8000000 kB
MemAvailable:    6000000 kB
::kiln::
27.3.1
rc=0
::kiln::
3
"""


class _Server(asyncssh.SSHServer):
    authorized: asyncssh.SSHKey

    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return key.public_data == self.authorized.public_data

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return password == "s3cret"


def sent_command(process: asyncssh.SSHServerProcess) -> str:
    """The command as Kiln built it: run() sends ``exec /bin/sh -c <quoted command>``."""
    words = shlex.split(process.command or "")
    assert words[:3] == ["exec", "/bin/sh", "-c"] and len(words) == 4, process.command
    return words[3]


async def _handle(process: asyncssh.SSHServerProcess) -> None:
    cmd = sent_command(process)
    if "os-release" in cmd:
        process.stdout.write(PROBE_OUTPUT)
        process.exit(0)
    elif cmd.startswith("echo"):
        process.stdout.write("hello\nworld\n")
        process.exit(0)
    else:
        process.stderr.write("boom\n")
        process.exit(3)


@pytest.fixture
async def ssh_server():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_priv, client_pub = ssh.generate_keypair("test")
    _Server.authorized = asyncssh.import_public_key(client_pub)
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=_handle, sftp_factory=True
    )
    port = server.sockets[0].getsockname()[1]
    yield {"port": port, "host_key": host_key, "client_key": client_priv}
    server.close()
    await server.wait_closed()


def _target(srv, **kw) -> ssh.SSHTarget:
    return ssh.SSHTarget(hostname="127.0.0.1", port=srv["port"], username="deploy", private_key=srv["client_key"], **kw)


async def test_probe_pins_host_key_and_parses_metrics(ssh_server):
    result = await ssh.probe(_target(ssh_server))
    expected = ssh_server["host_key"].export_public_key("openssh").decode().strip()
    assert result.host_key == expected
    assert result.fingerprint.startswith("SHA256:")
    assert result.os_info == "Ubuntu 24.04 LTS"
    assert result.cpus == 4 and result.cpu_percent == 25.0
    assert result.mem_total_mb == 7812 and round(result.mem_percent) == 25
    assert result.docker_version == "27.3.1" and result.containers_running == 3


async def test_pinned_key_is_enforced(ssh_server):
    good = ssh_server["host_key"].export_public_key("openssh").decode()
    async with ssh.open_session(_target(ssh_server, pinned_host_key=good)) as remote:
        status, output = await remote.run("echo hi")
    assert status == 0 and output == "hello\nworld"

    impostor = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()
    with pytest.raises(ssh.HostKeyMismatch):
        await ssh.connect(_target(ssh_server, pinned_host_key=impostor))


async def test_unpinned_connection_refused_outside_probe(ssh_server):
    with pytest.raises(ssh.HostKeyNotPinned):
        await ssh.connect(_target(ssh_server))


async def test_password_auth_and_bad_credentials(ssh_server):
    pinned = ssh_server["host_key"].export_public_key("openssh").decode()
    target = ssh.SSHTarget(hostname="127.0.0.1", port=ssh_server["port"], username="deploy", password="s3cret", pinned_host_key=pinned)
    async with ssh.open_session(target) as remote:
        assert (await remote.run("echo"))[0] == 0
    target.password = "wrong"
    with pytest.raises(ssh.SSHError, match="Authentication failed"):
        await ssh.connect(target)


async def test_command_failure_and_streaming(ssh_server, tmp_path):
    pinned = ssh_server["host_key"].export_public_key("openssh").decode()
    lines: list[str] = []

    async def on_line(line: str) -> None:
        lines.append(line)

    async with ssh.open_session(_target(ssh_server, pinned_host_key=pinned)) as remote:
        await remote.run("echo", on_line=on_line)
        with pytest.raises(ssh.CommandFailed) as exc:
            await remote.run("false")
        assert exc.value.exit_status == 3 and "boom" in exc.value.output

        env_path = tmp_path / ".env"
        await remote.write_text(str(env_path), "A=1\n")
    assert lines == ["hello", "world"]
    assert env_path.read_text() == "A=1\n"
    assert oct(env_path.stat().st_mode & 0o777) == "0o600"


async def test_unreachable_host():
    target = ssh.SSHTarget(hostname="127.0.0.1", port=1, username="deploy", password="x")
    with pytest.raises(ssh.SSHError, match="Could not connect"):
        await ssh.probe(target)


def test_key_helpers():
    priv, pub = ssh.generate_keypair("kiln@test")
    assert pub.startswith("ssh-ed25519 ") and pub.endswith("kiln@test")
    assert ssh.public_key_from_private(priv) == pub
    with pytest.raises(ssh.SSHError):
        ssh.public_key_from_private("not a key")


def test_parse_probe_without_docker():
    out = PROBE_OUTPUT.replace("27.3.1\nrc=0", "sh: docker: not found\nrc=127")
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()
    result = ssh.parse_probe(out, key)
    assert result.docker_version is None and "not found" in result.docker_error
