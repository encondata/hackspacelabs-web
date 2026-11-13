# Slipway

**Deploy. Run. Observe.** Slipway lists your GitHub repositories and deploys any of them as Docker containers on
your own Linux hosts over SSH, with roles and an audit trail. It is an app inside the HackSpaceLabs portal:
people sign in to HackSpaceLabs (Keycloak), and the portal shows Slipway under **Apps → Slipway**.

Stack: **FastAPI** JSON API · **PostgreSQL** (SQLAlchemy 2 async + Alembic) · **asyncssh** · Docker image.
The UI is React in the portal (`selfhost/web/slipway/`); this directory has no pages of its own.

## How it fits into HackSpaceLabs

```
browser ──▶ portal gateway (selfhost/server) ──/api/slipway/*──▶ Slipway /api/v1/*   (private compose network)
              │ session, CSRF, Slipway role check                  │ verifies the Keycloak access token itself
              └── attaches the user's Keycloak access token        └── PostgreSQL database hsl_slipway
```

- **Sign-in.** Slipway has no passwords or sessions. Each request carries the person's Keycloak access token,
  which Slipway verifies (RS256 via the realm JWKS, issuer, audience `slipway`, authorized party
  `hackspacelabs-web`, token type, expiry). Accounts are mirrored by Keycloak `sub`, never matched by email.
- **Roles** come from the `slipway` client in Keycloak (`admin`, `maintainer`, `developer`, `viewer`), assigned
  in the portal under **Identity & access → Users/Groups → Slipway roles**, and re-read on every request.
- **API tokens** (`Authorization: Bearer slipway_pat_…`, created under **Slipway → Settings → API tokens**) are for
  scripts and CI, against `https://<portal>/api/slipway/...`. On use, Slipway asks the portal gateway whether the owner
  still exists and is enabled and which Slipway roles they hold now (cached 60 seconds; refused with 503 if the gateway
  or Keycloak can't be reached), so a disabled or deleted account, or one whose roles were removed, stops working.
  Slipway itself has no Keycloak admin access.
- **GitHub** is not a way to sign in. People connect it under **Slipway → Settings** so Slipway can sync their
  repositories and deploy with their access. The OAuth app's callback is `<portal>/api/slipway/auth/github/callback`.

Installation, secrets, the GitHub OAuth app and backups are covered in the
[deployment guide](../../deployment/README.md#slipway-deployment-app); `install.sh` at the repository root sets
everything up.

## What it does

| Area | Details |
|---|---|
| Repositories | Sync from GitHub (owner, collaborator, org repos), detect `Dockerfile` / compose file, README preview, branch picker. Repositories are addressed by their GitHub id, so renames and transfers are followed and a repository re-created under an old name is never deployed |
| Hosts | Add Linux/Docker hosts; Slipway generates an ed25519 key (or use your own key / password); SSH host key pinned on first check (TOFU) and enforced afterwards; health: CPU, RAM, Docker version, containers; background polling (each host checked independently) |
| Instances | Repo + branch + host + Dockerfile *or* docker compose; encrypted env vars, port and volume mappings; deploy, start/stop/restart, live `docker ps`, container logs, destroy |
| Deployments | Source tarball fetched by Slipway and uploaded over SFTP (your GitHub token never touches the host), build output streamed live into the portal, a fresh release directory per deployment with `current` switched only after a successful build, old releases plus superseded images pruned, build logs capped at about 1 MB (start and end kept) |
| Audit | First sign-ins, Keycloak role changes, GitHub links, token/host/instance/deploy actions with actor and IP |

## Preparing a host

Any Linux machine with Docker Engine 20.10 or later + the compose plugin and SSH. Slipway runs every remote
command with `/bin/sh`, so the deploy user's login shell (bash, zsh, …) does not matter:

1. In the portal, **Slipway → Hosts → Add host**, keep *Generate a key for me*.
2. Slipway shows the public key and a ready-to-paste snippet that authorizes it, creates the deploy
   root (default `/opt/slipway`) and adds the user to the `docker` group.
3. Click **Verify connection**. Slipway records the host key fingerprint and refuses to connect if it ever
   changes (reset it from the host page only if you rebuilt the server). A server that starts offering a
   different *type* of host key is also reported as a mismatch.

Changing a host's hostname or port forgets its pinned key, so verify it again afterwards (the change is
audited). A check that was running while the address or key changed is discarded. The deploy root cannot change once any instance on the host has been deployed.

On the host each instance lives in `<deploy_root>/<slug>/` with `releases/<sha12>-<deployment>`,
`current → releases/…` and `shared/.env` (mode 600). Every deployment, even of the same commit, gets a
fresh release directory; the one `current` points to is never touched by a redeploy, and a failed
deployment removes its release again. Keep persistent data in **named volumes or absolute host paths**:
relative bind mounts like `./data` do not survive a redeploy.

Files that containers wrote as root cannot be deleted by the non-root deploy user. Slipway then removes them
through a throwaway container (`docker run --rm --network none -v <deploy_root>:/r alpine:3.20 rm -rf /r/<slug>`),
so the host pulls `alpine:3.20` the first time this is needed. Without registry access, or with userns-remap,
that fallback fails: deleting the instance still succeeds and Slipway reports (and audits) the directory left
for you to remove by hand.

**Compose instances:** Slipway builds `shared/.env` from the repository's own `.env` (next to the compose file)
followed by Slipway's values, so Slipway's values win and the repository's defaults stay. It is passed with
`--env-file` to every compose command and linked as `.env` next to the compose file. Values are quoted so
`$`, `#`, quotes and spaces arrive exactly as entered (they are not `${VAR}`-interpolated). A value that
ends in a backslash and also needs quoting requires a recent Docker Compose release. Values in the repository's `.env` that reference a variable Slipway overrides (for example
`DATABASE_URL=postgres://app:${POSTGRES_PASSWORD}@db/app`) keep the repository's value when the compose file
interpolates them with `${...}` (a service's `env_file: .env` does see Slipway's values), so set the derived
variable in Slipway too.

An instance's host and build settings (host, Dockerfile or compose, Dockerfile path, build context, compose
file) can only change before its first deployment; after that, destroy it and create a new one. Deleting an
instance, or changing these settings, is refused while a deployment is queued or running.

Dockerfile path, build context and compose file must be relative paths inside the repository that don't
start with `-`. Before uploading, Slipway checks the source archive and refuses the deployment if the build
context, the Dockerfile, the compose file or any directory on the way to them is a symbolic or hard link
(Docker would follow it out of the release directory); links elsewhere in the repository are fine. A
Dockerfile build that leaves no local image fails before the running container is replaced, and Slipway never
pulls the image it built (`docker run --pull=never`).

Branch names can be up to 255 characters and are never shortened. If a repository's GitHub default branch is
longer, Slipway skips build detection for it and asks you to choose a branch when you create an instance.

## Permissions

| Permission | admin | maintainer | developer | viewer |
|---|:-:|:-:|:-:|:-:|
| `repos:read`, `hosts:read`, `instances:read`, `deployments:read`, `analytics:read`, `logs:read` | ✓ | ✓ | ✓ | ✓ |
| `repos:sync`, `deployments:create`, `instances:operate` (start/stop/restart) | ✓ | ✓ | ✓ | |
| `hosts:write`, `instances:write`, `audit:read`, `users:read`, `roles:read` | ✓ | ✓ | | |
| `users:write` (unlink others' GitHub, revoke their API tokens), `settings:write` | ✓ | | | |

`hosts:write` and `instances:write` are privileged. Whoever holds them controls SSH credentials and
container mounts, which effectively means root on those hosts. Pinning a host key on first contact
needs `hosts:write`; later health checks only need `hosts:read`. Through Slipway, environment variable values
are only readable with `instances:write`.

**Compose instances run repository-defined containers as root.** Slipway runs the compose file from the
deployed branch as is (bind mounts, `privileged`, host namespaces and so on), ignoring the instance's port
and volume settings. So anyone who can push to that branch, together with anyone holding
`deployments:create`, effectively has root on that host and can read every other instance's `shared/.env`
there. Use one host per trust level and protect deployed branches; on hosts that run compose instances from
less-trusted branches, consider rootless Docker or userns-remap. The instance form shows this warning.

## Security notes

- SSH keys, passwords, GitHub tokens and env vars are encrypted at rest with Fernet (`SLIPWAY_ENCRYPTION_KEY`).
  Back this key up. To rotate it: set `SLIPWAY_ENCRYPTION_KEY=new,old` (new first) and restart, run
  `slipway rotate-encryption-key` (`docker compose exec slipway slipway rotate-encryption-key` from `deployment/`), which re-encrypts
  every stored secret and lists any it couldn't read, then remove the old key and restart. If a key is lost,
  secrets encrypted with it read as empty and Slipway logs the affected columns at startup; re-enter them (host
  key or password on the host page, env vars on the instance, GitHub by re-linking), or erase them with
  `slipway rotate-encryption-key --clear-unreadable`. In development the key is derived from `SLIPWAY_SECRET_KEY`,
  so changing that has the same effect.
  An instance whose environment variables can't be decrypted says so on its page and in the API
  (`env_unreadable: true`; `GET /api/v1/instances/{id}/env` answers 409), and its deployments are refused
  until the variables are re-entered or cleared ("Clear the stored variables" on the instance’s edit form, or
  `PATCH /api/v1/instances/{id}` with `{"clear_env": true}`). Saving the form without entering variables keeps
  the unreadable values, so restoring the old key still recovers them; `--clear-unreadable` keeps that
  deploy guard for instances.
- Every remote command is built with `shlex.quote` and run with `/bin/sh` with stdin closed; paths and names are
  validated against traversal and injection. Text containing NUL characters is refused (PostgreSQL can't store
  it): request bodies get a 422 and URLs with `%00` a 400. Build output lines longer than 16 KiB are cut.
- Every response carries `Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY` and `nosniff`; the
  portal gateway adds HSTS and its own page CSP. In production, SQL errors do not include bound parameter values.
  The `httpx`/`httpcore` loggers stay at WARNING even with `SLIPWAY_LOG_LEVEL=DEBUG`, because their request logs
  include short-lived GitHub download tokens.
- Slipway is reachable only on the private compose network. It records the client address the gateway forwards
  (`SLIPWAY_FORWARDED_ALLOW_IPS='*'` in `deployment/compose.yaml`); that address is used for the audit log only.

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                # includes a real in-process SSH server and a stand-in Keycloak signing key
sh scripts/dev.sh               # API on http://localhost:8000 with SQLite at data/slipway-dev.db, auto-reload
```

Requests need a Keycloak access token, so the API is easiest to exercise through the tests or behind the portal
gateway (`SLIPWAY_URL` in the gateway, `SLIPWAY_OIDC_ISSUER` here). To fill a database with demo repositories,
hosts and deployments (refuses to run in production):

```bash
SLIPWAY_ENV=development SLIPWAY_DATABASE_URL=sqlite+aiosqlite:///data/slipway-demo.db .venv/bin/python scripts/seed_demo.py
```

New migration after changing models: run `sh scripts/dev.sh` once so `data/slipway-dev.db` is at head, then
`SLIPWAY_DATABASE_URL=sqlite+aiosqlite:///$(pwd)/data/slipway-dev.db .venv/bin/alembic revision --autogenerate -m "describe change"`.
Interactive API docs: `/api/docs` (on the container, not exposed through the gateway).

## Project layout

```
slipway/
  core/        config, permissions catalogue, encryption, token hashing
  db/          engine/session, declarative base + portable column types
  models/      users (mirrored from Keycloak), roles, linked identities, tokens, hosts, repositories, instances/deployments, audit
  services/    oidc (token verification, Keycloak owner checks), identity (account sync), github, ssh, hosts, repos, deployer
  api/v1/      JSON API routers
alembic/       migrations
docker/        container entrypoint (runs migrations)
scripts/       dev server, demo-data seeder
tests/         pytest suite
```

## Roadmap

- **Analytics:** ingest API with per-app keys for Android/iOS/web SDKs, sessions, crashes, ANR, release health.
- **Logs:** structured log ingestion, search, live streaming across instances.
- **GitHub App** instead of user OAuth tokens for repo access, plus push webhooks for auto-deploy.
- **Job queue** (e.g. arq + Redis) so deployments survive restarts and run on several Slipway replicas.
  Today they run as in-process tasks, and anything in flight at restart is marked failed.
- Zero-downtime deploys (start new container, health check, then swap), rollbacks to a previous release.
- Per-project / per-host permission scoping.
