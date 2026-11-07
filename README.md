# Kiln

**Deploy. Run. Observe.** Kiln lists your GitHub repositories and deploys any of them as Docker
containers on your own Linux hosts over SSH, with user accounts, roles and an audit trail.
Mobile/web analytics and centralized logging are scaffolded for the next phase.

Stack: **FastAPI** · **PostgreSQL** (SQLAlchemy 2 async + Alembic) · server-rendered Jinja UI with
vanilla JS (no Node build) · **asyncssh** · shipped as a **Docker** image.

---

## What works today

| Area | Details |
|---|---|
| Accounts | Email/password (Argon2), GitHub OAuth sign-in, link/unlink GitHub, server-side sessions, CSRF protection, login rate limiting, personal API tokens (`Authorization: Bearer kiln_pat_…`) |
| Permissions | Role-based: built-in `admin`, `maintainer`, `developer`, `viewer` + custom roles; users can hold several roles; no privilege escalation (you can only grant what you hold); last-admin protection |
| Repositories | Sync from GitHub (owner, collaborator, org repos), detect `Dockerfile` / compose file, README preview, branch picker |
| Hosts | Add Linux/Docker hosts; Kiln generates an ed25519 key (or use your own key / password); SSH host key pinned on first check (TOFU) and enforced afterwards; health: CPU, RAM, Docker version, containers; background polling |
| Instances | Repo + branch + host + Dockerfile *or* docker compose; encrypted env vars, port and volume mappings; deploy, start/stop/restart, live `docker ps`, container logs, destroy |
| Deployments | Source tarball fetched by Kiln and uploaded over SFTP (your GitHub token never touches the host), build output streamed live into the UI, release directories with `current` symlink, old releases and images pruned |
| Audit | Sign-ins, failed logins, user/role/host/instance/deploy actions with actor and IP |
| UI | Light and dark themes from your mockups and asset pack, responsive down to phone width |

## Quick start (Docker)

```bash
cp .env.example .env
docker compose run --rm --no-deps -e KILN_SKIP_MIGRATIONS=1 kiln kiln generate-secrets   # paste both values into .env
# edit .env: KILN_BASE_URL, POSTGRES_PASSWORD, KILN_ADMIN_EMAIL/PASSWORD, GitHub OAuth app
docker compose up -d --build
```

Open `KILN_BASE_URL` and sign in. Migrations run automatically on container start.
Put Kiln behind a TLS reverse proxy (Caddy, Traefik, nginx) for anything beyond your LAN:
with an `https://` base URL, cookies become `Secure` and HSTS is sent.

**First admin:** whichever comes first becomes admin: `KILN_ADMIN_EMAIL`/`KILN_ADMIN_PASSWORD` on an empty
database, `docker compose exec kiln kiln create-admin you@example.com`, or the first person to sign in with GitHub.

### GitHub OAuth app

1. GitHub → Settings → Developer settings → **OAuth Apps** → New.
2. Homepage URL = `KILN_BASE_URL`; callback URL = `KILN_BASE_URL/auth/github/callback`.
3. Put the client ID and secret in `KILN_GITHUB_CLIENT_ID` / `KILN_GITHUB_CLIENT_SECRET`.
4. Decide who may create an account by signing in with GitHub: `KILN_GITHUB_ALLOWED_USERS=alice,bob`
   and/or `KILN_GITHUB_ALLOWED_ORGS=my-org` (adds the `read:org` scope). Admins can also add a user
   with their GitHub username in **Settings → Users**.

Kiln never links GitHub to an existing account by matching email. Users link GitHub themselves
from **Settings → Profile** after signing in.

### Preparing a host

Any Linux machine with Docker Engine + the compose plugin and SSH:

1. **Hosts → Add Host**, keep *Generate key*.
2. Kiln shows the public key and a ready-to-paste snippet that authorizes it, creates the deploy
   root (default `/opt/kiln`) and adds the user to the `docker` group.
3. Click **Verify connection**. Kiln records the host key fingerprint and refuses to connect if it ever
   changes (reset it from the host page only if you rebuilt the server).

On the host each instance lives in `<deploy_root>/<slug>/` with `releases/<sha>`, `current → releases/<sha>`
and `shared/.env` (mode 600). Keep persistent data in **named volumes or absolute host paths**:
each deploy gets a fresh release directory, so relative bind mounts like `./data` do not survive a redeploy.

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp .env.example .env            # set KILN_ENV=development and an admin email/password
sh scripts/dev.sh               # SQLite at data/kiln-dev.db, auto-reload, http://localhost:8000
.venv/bin/pytest                # 52 tests, includes a real in-process SSH server
```

`scripts/dev.sh` uses SQLite unless `.env` sets `KILN_DATABASE_URL`, so no Postgres is needed to hack on
the UI. To work on screens with realistic content, seed a separate demo database (refuses to run in production):

```bash
KILN_ENV=development KILN_DATABASE_URL=sqlite+aiosqlite:///data/kiln-demo.db .venv/bin/python scripts/seed_demo.py
PORT=8001 KILN_DATABASE_URL=sqlite+aiosqlite:///data/kiln-demo.db sh scripts/dev.sh
```

New migration after changing models: `.venv/bin/alembic revision --autogenerate -m "describe change"`.
Interactive API docs: `/api/docs`.

## Permissions

| Permission | admin | maintainer | developer | viewer |
|---|:-:|:-:|:-:|:-:|
| `repos:read`, `hosts:read`, `instances:read`, `deployments:read`, `analytics:read`, `logs:read` | ✓ | ✓ | ✓ | ✓ |
| `repos:sync`, `deployments:create`, `instances:operate` (start/stop/restart) | ✓ | ✓ | ✓ | |
| `hosts:write`, `instances:write`, `audit:read`, `users:read`, `roles:read` | ✓ | ✓ | | |
| `users:write`, `roles:write`, `settings:write` | ✓ | | | |

`hosts:write` and `instances:write` are privileged. Whoever holds them controls SSH credentials and
container mounts, which effectively means root on those hosts. Pinning a host key on first contact
needs `hosts:write`; later health checks only need `hosts:read`. Environment variable values are only
readable with `instances:write`.

## Security notes

- SSH keys, passwords, GitHub tokens and env vars are encrypted at rest with Fernet (`KILN_ENCRYPTION_KEY`;
  comma-separate keys to rotate). Back this key up: without it those secrets must be re-entered.
- Sessions are opaque random tokens (only a SHA-256 hash is stored) in an `HttpOnly`, `SameSite=Lax` cookie;
  cookie-authenticated writes must echo a per-session CSRF token. API tokens skip CSRF but cannot mint tokens.
- Every remote command is built with `shlex.quote`, and paths and names are validated against traversal and injection.
- Strict CSP (`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, HSTS when served over HTTPS.

## Project layout

```
kiln/
  core/        config, permissions catalogue, encryption, password/token hashing, rate limiting
  db/          engine/session, declarative base + portable column types
  models/      users/roles/sessions/tokens, hosts, repositories, instances/deployments, audit
  services/    auth, users, github, ssh, hosts (health), repos (sync), deployer (pipeline + runner)
  api/v1/      JSON API routers
  web/         page routes, GitHub OAuth flow, Jinja templates, static CSS/JS/icons
alembic/       migrations
docker/        container entrypoint (runs migrations)
scripts/       dev server, demo-data seeder
tests/         pytest suite
```

## Roadmap

- **Analytics:** ingest API with per-app keys for Android/iOS/web SDKs, sessions, crashes, ANR, release health.
- **Logs:** structured log ingestion, search, live streaming across instances.
- **GitHub App** instead of user OAuth tokens for repo access, plus push webhooks for auto-deploy.
- **Job queue** (e.g. arq + Redis) so deployments survive restarts and run on several Kiln replicas.
  Today they run as in-process tasks, and anything in flight at restart is marked failed.
- Zero-downtime deploys (start new container, health check, then swap), rollbacks to a previous release.
- Per-project / per-host permission scoping, teams, and SSO (OIDC).
