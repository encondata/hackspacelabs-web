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
| Accounts | Email/password (Argon2), GitHub OAuth sign-in, link/unlink GitHub, server-side sessions, CSRF protection, login and sign-up rate limiting, personal API tokens (`Authorization: Bearer kiln_pat_…`) that admins can list and revoke |
| Permissions | Role-based: built-in `admin`, `maintainer`, `developer`, `viewer` + custom roles; users can hold several roles; no privilege escalation (you can only grant, remove or manage what you hold: `users:write` only reaches users whose every permission you also have); last-admin protection; the UI only shows what your roles allow |
| Repositories | Sync from GitHub (owner, collaborator, org repos), detect `Dockerfile` / compose file, README preview, branch picker. Repositories are addressed by their GitHub id, so renames and transfers are followed and a repository re-created under an old name is never deployed |
| Hosts | Add Linux/Docker hosts; Kiln generates an ed25519 key (or use your own key / password); SSH host key pinned on first check (TOFU) and enforced afterwards; health: CPU, RAM, Docker version, containers; background polling (each host checked independently) |
| Instances | Repo + branch + host + Dockerfile *or* docker compose; encrypted env vars, port and volume mappings; deploy, start/stop/restart, live `docker ps`, container logs, destroy |
| Deployments | Source tarball fetched by Kiln and uploaded over SFTP (your GitHub token never touches the host), build output streamed live into the UI, a fresh release directory per deployment with `current` switched only after a successful build, old releases plus superseded images pruned, build logs capped at about 1 MB (start and end kept) |
| Audit | Sign-ins, failed logins and password checks, user/role/token/host/instance/deploy actions with actor and IP |
| UI | Light and dark themes from your mockups and asset pack, responsive down to phone width |

## Quick start (Docker)

```bash
cp .env.example .env
docker compose run --rm --no-deps -e KILN_SKIP_MIGRATIONS=1 kiln kiln generate-secrets   # paste all three values into .env
# edit .env: KILN_BASE_URL, KILN_ADMIN_EMAIL/PASSWORD, GitHub OAuth app
docker compose up -d --build
```

Open `KILN_BASE_URL` and sign in. Migrations run automatically on container start.
`POSTGRES_PASSWORD` may contain any character: compose passes it to Kiln as `KILN_DATABASE_PASSWORD`
instead of putting it in the URL. (Changing it after the database volume exists does not change the
Postgres user's password.) Outside compose, set `KILN_DATABASE_URL` and `KILN_DATABASE_PASSWORD`;
a password written into the URL itself takes precedence.

Put Kiln behind a TLS reverse proxy (Caddy, Traefik, nginx) for anything beyond your LAN:
with an `https://` base URL, cookies become `Secure` and HSTS is sent. Then set
`KILN_FORWARDED_ALLOW_IPS` to the proxy's address or subnet as Kiln sees it (for a proxy on the Docker
host, the compose network gateway such as `172.18.0.1`, or a CIDR such as `172.16.0.0/12`). Kiln then
takes the client IP from `X-Forwarded-For` for rate limiting and the audit log. Keep the default
(`127.0.0.1`) behind a proxy and every client shares the proxy's IP, so anyone's failed logins slow
everyone down. Never use `*`: any client could then forge its IP. If the proxy runs on the same machine,
publish Kiln on loopback only (`"127.0.0.1:${KILN_PORT:-8000}:8000"` in docker-compose.yml).

**First admin:** whichever comes first becomes admin:
- `KILN_ADMIN_EMAIL`/`KILN_ADMIN_PASSWORD` on an empty database. The password must be at least 10
  characters; if it is too short Kiln logs an error at startup and does not create the admin.
- `docker compose exec kiln kiln create-admin you@example.com` (see below).
- The first person to sign in with GitHub. When `KILN_GITHUB_ALLOWED_USERS` or `KILN_GITHUB_ALLOWED_ORGS`
  is set, only an allow-listed GitHub account can claim this. With neither set, anyone who reaches Kiln
  first can, so on an internet-facing install set an allowlist or use one of the options above.

`kiln create-admin EMAIL` creates a new admin and asks for a password. For an existing account it only
grants the admin role and never changes the password; it prints the account's details (check any linked
GitHub login before promoting an account you didn't create). Add `--reset-password` to set a new password,
which also signs out the account's sessions and deletes its API tokens, and `--activate` to re-enable a
deactivated account. To script it, pipe the password on stdin:
`printf '%s\n' "$PW" | docker compose exec -T kiln kiln create-admin you@example.com`.

### GitHub OAuth app

1. GitHub → Settings → Developer settings → **OAuth Apps** → New.
2. Homepage URL = `KILN_BASE_URL`; callback URL = `KILN_BASE_URL/auth/github/callback`.
3. Put the client ID and secret in `KILN_GITHUB_CLIENT_ID` / `KILN_GITHUB_CLIENT_SECRET`.
4. Decide who may create an account by signing in with GitHub: `KILN_GITHUB_ALLOWED_USERS=alice,id:583231`
   and/or `KILN_GITHUB_ALLOWED_ORGS=my-org,id:9919` (the orgs setting adds the `read:org` scope). An entry is a
   login/org name or an immutable numeric id written as `id:<number>`. Prefer ids: after a rename or deletion
   anyone can register the old name. Find the `id` at `https://api.github.com/users/<login>` or
   `https://api.github.com/orgs/<org>`. Admins can also add a user with their GitHub username in
   **Settings → Users**, which pins their numeric id.

Kiln never links GitHub to an existing account by matching email. Users link GitHub themselves
from **Settings → Profile** after signing in.

### Preparing a host

Any Linux machine with Docker Engine + the compose plugin and SSH:

1. **Hosts → Add Host**, keep *Generate key*.
2. Kiln shows the public key and a ready-to-paste snippet that authorizes it, creates the deploy
   root (default `/opt/kiln`) and adds the user to the `docker` group.
3. Click **Verify connection**. Kiln records the host key fingerprint and refuses to connect if it ever
   changes (reset it from the host page only if you rebuilt the server). A server that starts offering a
   different *type* of host key is also reported as a mismatch.

Changing a host's hostname or port forgets its pinned key, so verify it again afterwards (the change is
audited). The deploy root cannot change once any instance on the host has been deployed.

On the host each instance lives in `<deploy_root>/<slug>/` with `releases/<sha12>-<deployment>`,
`current → releases/…` and `shared/.env` (mode 600). Every deployment, even of the same commit, gets a
fresh release directory; the one `current` points to is never touched by a redeploy, and a failed
deployment removes its release again. Keep persistent data in **named volumes or absolute host paths**:
relative bind mounts like `./data` do not survive a redeploy.

Files that containers wrote as root cannot be deleted by the non-root deploy user. Kiln then removes them
through a throwaway container (`docker run --rm --network none -v <deploy_root>:/r alpine:3.20 rm -rf /r/<slug>`),
so the host pulls `alpine:3.20` the first time this is needed. Without registry access, or with userns-remap,
that fallback fails: deleting the instance still succeeds and Kiln reports (and audits) the directory left
for you to remove by hand.

**Compose instances:** Kiln builds `shared/.env` from the repository's own `.env` (next to the compose file)
followed by Kiln's values, so Kiln's values win and the repository's defaults stay. It is passed with
`--env-file` to every compose command and linked as `.env` next to the compose file. Values are quoted so
`$`, `#`, quotes and spaces arrive exactly as entered (they are not `${VAR}`-interpolated). A value that
ends in a backslash and also needs quoting requires a recent Docker Compose release.

An instance's host and build settings (host, Dockerfile or compose, Dockerfile path, build context, compose
file) can only change before its first deployment; after that, destroy it and create a new one. Deleting an
instance, or changing these settings, is refused while a deployment is queued or running.

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"   # re-run after pulling (adds bcrypt for passphrase keys)
cp .env.example .env            # set KILN_ENV=development and an admin email/password
sh scripts/dev.sh               # SQLite at data/kiln-dev.db, auto-reload, http://localhost:8000
.venv/bin/pytest                # includes a real in-process SSH server
```

`scripts/dev.sh` uses SQLite unless `.env` sets `KILN_DATABASE_URL`, so no Postgres is needed to hack on
the UI. To work on screens with realistic content, seed a separate demo database (refuses to run in
production; it needs an admin first, from `KILN_ADMIN_EMAIL`/`KILN_ADMIN_PASSWORD` or `kiln create-admin`;
demo team members have no password and can't sign in):

```bash
KILN_ENV=development KILN_DATABASE_URL=sqlite+aiosqlite:///data/kiln-demo.db .venv/bin/python scripts/seed_demo.py
PORT=8001 KILN_DATABASE_URL=sqlite+aiosqlite:///data/kiln-demo.db sh scripts/dev.sh
```

New migration after changing models: run `sh scripts/dev.sh` once so `data/kiln-dev.db` is at head, then
`KILN_DATABASE_URL=sqlite+aiosqlite:///$(pwd)/data/kiln-dev.db .venv/bin/alembic revision --autogenerate -m "describe change"`
(leave the variable off if `.env` points `KILN_DATABASE_URL` at your own database).
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
needs `hosts:write`; later health checks only need `hosts:read`. Through Kiln, environment variable values
are only readable with `instances:write`.

**Compose instances run repository-defined containers as root.** Kiln runs the compose file from the
deployed branch as is (bind mounts, `privileged`, host namespaces and so on), ignoring the instance's port
and volume settings. So anyone who can push to that branch, together with anyone holding
`deployments:create`, effectively has root on that host and can read every other instance's `shared/.env`
there. Use one host per trust level and protect deployed branches; on hosts that run compose instances from
less-trusted branches, consider rootless Docker or userns-remap. The instance form shows this warning.

The role editor shows every permission a role holds, including `*`, `resource:*` wildcards and permissions
Kiln no longer knows; saving without touching the boxes keeps them. Uncheck an unknown permission before
changing a role's other permissions.

## Security notes

- SSH keys, passwords, GitHub tokens and env vars are encrypted at rest with Fernet (`KILN_ENCRYPTION_KEY`).
  Back this key up. To rotate it: set `KILN_ENCRYPTION_KEY=new,old` (new first) and restart, run
  `kiln rotate-encryption-key` (`docker compose exec kiln kiln rotate-encryption-key`), which re-encrypts
  every stored secret and lists any it couldn't read, then remove the old key and restart. If a key is lost,
  secrets encrypted with it read as empty and Kiln logs the affected columns at startup; re-enter them (host
  key or password on the host page, env vars on the instance, GitHub by re-linking), or erase them with
  `kiln rotate-encryption-key --clear-unreadable`. In development the key is derived from `KILN_SECRET_KEY`,
  so changing that has the same effect.
- Sessions are opaque random tokens (only a SHA-256 hash is stored) in an `HttpOnly`, `SameSite=Lax` cookie;
  cookie-authenticated writes must echo a per-session CSRF token. API tokens skip CSRF but cannot mint tokens,
  change the password or unlink GitHub. Setting a first password on a GitHub-only account also needs a sign-in
  from the last 15 minutes.
- An admin password reset or deactivation signs the user out everywhere and deletes their API tokens.
  Changing your own password (Settings → Profile; `PATCH /api/v1/users/{your id}` refuses a password) signs
  out your other sessions but keeps your API tokens; revoke them under Settings → Tokens. Admins can list and
  revoke another user's tokens with `GET /api/v1/users/{id}/tokens` and `DELETE /api/v1/users/{id}/tokens/{token_id}`.
- Rate limits are in-process (single node) and count failures only. Password login: 10 per 5 minutes per
  client + email (IPv6 grouped by /48), 30 per 5 minutes per client IP (IPv6 /64), and 50 per 15 minutes per
  email across all clients. Attempts are counted before the password is checked, so parallel bursts are
  limited too. The per-email cap limits distributed guessing to about 4,800 guesses per account per day, but
  it is a hard block: failures kept up from two or more addresses keep that account's password login at 429,
  for the owner too, until 15 minutes after they stop (GitHub sign-in is unaffected). Self-registration is
  limited to 10 attempts per IP per hour; wrong current passwords on the password form to 5 per session and
  25 per user per 15 minutes (audited as `auth.password_change_failed`).
- With `KILN_ALLOW_SIGNUP=true`, `/api/v1/auth/register` reveals whether an email already has an account
  (rate limited per IP); Kiln has no email verification yet.
- Every remote command is built with `shlex.quote`, and paths and names are validated against traversal and injection.
- Strict CSP (`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, HSTS when served over HTTPS.
  In production, SQL errors do not include bound parameter values. The `httpx`/`httpcore` loggers stay at
  WARNING even with `KILN_LOG_LEVEL=DEBUG`, because their request logs include short-lived GitHub download tokens.

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
  Today they run as in-process tasks, and anything in flight at restart is marked failed. Rate limits are
  also per process and would move to Redis.
- Zero-downtime deploys (start new container, health check, then swap), rollbacks to a previous release.
- Per-project / per-host permission scoping, teams, SSO (OIDC), and email verification for open sign-up.
