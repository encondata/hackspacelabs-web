# HackSpaceLabs self-hosted identity and website

This package makes **authentication real** and leaves **all environments, devices, tickets, notifications, and search results as sample data**. It is ready for deployment configuration and staging validation; it has not been installed on your server or connected to your DNS.

The existing ChatGPT Sites URL remains a separate, owner-private demo. It does not become the production identity provider. The self-hosted build reuses the homepage and dashboard components but uses the authentication gateway below instead of demo login controls.

## Architecture

- **Your existing reverse proxy** terminates HTTPS for the website and `auth.hackspacelabs.com`. Containers publish HTTP ports 8088 (web) and 8089 (auth) on `0.0.0.0` by default.
- **Keycloak 26.8.2** owns accounts, passwords, MFA, recovery, signing keys, OAuth/OIDC clients, and SSO. Its login/reset/MFA pages inherit maintained Keycloak templates with HackSpaceLabs branding.
- **Node 22 / Express / openid-client** serve the website and act as a backend-for-frontend. Passwords never pass through this application. OIDC authorization code + PKCE S256, state, nonce, and ID-token signature verification establish sessions.
- **PostgreSQL** contains separate identity and website-session databases with separate database roles. It does not contain customer environment or ticket records in this release.
- Application sessions use host-only Secure/HttpOnly/SameSite=Lax cookies. Refresh and ID tokens are encrypted before storage; they are never placed in browser local storage. The browser receives only a user profile and logout CSRF token.

The identity issuer is:

`https://auth.hackspacelabs.com/realms/hackspacelabs`

Discovery is:

`https://auth.hackspacelabs.com/realms/hackspacelabs/.well-known/openid-configuration`

The `/realms/hackspacelabs` suffix is part of the issuer identifier. Other applications must use this full issuer, not just the hostname.

## Deployment on an internal server or DigitalOcean droplet

Use a Linux host with Docker Engine, Docker Compose v2+, Git, Bash, and OpenSSL. Node is not needed on the host: Docker builds the application. Python 3 is only needed for the installer tests. The script does not install system packages or change your reverse proxy.

```sh
curl -fL https://raw.githubusercontent.com/encondata/hackspacelabs-web/main/install.sh -o /tmp/hackspacelabs-install.sh
bash /tmp/hackspacelabs-install.sh
```

Read the downloaded script before executing it. It asks for an installation directory (default `/mnt/user/hackspacelabs_web`), and on first installation asks for website/authentication hostnames and HTTP ports (defaults 8088 and 8089). It clones the public repository or uses `git pull --ff-only origin main` for an existing clean checkout, generates private secrets once, builds Docker images, and starts containers. No GitHub token or `gh` CLI is needed to install this public repository.

Run the installer again to update. It refuses to overwrite unrelated/nonempty directories, switch branches, discard local source changes, or replace existing `.env` secrets. `deployment/.env` is ignored by Git. Concurrent installs use a sibling `.install-lock` directory; remove that lock manually only after confirming an interrupted installer is no longer running. The installer never runs `docker compose down -v` or deletes database volumes. Back up before upgrades; database upgrades may require explicit migrations.

The install directory holds source and private configuration. PostgreSQL data lives in the Docker named volume `hackspacelabs_postgres_data`, under Docker's storage directory, not in the source checkout. Back up that volume/database separately. Only one stack with this Compose project name should run on a host.

### Reverse proxy routes

| Public HTTPS hostname | HTTP upstream on your Docker host |
| --- | --- |
| `hackspacelabs.com` (or the website hostname you enter) | `http://SERVER_IP:8088` |
| `auth.hackspacelabs.com` | `http://SERVER_IP:8089` |

These are separate hostnames at `/`, not `/web` and `/auth` subdirectories. Configure certificates and DNS at your existing proxy. When you later enable login, the application container must resolve and reach the public HTTPS auth hostname for OIDC discovery and token exchange; use split DNS or working hairpin routing if necessary. This is not an installation or startup prerequisite. Do not disable TLS verification.

For each route, **overwrite** inbound `X-Forwarded-For`, `X-Forwarded-Proto: https`, `X-Forwarded-Host`, and `X-Forwarded-Port: 443`; preserve/set `Host` to the correct public hostname. The web gateway trusts one proxy hop. Restrict access to the published backend ports to your trusted proxy/LAN; those HTTP listeners trust proxy headers and must not be exposed directly to the Internet. PostgreSQL and Keycloak management port 9000 are not published. Block public `/healthz` on the web route.

See `reverse-proxy.nginx.conf` for an example to adapt to your existing proxy. The old `Caddyfile` is a reference only and is not started by Compose.

### Startup and updates

First startup generates `deployment/.env` with mode 0600. The installer leaves SMTP unset; configure and test email in Keycloak's Admin Console after startup. Later `.env` edits do not update an already imported realm. The installer does not print credentials. Use the bootstrap account stored in that private file to provision permanent administrators and customers as described below.

Installation checks local containers only. The web process binds `0.0.0.0:3000` immediately, published as `0.0.0.0:8088` by default, and `/healthz` checks the HTTP listener without contacting DNS, TLS, the identity provider, or the database. The public homepage can be opened directly over HTTP at the server IP and web port. Keycloak listens on its published auth port independently of the public proxy. Authentication initializes on demand when first requested; failed discovery is retried on a later request, so configuring the proxy afterward needs no web restart. Login and authenticated pages still use the configured HTTPS origin and secure cookies. The installer does not run the optional `scripts/verify.mjs` external checks.

For manual operation:

```sh
cd /mnt/user/hackspacelabs_web/deployment
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 180
docker compose ps
```

Edit `BIND_ADDRESS`, `WEB_PORT`, and `AUTH_PORT` in `.env` to change published endpoints, then run Compose again. Do not change passwords or client secrets in `.env` alone after first boot; the existing database/realm also needs coordinated changes.

## First administrator and customer accounts

1. Open `https://auth.hackspacelabs.com/admin/` and use the **temporary bootstrap administrator** from the private `.env`. This is a Keycloak infrastructure account in the `master` realm, not a HackSpaceLabs website account.
2. Create a permanent, individually named Keycloak administrator, configure MFA, verify that it works, and remove the temporary bootstrap account. Remove bootstrap credentials from the running environment after bootstrap is complete. Maintain a documented recovery process.
3. Select the **hackspacelabs** realm. Confirm Realm settings → Email and test SMTP. Email verification and password-reset links cannot be delivered until SMTP is configured successfully.
4. On a **fresh realm**, the website administrator is **`admin` / `123456`** with the `hackspacelabs-web` client role `admin`. Keycloak requires a password change, profile completion (including your email), and email verification before issuing the login tokens used by the website. The replacement password must satisfy the realm policy (at least 14 characters). Configure SMTP first. This website account is separate from the randomly generated infrastructure bootstrap administrator in the `master` realm.

   For additional individual users, assign a role from client **hackspacelabs-web**:
   - `customer`: access `/portal` only.
   - `admin`: access `/admin` and `/portal`.
   No role is granted by email address, URL, browser storage, or being the first person to sign in. Accounts without an assigned application role are denied.
5. Use required-action emails to verify email and set an initial password. Do not share permanent passwords. For administrators, also require `CONFIGURE_TOTP` (or configure an appropriately enforced passkey/MFA policy) before granting operational access.
6. Visit the website `/login`, choose **Continue to sign in**, and complete the branded Keycloak flow. The gateway routes customers to `/portal` and admins to `/admin`.

**Existing installations:** startup import skips an existing realm. Updating or reinstalling the code never resets an administrator password. If the realm already exists, use its infrastructure administrator to create `admin`, assign the website `admin` client role, set `123456` as a **temporary** password, and require `UPDATE_PASSWORD`, `UPDATE_PROFILE`, and `VERIFY_EMAIL`. Do not overwrite an existing account or delete database volumes.

Public account registration is disabled. Account provisioning is administrator-controlled. Keycloak handles password reset on its login screen and account management at `/realms/hackspacelabs/account/`.

## Role checks, sessions, and logout

- `/admin` and `/portal` are authorized on the server before the HTML is served. The frontend also checks the session and hides the admin link for customers.
- The session idle timeout is 30 minutes and its absolute lifetime is 8 hours. Refresh tokens are revalidated at most every 60 seconds on authenticated requests; the open dashboard also polls the session every minute. Role removal or Keycloak session revocation takes effect at the next refresh check, not instantaneously. If the identity service cannot refresh the session, access fails closed and a new login is required.
- Logout is POST-only and requires both a same-origin request and the session CSRF token. It deletes the website session, then redirects through Keycloak's OIDC end-session endpoint to end SSO.
- The single-instance gateway coordinates concurrent refreshes in memory. Do not scale the web service to multiple replicas without revisiting refresh coordination and distributed rate limiting.
- Notifications/read state are demo/session-local UI data. Sample tickets remain in browser local storage. All signed-in customer accounts currently see the same labeled **Oak House sample environment**; there is no claim of real tenant environment isolation or device integration.

## Authentication API

| Endpoint | Behavior |
| --- | --- |
| `GET /api/auth/login` | Starts OIDC code + PKCE. Optional `returnTo` accepts only `/portal` or `/admin`. |
| `GET /api/auth/callback` | One-time state/nonce/PKCE validation, verified email and application role checks, session rotation. |
| `GET /api/auth/session` | 401 when anonymous; otherwise returns the user profile, roles, logout CSRF token, and `sampleData: true`. Never returns OAuth tokens. |
| `POST /api/auth/logout` | Requires exact Origin and `x-csrf-token`; deletes local session and returns the identity-provider logout URL. |
| `GET /api/auth/account` | Requires a session, then redirects to Keycloak account management. |
| `GET /healthz` | Container-local HTTP liveness check only; blocked at the public proxy. |

No production ticket/device API exists. `/api/*` paths outside authentication return 404. Do not build real customer integrations on top of the sample browser storage.

## “Sign in with HackSpaceLabs” for other applications

Register **one OIDC client per application**, and separate production and development clients. A starting template is `clients/web-app.example.json`. Replace its example hosts before importing it into Keycloak; it is not imported automatically.

- Use Authorization Code flow with PKCE **S256**. Disable implicit flow and password/direct-access grants.
- Register exact HTTPS callback and logout URLs; do not use broad wildcard redirects.
- Server apps use a confidential client and keep the generated secret server-side. Obtain that secret from the client's Credentials tab after creation; never put it in a SPA or mobile app.
- Browser-only/mobile/native apps require a public client with PKCE and appropriate redirect handling. They must not reuse the website's confidential client.
- Request `openid profile email` and discover endpoints/JWKS from the full issuer above. Use maintained OIDC libraries and validate issuer, audience, signature, state, nonce, and token expiry.
- Use the stable `sub` claim for identity. Create roles/scopes per application; other applications are not automatically given HackSpaceLabs administrator roles.
- Client credentials/service accounts are a separate machine-to-machine decision and are off in these templates.

## Database lifecycle, backups, and upgrades

`postgres/init.sh` creates databases and the `web_sessions` table **only on an empty PostgreSQL volume**. Changing environment passwords later does not change existing database roles. Apply explicit, coordinated migrations for existing installations; do not delete volumes to apply configuration changes.

Realm import is also first-boot setup: Keycloak skips an already existing realm. Later SMTP, client-secret, or role changes must be made through the Admin Console/API and coordinated with the gateway's environment. Do not force-import over a running identity database.

Back up the PostgreSQL cluster (including roles), the private `.env` / token-encryption key using encrypted, access-controlled backups. Keycloak's signing keys and identity records live in its database. Realm export alone is not a complete backup of accounts/sessions/events. Test restoration on an isolated staging host before relying on it. Backup output contains identity data and credentials; never commit it.

Before upgrades, take and verify backups, read Keycloak/PostgreSQL release notes, test the inherited login theme and all OIDC flows in staging, and record the exact container image digests deployed. Keycloak is pinned to 26.8.2; Node/PostgreSQL tags track their specified major versions and should be resolved to reviewed digests in your release process. Keep security patches current.

Rotating `SESSION_SECRET` signs users out. Losing or rotating `TOKEN_ENCRYPTION_KEY` makes existing encrypted session tokens unreadable and forces reauthentication; keep it in backed-up secret storage. Coordinate client-secret changes in Keycloak and the web service.

## Verification performed and remaining staging checks

Implemented automated tests cover:

- OIDC code exchange with actual HTTP discovery, JWKS, signed JWTs, and PKCE using a **test issuer**, not a real Keycloak container.
- Anonymous denial, customer/admin roles, missing roles, unverified email, wrong signatures/issuer/audience/nonce, state tampering, and callback replay.
- Session rotation, CSRF/origin checks, logout, role refresh, revoked refresh tokens, absolute expiration, safe redirect targets, and token-encryption tamper detection.
- Real temporary PostgreSQL: database initialization, persisted sessions reused by a second gateway instance, encrypted token storage, logout deletion, and restricted database privileges.
- Production frontend build and Docker Compose configuration parsing.

The local Docker engine was unavailable. **Keycloak container startup, realm import, themed login/reset/MFA pages, SMTP delivery, public DNS/HTTPS, and the complete Keycloak browser flow still require staging verification on the target server.** No DNS changes or live accounts were created. The realm template includes the explicitly requested temporary website credential `admin` / `123456`; infrastructure secrets are generated privately on installation.

Run protocol tests from the repository root:

```sh
npm ci
npm ci --prefix selfhost
npm --prefix selfhost run build
npm --prefix selfhost test
```

For the database test, use only a dedicated disposable database initialized with `postgres/init.sh`, then:

```sh
TEST_DATABASE_URL='postgresql://...' node --test selfhost/test/postgres.integration.mjs
```

Before enabling real users, verify customer login and admin denial in one browser, admin login in another, password reset and verification emails, MFA enrollment/login, logout from both the website and SSO, role removal within the refresh interval, and an outage of the identity service. Confirm that new external application clients can complete their own independent OIDC flow.

## Primary references

- [Keycloak containers](https://www.keycloak.org/server/containers)
- [Keycloak hostname configuration](https://www.keycloak.org/server/hostname)
- [Keycloak realm import and its limitations](https://www.keycloak.org/server/importExport)
- [Keycloak OpenID Connect endpoints](https://www.keycloak.org/securing-apps/oidc-layers)
- [Keycloak theme inheritance](https://www.keycloak.org/ui-customization/themes)
- [openid-client](https://github.com/panva/openid-client)
- [Keycloak reverse proxy](https://www.keycloak.org/server/reverseproxy)
