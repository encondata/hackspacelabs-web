# HackSpaceLabs web and identity

Company homepage, sample customer portal and administration dashboard, with real self-hosted authentication through Keycloak, PostgreSQL, and an Express OIDC gateway. Authentication uses authorization code + PKCE; customer environments, devices, tickets, search, and notifications remain **sample data**.

## Install or update

Requires Linux, Bash, Git, OpenSSL, Docker Engine, and Docker Compose v2+. Your existing reverse proxy provides HTTPS.

```sh
curl -fL https://raw.githubusercontent.com/encondata/hackspacelabs-web/main/install.sh -o /tmp/hackspacelabs-install.sh
bash /tmp/hackspacelabs-install.sh
```

Inspect the script before running it. It prompts for the install directory (default **`/mnt/user/hackspacelabs_web`**). First install also asks for public hostnames and ports. Subsequent runs pull `main`, preserve secrets/data, rebuild images, and restart the services.

| Service | Default listener | Public proxy hostname |
| --- | --- | --- |
| Website | `0.0.0.0:8088` | `hackspacelabs.com` |
| Keycloak | `0.0.0.0:8089` | `auth.hackspacelabs.com` |

Route each hostname at `/` to its upstream port. The web service needs to reach the public auth URL before it can become healthy. Keep backend ports reachable only by your trusted proxy/LAN. All user traffic uses HTTPS through your proxy. No GitHub credentials are required for installation.

Existing installations are not reset by updates: realm import only seeds an empty realm.

**[Full deployment guide](deployment/README.md)** covers proxy headers, bootstrap accounts, SMTP, customer/admin roles, future OAuth clients, backups, and upgrades. See [Nginx example](deployment/reverse-proxy.nginx.conf).

## Status

The authentication protocol and PostgreSQL session tests passed during development, and the production frontend builds. Docker Compose configuration is validated. Full Keycloak container startup, email delivery, and end-to-end production login still require staging verification; the development machine's Docker engine was unavailable. Fresh installations seed the website account **`admin` / `123456`** with a mandatory password change. Complete the profile and email verification before portal access; configure SMTP first. Infrastructure credentials remain randomly generated.

## Development checks

```sh
npm ci
npm ci --prefix selfhost
npm run build
npm test
python3 deployment/tests/test_installer.py
```

Authentication tests use a local signed test issuer. They do not substitute for Keycloak staging tests. Real PostgreSQL integration tests and their dedicated test-database requirements are documented in the deployment guide.
