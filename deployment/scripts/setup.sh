#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
root=${1:?Expected checkout directory}
cd -- "$root/deployment"
ask_host() {
  local value
  read -r -p "$1 [$2]: " value
  value=${value:-$2}
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$value" == *.* && "$value" != *..* ]] || { echo 'Use a DNS hostname, without a scheme, port, or path.' >&2; exit 1; }
  printf '%s' "$value"
}
ask_port() {
  local value
  read -r -p "$1 [$2]: " value
  value=${value:-$2}
  [[ "$value" =~ ^[0-9]{1,5}$ ]] && (( 10#$value >= 1024 && 10#$value <= 65535 )) || { echo 'Use a port from 1024 through 65535.' >&2; exit 1; }
  printf '%s' "$((10#$value))"
}
if [[ ! -f .env ]]; then
  app_host=$(ask_host 'Website hostname' hackspacelabs.com)
  auth_host=$(ask_host 'Authentication hostname' auth.hackspacelabs.com)
  [[ "$app_host" != "$auth_host" ]] || { echo 'Web and auth require distinct hostnames.' >&2; exit 1; }
  web_port=$(ask_port 'Website HTTP port (0.0.0.0)' 8088)
  auth_port=$(ask_port 'Authentication HTTP port (0.0.0.0)' 8089)
  [[ "$web_port" != "$auth_port" ]] || { echo 'Web and auth require distinct ports.' >&2; exit 1; }
  # Infrastructure secrets are random and never printed; the realm imports the requested temporary website admin.
  temporary=$(mktemp .env.new.XXXXXX)
  trap 'rm -f -- "$temporary"' EXIT
  {
    printf 'APP_HOST=%s\nAUTH_HOST=%s\nBIND_ADDRESS=0.0.0.0\nWEB_PORT=%s\nAUTH_PORT=%s\n' "$app_host" "$auth_host" "$web_port" "$auth_port"
    for key in POSTGRES_PASSWORD KEYCLOAK_DB_PASSWORD APP_DB_PASSWORD KEYCLOAK_BOOTSTRAP_PASSWORD OIDC_CLIENT_SECRET SESSION_SECRET; do
      printf '%s=%s\n' "$key" "$(openssl rand -hex 48)"
    done
    printf 'TOKEN_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32)"
    printf 'KEYCLOAK_BOOTSTRAP_ADMIN=bootstrap-admin\nSMTP_HOST=\nSMTP_PORT=587\nSMTP_FROM=accounts@hackspacelabs.com\nSMTP_USER=\nSMTP_PASSWORD=\nSMTP_AUTH=true\nSMTP_STARTTLS=true\nSMTP_SSL=false\n'
  } > "$temporary"
  # Atomic create, refusing to replace an env file created concurrently.
  ln "$temporary" .env
  rm -- "$temporary"
  trap - EXIT
  echo "Generated private secrets in $root/deployment/.env"
else
  echo 'Keeping existing deployment/.env and persistent volumes.'
fi
chmod 600 .env
# Never source .env as executable shell code or print rendered secret configuration.
docker compose config --quiet
echo 'Building images. Your HTTPS reverse proxy must route both hostnames before the web service can become healthy.'
if ! docker compose up -d --build --wait --wait-timeout 180; then
  echo 'Startup did not become healthy. Containers/data are retained; this is not a successful installation.' >&2
  echo 'Check docker compose ps and logs locally. Confirm DNS, HTTPS certificates, and both proxy routes; then rerun install.sh.' >&2
  exit 1
fi
docker compose ps
echo "Services are running. Configure SMTP in Keycloak, then sign in to the website as admin / 123456 and change the temporary password."
echo "Bootstrap credentials are stored privately in $root/deployment/.env; they are not displayed."
echo 'See deployment/README.md for proxy headers, account setup, backups, and staging checks.'
