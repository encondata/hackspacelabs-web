#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
root=${1:?Expected checkout directory}
access_mode=${2:-keep}
lan_ip=${3:-}
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
    printf 'KEYCLOAK_BOOTSTRAP_ADMIN=bootstrap-admin\n'
  } > "$temporary"
  # Atomic create, refusing to replace an env file created concurrently.
  ln "$temporary" .env
  rm -- "$temporary"
  trap - EXIT
  echo "Generated private secrets in $root/deployment/.env"
else
  echo 'Keeping existing deployment/.env and persistent volumes.'
fi
# Change only endpoint settings; keep credentials and database volumes intact.
set_setting() {
  local temporary
  temporary=$(mktemp .env.new.XXXXXX)
  awk -v key="$1" -v value="$2" 'BEGIN{done=0} index($0,key "=")==1 {if(!done)print key "=" value;done=1;next} {print} END{if(!done)print key "=" value}' .env > "$temporary"
  chmod 600 "$temporary"
  mv -- "$temporary" .env
}
get_setting() { awk -F= -v key="$1" '$1==key {value=substr($0,length(key)+2)} END{print value}' .env; }
# Secrets added by later releases are generated once for existing installations, never replaced or printed.
ensure_secret() { [[ -n "$(get_setting "$1")" ]] || set_setting "$1" "$2"; }
ensure_secret SLIPWAY_DB_PASSWORD "$(openssl rand -hex 48)"
ensure_secret SLIPWAY_SECRET_KEY "$(openssl rand -hex 48)"
ensure_secret SLIPWAY_INTERNAL_SECRET "$(openssl rand -hex 48)"
# Fernet key: urlsafe base64 of 32 random bytes.
ensure_secret SLIPWAY_ENCRYPTION_KEY "$(openssl rand -base64 32 | tr '+/' '-_')"
if [[ "$access_mode" == lan ]]; then
  if [[ ! "$lan_ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then echo 'LAN mode requires a private IPv4 address.' >&2; exit 1; fi
  a=$((10#${BASH_REMATCH[1]})); b=$((10#${BASH_REMATCH[2]})); c=$((10#${BASH_REMATCH[3]})); d=$((10#${BASH_REMATCH[4]}))
  if ! ((a<=255 && b<=255 && c<=255 && d<=255 && (a==10 || (a==192 && b==168) || (a==172 && b>=16 && b<=31)))); then echo 'LAN mode only accepts RFC1918 private IPv4 addresses.' >&2; exit 1; fi
  lan_ip="$a.$b.$c.$d"
  web_port=$(get_setting WEB_PORT); web_port=${web_port:-8088}
  auth_port=$(get_setting AUTH_PORT); auth_port=${auth_port:-8089}
  set_setting AUTH_MODE lan
  set_setting APP_ORIGIN "http://$lan_ip:$web_port"
  set_setting AUTH_ORIGIN "http://$lan_ip:$auth_port"
  echo "LAN HTTP login enabled for $lan_ip. Use only on your trusted private network."
elif [[ "$access_mode" == https ]]; then
  app_host=$(get_setting APP_HOST); auth_host=$(get_setting AUTH_HOST)
  set_setting AUTH_MODE https
  set_setting APP_ORIGIN "https://${app_host:-hackspacelabs.com}"
  set_setting AUTH_ORIGIN "https://${auth_host:-auth.hackspacelabs.com}"
fi
chmod 600 .env
# Never source .env as executable shell code or print rendered secret configuration.
docker compose config --quiet
echo 'Building images and starting local listeners. DNS, certificates, and proxy routes are not checked.'
# Provision application databases (idempotent) before the services that need them start.
if ! { docker compose up -d --wait --wait-timeout 120 postgres &&
       docker compose exec -T postgres sh /docker-entrypoint-initdb.d/02-slipway.sh >/dev/null &&
       BUILDX_GIT_INFO=false docker compose up -d --build --wait --wait-timeout 180; }; then
  echo 'Startup did not become healthy. Containers/data are retained; this is not a successful installation.' >&2
  echo 'Check docker compose ps and logs for local container, port, or database errors; then rerun install.sh.' >&2
  exit 1
fi
docker compose --profile tools run --rm --no-deps -T configure-auth
docker compose ps
echo "Local services are running. Sign in with your username and password. No email setup is required."
echo "Bootstrap credentials are stored privately in $root/deployment/.env; they are not displayed."
echo 'See deployment/README.md for proxy headers, account setup, backups, and staging checks.'
