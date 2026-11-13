#!/usr/bin/env bash
# Disposable CI deployment: verify upgrading an existing HTTPS realm to LAN URLs.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[[ ! -e .env ]] || { echo 'Use only an isolated checkout without deployment/.env.' >&2; exit 1; }
node scripts/init-env.mjs
cleanup() { result=$?; if ((result!=0)); then docker compose -p hsl-ci-lan logs --tail=80 keycloak postgres web; fi; docker compose -p hsl-ci-lan --profile tools down -v >/dev/null 2>&1 || true; rm -f .env; }
trap cleanup EXIT
docker tag hackspacelabs-web:ci hsl-ci-lan-web
docker tag hackspacelabs-web:ci hackspacelabs-web
docker tag hackspacelabs-auth:ci hsl-ci-lan-keycloak
printf '\nHARBORMASTER_ORIGIN=https://harbormaster.not-configured.invalid\n' >> .env
docker compose -p hsl-ci-lan up -d --no-build --wait --wait-timeout 180
# Complete the original realm startup before changing the endpoints.
docker compose -p hsl-ci-lan --profile tools run --rm --no-deps -T configure-auth
docker compose -p hsl-ci-lan --profile tools run --rm --no-deps -T -v "$(pwd)/tests:/tests:ro" --entrypoint node configure-auth /tests/email-policy.mjs seed
lan_ip=$(hostname -I | awk '{print $1}')
printf '\nAUTH_MODE=lan\nAPP_ORIGIN=http://%s:8088\nAUTH_ORIGIN=http://%s:8089\n' "$lan_ip" "$lan_ip" >> .env
docker compose -p hsl-ci-lan up -d --no-build --wait --wait-timeout 180
docker compose -p hsl-ci-lan --profile tools run --rm --no-deps -T configure-auth
docker compose -p hsl-ci-lan --profile tools run --rm --no-deps -T -v "$(pwd)/tests:/tests:ro" --entrypoint node configure-auth /tests/email-policy.mjs verify
headers=$(mktemp)
status=$(curl --noproxy '*' --retry 4 --retry-all-errors --max-time 20 -sS -D "$headers" -o /dev/null -w '%{http_code}' "http://$lan_ip:8088/api/auth/login")
[[ "$status" == 303 ]] || { echo "LAN login failed: HTTP $status"; docker compose -p hsl-ci-lan logs --tail=20 web; exit 1; }
grep -qi "location: http://$lan_ip:8089/realms/hackspacelabs/protocol/openid-connect/auth" "$headers"
grep -qi 'set-cookie: hsl.lan.sid=' "$headers"
rm -f "$headers"
echo 'Existing Keycloak realm migrated and real LAN OIDC login redirected successfully.'

docker compose -p hsl-ci-lan exec -T web node --input-type=module < tests/profile-store.mjs
