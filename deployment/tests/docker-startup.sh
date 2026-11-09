#!/usr/bin/env bash
# CI regression: exercise the built image with no network, DNS, TLS, or database.
set -Eeuo pipefail
container="hsl-startup-test-$$"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
docker run -d --network none --name "$container" \
  -e NODE_ENV=production -e PORT=3000 \
  -e APP_ORIGIN=https://web.not-configured.invalid \
  -e OIDC_ISSUER=https://auth.not-configured.invalid/realms/hackspacelabs \
  -e DATABASE_URL=postgres://unavailable:unavailable@127.0.0.1:1/unavailable \
  -e SESSION_SECRET="$(openssl rand -hex 48)" \
  -e OIDC_CLIENT_SECRET="$(openssl rand -hex 32)" \
  -e TOKEN_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  hackspacelabs-web:ci >/dev/null
for attempt in {1..20}; do
  if docker exec "$container" node --input-type=module -e '
    const health=await fetch("http://127.0.0.1:3000/healthz");
    if(!health.ok)process.exit(1);
  ' >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$container" node --input-type=module -e '
  const origin="http://127.0.0.1:3000";
  const response=await fetch(origin);
  if(!response.ok)throw new Error("Homepage failed: "+response.status);
  if(response.headers.get("content-security-policy").includes("upgrade-insecure-requests"))throw new Error("HTTP assets would be upgraded to HTTPS");
  const html=await response.text();
  const assets=[...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)].map(match=>match[1]);
  if(!assets.some(asset=>asset.endsWith(".js")))throw new Error("Missing frontend bundle");
  for(const asset of assets){if(!(await fetch(origin+asset)).ok)throw new Error("Missing asset: "+asset)}
  console.log("Built image serves homepage and assets without network/DNS/TLS/database.");
'
docker logs "$container" 2>&1 | grep -F 'listening on 0.0.0.0:3000'
