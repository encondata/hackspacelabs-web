"""Keycloak (HackSpaceLabs realm) integration.

* ``verify_access_token``: the portal gateway forwards the signed-in user's access token on every request.
  Slipway trusts nothing about the caller until it has checked the token itself: RS256 signature against the
  realm's JWKS, issuer, audience (``slipway``), authorized party (the gateway's client), expiry and token type.
* ``owners``: API tokens (``slipway_pat_...``) are long-lived, so on use Slipway asks the portal gateway (which holds
  Keycloak's management account) whether the owner still exists and is enabled, and what Slipway roles they hold now.
  A disabled or deleted account, or one whose roles were removed, stops working within the cache window.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
import jwt

from slipway.core.config import get_settings
from slipway.core.permissions import SYSTEM_ROLES

log = logging.getLogger(__name__)

ALGORITHMS = ["RS256"]
LEEWAY_SECONDS = 30
_JWKS_TTL = 600.0
# An unknown key id triggers at most one JWKS refetch per this many seconds (keys rotate rarely).
_JWKS_MIN_REFETCH = 30.0


class TokenError(Exception):
    """The bearer token is not a valid access token for Slipway (reported as 401)."""


class IdentityUnavailable(Exception):
    """Keycloak could not be reached to verify the caller (reported as 503; never treated as success)."""


Fetch = Callable[[], Awaitable[dict[str, Any]]]


async def _fetch_jwks() -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(get_settings().jwks_url)
        response.raise_for_status()
        return response.json()


class JwksCache:
    def __init__(self, fetch: Fetch | None = None) -> None:
        self.fetch: Fetch = fetch or _fetch_jwks
        self._keys: dict[str, Any] = {}
        self._loaded_at = float("-inf")
        self._lock = asyncio.Lock()

    def clear(self) -> None:
        self._keys = {}
        self._loaded_at = float("-inf")

    async def _load(self) -> None:
        data = await self.fetch()
        keys: dict[str, Any] = {}
        for entry in data.get("keys", []) if isinstance(data, dict) else []:
            if not isinstance(entry, dict) or entry.get("use", "sig") != "sig" or entry.get("kty") != "RSA":
                continue
            kid = entry.get("kid")
            if not isinstance(kid, str) or (entry.get("alg") not in (None, *ALGORITHMS)):
                continue
            try:
                keys[kid] = jwt.PyJWK(entry, algorithm="RS256").key
            except jwt.PyJWTError:
                continue
        self._keys = keys
        self._loaded_at = time.monotonic()

    async def key(self, kid: str) -> Any:
        if kid in self._keys and time.monotonic() - self._loaded_at < _JWKS_TTL:
            return self._keys[kid]
        async with self._lock:
            age = time.monotonic() - self._loaded_at
            stale = age >= _JWKS_TTL
            if (kid not in self._keys and age >= _JWKS_MIN_REFETCH) or stale:
                try:
                    await self._load()
                except (httpx.HTTPError, ValueError) as exc:
                    if kid in self._keys:  # keep serving with the keys we have; Keycloak is briefly away
                        log.warning("Could not refresh Keycloak signing keys (%s); using cached keys", exc)
                        return self._keys[kid]
                    raise IdentityUnavailable("Could not fetch Keycloak signing keys") from exc
            return self._keys.get(kid)


jwks = JwksCache()


async def verify_access_token(raw: str) -> dict[str, Any]:
    settings = get_settings()
    if not settings.oidc_issuer:
        raise TokenError("Keycloak sign-in is not configured")
    try:
        header = jwt.get_unverified_header(raw)
    except jwt.PyJWTError as exc:
        raise TokenError("Malformed access token") from exc
    kid = header.get("kid")
    if header.get("alg") not in ALGORITHMS or not isinstance(kid, str):
        raise TokenError("Unsupported access token")
    key = await jwks.key(kid)
    if key is None:
        raise TokenError("Access token signed with an unknown key")
    try:
        claims = jwt.decode(
            raw, key, algorithms=ALGORITHMS, audience=settings.oidc_audience, issuer=settings.oidc_issuer,
            leeway=LEEWAY_SECONDS, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("Invalid or expired access token") from exc
    # Keycloak marks access tokens typ=Bearer; ID and refresh tokens must never authenticate API calls.
    if claims.get("typ") != "Bearer":
        raise TokenError("Not an access token")
    if settings.oidc_authorized_party and claims.get("azp") != settings.oidc_authorized_party:
        raise TokenError("Access token was issued to another application")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub or len(sub) > 64:
        raise TokenError("Access token has no usable subject")
    return claims


def roles_from_claims(claims: dict[str, Any]) -> list[str]:
    value = claims.get(get_settings().oidc_roles_claim)
    if not isinstance(value, list):
        return []
    return sorted({r for r in value if isinstance(r, str) and r in SYSTEM_ROLES})


# ------------------------------------------------------------------------------------- API-token owners


@dataclass(frozen=True)
class OwnerStatus:
    exists: bool
    enabled: bool = False
    roles: tuple[str, ...] = ()
    username: str | None = None
    email: str | None = None
    full_name: str = ""


OwnerLookup = Callable[[str], Awaitable[OwnerStatus]]


class GatewayOwners:
    """Ask the portal gateway about an API token's owner (it holds the Keycloak management account; Slipway does not).

    Reading another user's client roles through Keycloak's admin API needs view-clients, which would also expose every
    client's secret, so Slipway never gets admin access. The gateway answers this one question over the private network.
    """

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.transport = transport

    async def owner(self, sub: str) -> OwnerStatus:
        s = get_settings()
        if not s.internal_secret:
            raise IdentityUnavailable("SLIPWAY_INTERNAL_SECRET is not set")
        try:
            async with httpx.AsyncClient(timeout=10, transport=self.transport) as client:
                response = await client.get(
                    f"{s.owner_lookup_url}/{quote(sub, safe='')}", headers={"Authorization": f"Bearer {s.internal_secret}"}
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IdentityUnavailable("Could not check the token owner with the portal") from exc
        if not isinstance(data, dict) or not data.get("exists"):
            return OwnerStatus(exists=False)
        roles = data.get("roles") if isinstance(data.get("roles"), list) else []
        text = lambda key: data.get(key) if isinstance(data.get(key), str) else None  # noqa: E731
        full_name = " ".join(p for p in (text("firstName"), text("lastName")) if p)
        return OwnerStatus(
            exists=True, enabled=data.get("enabled") is True,
            roles=tuple(sorted({r for r in roles if isinstance(r, str) and r in SYSTEM_ROLES})),
            username=text("username"), email=text("email"), full_name=full_name,
        )


class OwnerCache:
    def __init__(self, lookup: OwnerLookup | None = None) -> None:
        self._gateway = GatewayOwners()
        self.lookup: OwnerLookup = lookup or self._gateway.owner
        self._entries: dict[str, tuple[float, OwnerStatus]] = {}

    def clear(self) -> None:
        self._entries.clear()

    async def get(self, sub: str) -> OwnerStatus:
        hit = self._entries.get(sub)
        if hit and time.monotonic() - hit[0] < get_settings().oidc_owner_cache_seconds:
            return hit[1]
        status = await self.lookup(sub)
        if len(self._entries) > 10_000:
            self._entries.clear()
        self._entries[sub] = (time.monotonic(), status)
        return status


owners = OwnerCache()
