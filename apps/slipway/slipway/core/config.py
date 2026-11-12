"""Application settings, read from environment variables (prefix ``SLIPWAY_``) or ``.env``."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from functools import lru_cache
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

log = logging.getLogger(__name__)

DEV_SECRET = "dev-insecure-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SLIPWAY_",
        # SLIPWAY_ENV_FILE="" disables .env loading (the test suite does this).
        env_file=os.environ.get("SLIPWAY_ENV_FILE", ".env") or None,
        env_file_encoding="utf-8",
        extra="ignore",
        # Keep secrets out of configuration error messages.
        hide_input_in_errors=True,
    )

    env: Literal["development", "production", "test"] = "development"
    # Public origin of the HackSpaceLabs portal that fronts Slipway (scheme and host).
    base_url: str = "http://localhost:3000"
    # Path at which the portal gateway exposes this API (``/api/v1`` here). Used to build the GitHub callback URL.
    api_public_path: str = "/api/slipway"
    # Portal page the browser returns to after connecting GitHub.
    portal_return_path: str = "/portal"
    log_level: str = "INFO"
    # Proxies trusted to set X-Forwarded-For/-Proto (comma-separated IPs or CIDRs, passed to uvicorn).
    forwarded_allow_ips: str = "127.0.0.1"

    # Signs nothing user-visible today but is the root secret for derived keys.
    secret_key: str = DEV_SECRET
    # Fernet key(s) used to encrypt SSH keys, passwords, env vars and OAuth tokens at rest.
    # Comma-separate several keys to rotate: the first encrypts, all are tried for decryption.
    encryption_key: str = ""

    database_url: str = "postgresql+asyncpg://slipway:slipway@localhost:5432/slipway"
    # Optional; used unless a configured database_url has its own password. It may contain any character.
    database_password: str | None = None
    database_echo: bool = False

    # Identity: Keycloak (HackSpaceLabs realm). The gateway forwards the signed-in user's access token, which
    # Slipway verifies itself: signature (JWKS), issuer, audience, authorized party and token type.
    # oidc_issuer is the public issuer URL, exactly as it appears in the tokens' "iss" claim.
    oidc_issuer: str = ""
    # Where Slipway itself reaches the realm (JWKS, service-account token, admin API); defaults to oidc_issuer.
    # In the compose stack this is the internal http://keycloak:8080/realms/hackspacelabs.
    oidc_internal_url: str = ""
    oidc_audience: str = "slipway"
    # The client the gateway signs in with; tokens issued to any other client are refused.
    oidc_authorized_party: str = "hackspacelabs-web"
    oidc_roles_claim: str = "slipway_roles"
    # Confidential "slipway" client with a view-users service account. Slipway uses it to confirm that an API
    # token's owner is still enabled in Keycloak, and to read their current Slipway roles.
    oidc_client_id: str = "slipway"
    oidc_client_secret: str | None = None
    # How long a Keycloak lookup for an API-token owner is trusted before asking again.
    oidc_owner_cache_seconds: int = 60

    github_client_id: str | None = None
    github_client_secret: str | None = None
    github_scopes: str = "read:user user:email repo"
    # Optional machine token (PAT or GitHub App installation token) used for deploys
    # when the user triggering the deploy has not linked GitHub.
    github_service_token: str | None = None
    github_api_url: str = "https://api.github.com"
    github_web_url: str = "https://github.com"

    host_poll_interval: int = 300  # seconds; 0 disables background host health checks
    default_deploy_root: str = "/opt/slipway"
    ssh_connect_timeout: int = 15

    @field_validator("base_url", "oidc_issuer", "oidc_internal_url", "api_public_path")
    @classmethod
    def _strip_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("log_level", mode="before")
    @classmethod
    def _log_level(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip().upper()
            if value not in logging.getLevelNamesMapping():
                raise ValueError("SLIPWAY_LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL")
        return value

    @model_validator(mode="after")
    def _check_production(self) -> Settings:
        if self.env == "production":
            if self.secret_key == DEV_SECRET or len(self.secret_key) < 32:
                raise ValueError("SLIPWAY_SECRET_KEY must be set to a random value of 32+ characters")
            if not self.encryption_key:
                raise ValueError(
                    "SLIPWAY_ENCRYPTION_KEY must be set in production (run `slipway generate-secrets`)"
                )
            if not self.oidc_issuer:
                raise ValueError("SLIPWAY_OIDC_ISSUER must be set in production")
            if not self.oidc_client_secret:
                raise ValueError("SLIPWAY_OIDC_CLIENT_SECRET must be set in production")
        return self

    @model_validator(mode="after")
    def _check_encryption_keys(self) -> Settings:
        if not self.encryption_key:
            return self
        keys = self.fernet_keys()
        if not keys:
            raise ValueError("SLIPWAY_ENCRYPTION_KEY contains no keys (run `slipway generate-secrets`)")
        for i, key in enumerate(keys, 1):
            try:
                Fernet(key)
            except ValueError:
                raise ValueError(
                    f"SLIPWAY_ENCRYPTION_KEY entry {i} is not a valid Fernet key (run `slipway generate-secrets`)"
                ) from None
        return self

    @model_validator(mode="after")
    def _apply_database_password(self) -> Settings:
        if self.database_password is None:
            return self
        url = make_url(self.database_url)
        # A password written into a configured SLIPWAY_DATABASE_URL wins, so an overridden URL keeps working.
        url_has_password = url.password is not None and "database_url" in self.model_fields_set
        if url.get_backend_name() != "sqlite" and not url_has_password:
            self.database_url = url.set(password=self.database_password).render_as_string(hide_password=False)
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def realm_url(self) -> str:
        """The realm as Slipway reaches it (internal URL when set)."""
        return self.oidc_internal_url or self.oidc_issuer

    @property
    def jwks_url(self) -> str:
        return f"{self.realm_url}/protocol/openid-connect/certs"

    @property
    def oidc_token_url(self) -> str:
        return f"{self.realm_url}/protocol/openid-connect/token"

    @property
    def oidc_admin_url(self) -> str:
        """Admin REST API base for the realm: .../realms/<name> -> .../admin/realms/<name>."""
        base, sep, realm = self.realm_url.rpartition("/realms/")
        if not sep:
            raise ValueError("The OIDC issuer must look like https://host/realms/<realm>")
        return f"{base}/admin/realms/{realm}"

    @property
    def github_enabled(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

    @property
    def github_callback_url(self) -> str:
        return f"{self.base_url}{self.api_public_path}/auth/github/callback"

    @property
    def oauth_scopes(self) -> str:
        return " ".join(self.github_scopes.split())

    def fernet_keys(self) -> list[bytes]:
        if self.encryption_key:
            return [k.strip().encode() for k in self.encryption_key.split(",") if k.strip()]
        # Development fallback: derive a stable key from the secret key.
        digest = hashlib.sha256(f"slipway-encryption:{self.secret_key}".encode()).digest()
        return [base64.urlsafe_b64encode(digest)]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.encryption_key and not settings.is_production:
        log.warning("SLIPWAY_ENCRYPTION_KEY not set; deriving one from SLIPWAY_SECRET_KEY (dev only)")
    return settings
