"""Central settings, loaded from environment / .env.

Nothing in here reaches out over the network; it's pure config parsing so
the rest of the app can import `settings` without side effects.
"""
from __future__ import annotations

import os
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"

    store_backend: Literal["memory", "redis"] = "memory"
    redis_url: str = "redis://localhost:6379/0"

    admin_api_key: str = Field(default="change-me-to-a-long-random-value")

    receiver_base_url: str = "http://localhost:8080"

    replay_jti_ttl_seconds: int = 900
    decision_cache_ttl_seconds: int = 300
    correlation_ttl_seconds: int = 86400

    # --- Custom CA Trust ---
    ca_bundle_path: str = ""

    # --- BIG-IP APM ---
    bigip_host: str = ""
    bigip_port: int = 443
    bigip_username: str = ""
    bigip_password: str = ""
    bigip_verify_tls: bool = True
    bigip_auth_mode: Literal["token", "basic"] = "token"
    bigip_enable_fast_path: bool = False

    @property
    def bigip_base_url(self) -> str:
        return f"https://{self.bigip_host}:{self.bigip_port}"

    @property
    def valid_ca_bundle_path(self) -> str | None:
        """Returns ca_bundle_path if the file exists, is non-empty, and contains valid PEM certificates."""
        if not self.ca_bundle_path or not os.path.exists(self.ca_bundle_path):
            return None
        try:
            if os.path.getsize(self.ca_bundle_path) == 0:
                return None
            with open(self.ca_bundle_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if "-----BEGIN CERTIFICATE-----" not in content:
                return None
            import ssl

            ctx = ssl.create_default_context()
            ctx.load_verify_locations(cafile=self.ca_bundle_path)
            return self.ca_bundle_path
        except Exception:
            return None

    def get_httpx_verify(self, verify_tls: bool = True) -> bool | str:
        """Returns httpx verify parameter: False, ca_bundle_path string, or True."""
        if not verify_tls:
            return False
        valid_path = self.valid_ca_bundle_path
        if valid_path:
            return valid_path
        return True

    def get_ssl_context(self, verify_tls: bool = True) -> ssl.SSLContext:
        """Returns standard or custom SSLContext for libraries requiring PySSL."""
        import ssl

        if not verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        valid_path = self.valid_ca_bundle_path
        if valid_path:
            return ssl.create_default_context(cafile=valid_path)
        return ssl.create_default_context()


def _sanitize_ca_env() -> None:
    """Removes invalid, empty, or unpopulated CA bundle paths from os.environ
    so httpx/requests trust_env does not crash on empty files."""
    for env_var in ("SSL_CERT_FILE", "CA_BUNDLE_PATH", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        path = os.environ.get(env_var)
        if path:
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                os.environ.pop(env_var, None)
            else:
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if "-----BEGIN CERTIFICATE-----" not in content:
                        os.environ.pop(env_var, None)
                    else:
                        import ssl

                        ctx = ssl.create_default_context()
                        ctx.load_verify_locations(cafile=path)
                except Exception:
                    os.environ.pop(env_var, None)


_sanitize_ca_env()
settings = Settings()



