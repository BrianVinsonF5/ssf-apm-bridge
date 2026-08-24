"""Central settings, loaded from environment / .env.

Nothing in here reaches out over the network; it's pure config parsing so
the rest of the app can import `settings` without side effects.
"""
from __future__ import annotations

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


settings = Settings()
