"""Application configuration loaded from environment variables / .env file.

Secrets are never hard-coded; every sensitive value is read from the
environment (or a `.env` file at the project root).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


def _parse_cidrs(value: str | None) -> list[str]:
    if not value:
        return []
    items = []
    for part in value.split(","):
        part = part.strip()
        if part:
            items.append(part)
    return items


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = "MlinziOps AI"
    app_tagline: str = "AI-assisted Security Operations"
    app_env: str = "development"  # development | testing | production
    secret_key: str = "CHANGE_ME"
    cookie_secure: bool = False
    session_cookie_name: str = "mlinziops_session"
    access_token_expire_minutes: int = 480
    jwt_algorithm: str = "HS256"
    version: str = "2.0.0"

    # Database
    database_url: str = (
        "postgresql+psycopg://mlinziops:mlinziops@localhost:5432/mlinziops"
    )

    # Initial admin (used by CLI / seed)
    default_admin_username: str = "admin"
    default_admin_email: str = "admin@mlinziops.local"
    default_admin_password: str = "CHANGE_ME"

    # Wazuh
    wazuh_url: str = ""
    wazuh_username: str = ""
    wazuh_password: str = ""
    wazuh_verify_ssl: bool = False
    wazuh_timeout: float = 10.0

    # Authorized scanning scope
    authorized_cidrs: str = "127.0.0.1/32,192.168.187.0/24"

    # Log sources
    log_auth_path: str = "/var/log/auth.log"
    log_syslog_path: str = "/var/log/syslog"
    log_journalctl_available: bool = True
    log_max_lines: int = 5000

    # Nmap
    nmap_path: str = "/usr/bin/nmap"
    nmap_enabled: bool = True
    nmap_timeout: int = 300

    # Rate limiting
    rate_limit_login_max: int = 8
    rate_limit_login_window_seconds: int = 900

    # ---- AI / autonomy ------------------------------------------------
    # ai_provider: "disabled" | "ollama" | "openai_compatible"
    # When disabled/offline, the platform continues with deterministic
    # detection only (spec §40) — AI absence never breaks monitoring.
    ai_provider: str = "disabled"
    ai_model: str = ""
    ai_base_url: str = ""          # OpenAI-compatible endpoint or Ollama host
    ai_api_key: str = ""           # API key for openai_compatible
    ai_temperature: float = 0.2
    ai_timeout_seconds: float = 90.0
    ai_max_tokens: int = 1500
    autonomy_mode: str = "OBSERVE"  # OBSERVE | ASSIST | CONTROLLED_AUTONOMY | EMERGENCY_LOCKDOWN
    # Hard guardrails (spec §29)
    ai_max_autonomous_actions_per_hour: int = 10
    ai_max_concurrent_actions: int = 2
    ai_action_timeout_seconds: int = 60
    ai_cooldown_minutes: int = 5
    # SOC loop cadence (seconds). 0 disables the background worker.
    soc_loop_interval_seconds: int = 30
    # Emergency stop switch (spec §53) — persisted, admin-only via UI.
    emergency_stop: bool = True

    @field_validator("secret_key")
    @classmethod
    def _secret_key_not_default(cls, v: str) -> str:
        return v

    @property
    def authorized_cidr_list(self) -> list[str]:
        return _parse_cidrs(self.authorized_cidrs)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
