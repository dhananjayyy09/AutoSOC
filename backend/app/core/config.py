import logging
import re
from typing import List, Optional
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("autosoc")

_TI_PROVIDER_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


class Settings(BaseSettings):
    PROJECT_NAME: str = "AutoSOC API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    APP_ENV: str = "development"
    DEBUG: bool = False

    # Logging
    LOG_LEVEL: str = "INFO"

    # Postgres
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "autosoc"
    POSTGRES_PASSWORD: str = "autosoc_pass"
    POSTGRES_DB: str = "autosoc_db"
    POSTGRES_PORT: str = "5432"

    @property
    def async_database_uri(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    @property
    def redis_uri(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

    # Qdrant
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333

    # Kafka
    KAFKA_BROKERS: str = Field(
        default="localhost:9092",
        validation_alias=AliasChoices("KAFKA_BROKERS", "KAFKA_BOOTSTRAP_SERVERS"),
    )

    # Threat Intelligence Providers (Day 10)
    TI_ENABLED: bool = False
    TI_PROVIDERS: str = ""
    TI_TIMEOUT_SECONDS: float = Field(default=3.0, gt=0.0, le=30.0)
    TI_CACHE_TTL_SECONDS: int = Field(default=300, ge=1, le=86400)
    TI_MAX_OBSERVABLES_PER_EVENT: int = Field(default=10, ge=1, le=100)
    TI_USE_REDIS_CACHE: bool = True

    # Optional external TI credentials via environment (never logged or serialized)
    TI_VIRUSTOTAL_API_KEY: Optional[SecretStr] = None
    TI_ABUSEIPDB_API_KEY: Optional[SecretStr] = None
    TI_OTX_API_KEY: Optional[SecretStr] = None
    TI_GENERIC_API_KEY: Optional[SecretStr] = None
    TI_GENERIC_BASE_URL: Optional[str] = None

    @property
    def enabled_ti_providers(self) -> List[str]:
        """Ordered, deduplicated lowercase TI provider identifiers from TI_PROVIDERS."""
        if not self.TI_ENABLED or not self.TI_PROVIDERS:
            return []
        seen: List[str] = []
        for raw in self.TI_PROVIDERS.split(","):
            item = raw.strip().lower()
            if item and item not in seen:
                seen.append(item)
        return seen

    @field_validator("TI_PROVIDERS")
    @classmethod
    def validate_ti_providers(cls, value: str) -> str:
        if not value or not value.strip():
            return ""
        for raw in value.split(","):
            item = raw.strip()
            if not item:
                continue
            if not _TI_PROVIDER_NAME_RE.match(item):
                raise ValueError(
                    f"Invalid TI provider identifier {item!r}; allowed pattern [a-zA-Z0-9_.-]"
                )
        return value

    @field_validator("TI_GENERIC_BASE_URL")
    @classmethod
    def validate_ti_generic_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        parsed = urlsplit(stripped)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("TI_GENERIC_BASE_URL must be an http or https URL with host")
        if parsed.username or parsed.password:
            raise ValueError("TI_GENERIC_BASE_URL must not embed URL credentials")
        return stripped.rstrip("/")

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        extra="ignore",
        case_sensitive=True,
    )

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        """Warn about unsafe configuration when running in production."""
        if self.APP_ENV == "production":
            if self.DEBUG:
                logger.warning(
                    "SECURITY WARNING: DEBUG=True is set in production environment. "
                    "This exposes internal details and must be disabled."
                )
            if self.POSTGRES_PASSWORD in ("autosoc_pass", "", "password", "secret"):
                logger.warning(
                    "SECURITY WARNING: POSTGRES_PASSWORD appears to be a default or "
                    "weak value in production. Rotate immediately."
                )
        # Validate LOG_LEVEL is a known Python logging level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.LOG_LEVEL.upper() not in valid_levels:
            raise ValueError(
                f"LOG_LEVEL must be one of {valid_levels}, got: {self.LOG_LEVEL!r}"
            )
        return self


settings = Settings()
