import logging
import re
from typing import List, Optional
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("autosoc")

_TI_PROVIDER_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")
_SUPPORTED_LLM_PROVIDERS = frozenset({"ollama", "fixture"})
_VALID_APP_ENVS = frozenset({"development", "testing", "staging", "production"})


class Settings(BaseSettings):
    PROJECT_NAME: str = "AutoSOC API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    APP_ENV: str = "development"
    DEBUG: bool = False

    # Logging
    LOG_LEVEL: str = "INFO"

    # Postgres
    POSTGRES_SERVER: str = Field(default="localhost", min_length=1)
    POSTGRES_USER: str = Field(default="autosoc", min_length=1)
    POSTGRES_PASSWORD: str = "autosoc_pass"
    POSTGRES_DB: str = Field(default="autosoc_db", min_length=1)
    POSTGRES_PORT: str = "5432"

    @property
    def async_database_uri(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # Redis
    REDIS_HOST: str = Field(default="localhost", min_length=1)
    REDIS_PORT: int = Field(default=6379, ge=1, le=65535)

    @property
    def redis_uri(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

    # Qdrant
    QDRANT_HOST: str = Field(default="localhost", min_length=1)
    QDRANT_PORT: int = Field(default=6333, ge=1, le=65535)

    # Kafka
    KAFKA_BROKERS: str = Field(
        default="localhost:9092",
        min_length=1,
        validation_alias=AliasChoices("KAFKA_BROKERS", "KAFKA_BOOTSTRAP_SERVERS"),
    )

    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized not in _VALID_APP_ENVS:
            raise ValueError(
                f"APP_ENV must be one of {sorted(_VALID_APP_ENVS)}, got: {value!r}"
            )
        return normalized

    @field_validator("POSTGRES_PORT")
    @classmethod
    def validate_postgres_port(cls, value: str) -> str:
        raw = str(value or "").strip()
        if not raw.isdigit():
            raise ValueError("POSTGRES_PORT must be a numeric TCP port between 1 and 65535")
        port_num = int(raw)
        if port_num < 1 or port_num > 65535:
            raise ValueError("POSTGRES_PORT must be between 1 and 65535")
        return str(port_num)

    @field_validator(
        "POSTGRES_SERVER",
        "POSTGRES_USER",
        "POSTGRES_DB",
        "REDIS_HOST",
        "QDRANT_HOST",
        "KAFKA_BROKERS",
    )
    @classmethod
    def validate_non_empty_endpoint_field(cls, value: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("Configuration host/database/broker field must not be blank")
        return cleaned

    # Threat Intelligence Providers (Day 10)
    TI_ENABLED: bool = False
    TI_PROVIDERS: str = ""
    TI_TIMEOUT_SECONDS: float = Field(default=3.0, gt=0.0, le=30.0)
    TI_CACHE_TTL_SECONDS: int = Field(default=300, ge=1, le=86400)
    TI_MAX_OBSERVABLES_PER_EVENT: int = Field(default=10, ge=1, le=100)
    TI_USE_REDIS_CACHE: bool = True

    # Threat Intelligence Reliability & Circuit Breaker (Day 11)
    TI_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    TI_RETRY_BASE_DELAY_SECONDS: float = Field(default=0.25, ge=0.0, le=10.0)
    TI_RETRY_MAX_DELAY_SECONDS: float = Field(default=5.0, ge=0.0, le=30.0)
    TI_CIRCUIT_BREAKER_THRESHOLD: int = Field(default=3, ge=1, le=50)
    TI_CIRCUIT_BREAKER_COOLDOWN_SECONDS: float = Field(default=60.0, ge=1.0, le=3600.0)

    # Optional external TI credentials via environment (never logged or serialized)
    TI_VIRUSTOTAL_API_KEY: Optional[SecretStr] = None
    TI_ABUSEIPDB_API_KEY: Optional[SecretStr] = None
    TI_OTX_API_KEY: Optional[SecretStr] = None
    TI_GENERIC_API_KEY: Optional[SecretStr] = None
    TI_GENERIC_BASE_URL: Optional[str] = None

    # Local LLM Foundation (Day 12 - disabled by default; local Ollama runtime)
    LLM_ENABLED: bool = False
    LLM_PROVIDER: str = "ollama"
    LLM_MODEL: str = ""
    LLM_BASE_URL: Optional[str] = "http://localhost:11434"
    LLM_TIMEOUT_SECONDS: float = Field(default=30.0, gt=0.0, le=300.0)
    LLM_MAX_TOKENS: int = Field(default=512, ge=1, le=32768)
    LLM_TEMPERATURE: float = Field(default=0.1, ge=0.0, le=2.0)

    @field_validator("LLM_PROVIDER")
    @classmethod
    def validate_llm_provider(cls, value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized not in _SUPPORTED_LLM_PROVIDERS:
            raise ValueError(
                f"Unsupported LLM_PROVIDER {value!r}; allowed providers: {sorted(_SUPPORTED_LLM_PROVIDERS)}"
            )
        return normalized

    @field_validator("LLM_MODEL")
    @classmethod
    def validate_llm_model(cls, value: str) -> str:
        cleaned = str(value or "").strip()
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
            raise ValueError("LLM_MODEL must not contain control characters")
        if len(cleaned) > 128:
            raise ValueError("LLM_MODEL must not exceed 128 characters")
        return cleaned

    @field_validator("LLM_BASE_URL")
    @classmethod
    def validate_llm_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        parsed = urlsplit(stripped)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError("LLM_BASE_URL must be an http or https URL with host")
        if parsed.username or parsed.password:
            raise ValueError("LLM_BASE_URL must not embed URL credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("LLM_BASE_URL must not contain query parameters or fragments")
        return f"{parsed.scheme.lower()}://{parsed.netloc}{parsed.path}".rstrip("/")

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
        if self.TI_RETRY_MAX_DELAY_SECONDS < self.TI_RETRY_BASE_DELAY_SECONDS:
            raise ValueError(
                "TI_RETRY_MAX_DELAY_SECONDS must be >= TI_RETRY_BASE_DELAY_SECONDS"
            )
        # Validate LOG_LEVEL is a known Python logging level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.LOG_LEVEL.upper() not in valid_levels:
            raise ValueError(
                f"LOG_LEVEL must be one of {valid_levels}, got: {self.LOG_LEVEL!r}"
            )
        return self


settings = Settings()
