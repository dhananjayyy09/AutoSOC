import logging
from pydantic import Field, AliasChoices, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("autosoc")


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
