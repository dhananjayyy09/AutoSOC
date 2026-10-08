from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "AutoSOC API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Postgres
    # Postgres
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "autosoc"
    POSTGRES_PASSWORD: str = "autosoc_pass"
    POSTGRES_DB: str = "autosoc_db"
    POSTGRES_PORT: str = "5432"

    @property
    def async_database_uri(self) -> str:
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

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
    KAFKA_BROKERS: str = "localhost:9092"

    model_config = SettingsConfigDict(env_file="../.env", extra="ignore", case_sensitive=True)

settings = Settings()
