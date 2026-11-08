from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "TrustVault"
    env: str = "development"
    database_url: str = "postgresql+psycopg2://vault:vaultpass@db:5432/trustvault"
    secret_key: str = "change-me-in-production"
    encryption_key: str = "trustvault-master-aes-gcm-key-32bytes"
    storage_dir: str | None = None
    audit_hmac_key: str = "trustvault-audit-hmac-key-changeme"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("database_url")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        if v.startswith("postgres://"):
            return "postgresql+psycopg2://" + v[len("postgres://"):]
        if v.startswith("postgresql://"):
            return "postgresql+psycopg2://" + v[len("postgresql://"):]
        return v

cfg = Settings()
