from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "TrustVault"
    env: str = "development"
    database_url: str = "postgresql+psycopg2://vault:vaultpass@db:5432/trustvault"
    secret_key: str = "change-me-in-production"
    storage_dir: str = "/var/vault/storage"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

cfg = Settings()
