from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "TrustVault"
    env: str = "development"
    database_url: str = "postgresql+psycopg2://vault:vaultpass@db:5432/trustvault"
    secret_key: str = "change-me-in-production"
    encryption_key: str = "trustvault-master-aes-gcm-key-32bytes"
    storage_dir: str = "/var/vault/storage"
    audit_hmac_key: str = "trustvault-audit-hmac-key-changeme"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

cfg = Settings()
