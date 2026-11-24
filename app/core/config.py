from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Linkbase"
    database_url: str
    jwt_secret_key: str
    jwt_access_token_expire_minutes: int
    jwt_algorithm: str
    test_database_url: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

