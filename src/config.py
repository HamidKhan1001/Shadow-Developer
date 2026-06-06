"""
Global configuration loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # App
    app_env: str = "development"
    log_level: str = "INFO"

    # AWS
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0"

    # OpenSearch
    opensearch_endpoint: str = "https://localhost:9200"
    opensearch_index: str = "shadow-dev-context"

    # Kiro
    kiro_api_key: str = "demo-key"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
