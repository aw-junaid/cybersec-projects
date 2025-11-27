import os
from typing import List, Optional
from pydantic import BaseSettings
from datetime import timedelta

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Secure API"
    DEBUG: bool = False
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secure-secret-key-change-in-production")
    
    # JWT Configuration
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # Short-lived access tokens
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7     # Longer-lived refresh tokens
    JWT_LEEWAY: int = 15                   # Token expiration leeway in seconds
    
    # OAuth2 Configuration
    OAUTH2_CLIENT_ID: str = os.getenv("OAUTH2_CLIENT_ID", "default-client-id")
    OAUTH2_CLIENT_SECRET: str = os.getenv("OAUTH2_CLIENT_SECRET", "default-client-secret")
    OAUTH2_REDIRECT_URI: str = os.getenv("OAUTH2_REDIRECT_URI", "http://localhost:8000/auth/callback")
    
    # Security
    BCRYPT_ROUNDS: int = 12
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_TIME_MINUTES: int = 15
    RATE_LIMIT_PER_MINUTE: int = 10
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "https://yourdomain.com"
    ]
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./test.db")
    
    # Redis for token blacklisting
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    class Config:
        env_file = ".env"

settings = Settings()
