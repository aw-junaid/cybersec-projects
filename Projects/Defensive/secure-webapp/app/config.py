import os
from datetime import timedelta

class Config:
    # Basic Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secure-key-here-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY') or 'csrf-secure-key'
    
    # Session Security
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = 'memory://'
    
    # Password Security
    BCRYPT_LOG_ROUNDS = 12
    
    # Logging
    LOG_LEVEL = 'INFO'
