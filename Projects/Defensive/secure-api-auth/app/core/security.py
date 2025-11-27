import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import redis
from jose import JWTError, jwt
from fastapi import HTTPException, status, Request
from app.core.config import settings

# Redis connection for token blacklist
redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

class SecurityUtils:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def add_to_blacklist(token: str, expires_in: timedelta) -> None:
        """Add token to blacklist"""
        redis_client.setex(
            f"blacklist:{token}",
            expires_in,
            "revoked"
        )
    
    @staticmethod
    def is_token_blacklisted(token: str) -> bool:
        """Check if token is blacklisted"""
        return redis_client.exists(f"blacklist:{token}") == 1

class RateLimiter:
    @staticmethod
    def check_rate_limit(key: str, limit: int, window: int = 60) -> bool:
        """Check if rate limit is exceeded"""
        current = redis_client.get(f"rate_limit:{key}")
        if current and int(current) >= limit:
            return False
        
        # Use pipeline for atomic operations
        pipe = redis_client.pipeline()
        pipe.incr(f"rate_limit:{key}")
        pipe.expire(f"rate_limit:{key}", window)
        pipe.execute()
        
        return True

class IPBlocker:
    @staticmethod
    def block_ip(ip: str, minutes: int = settings.LOCKOUT_TIME_MINUTES) -> None:
        """Block IP address temporarily"""
        redis_client.setex(
            f"blocked_ip:{ip}",
            timedelta(minutes=minutes),
            "blocked"
        )
    
    @staticmethod
    def is_ip_blocked(ip: str) -> bool:
        """Check if IP is blocked"""
        return redis_client.exists(f"blocked_ip:{ip}") == 1
