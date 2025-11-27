from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import settings
from app.core.security import SecurityUtils, RateLimiter, IPBlocker

security = HTTPBearer(auto_error=False)

class JWTManager:
    def __init__(self):
        self.algorithm = settings.JWT_ALGORITHM
        self.secret_key = settings.SECRET_KEY
    
    def create_access_token(
        self, 
        subject: str, 
        payload: Optional[Dict[str, Any]] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode = {
            "exp": expire,
            "sub": subject,
            "iat": datetime.utcnow(),
            "type": "access",
            "jti": SecurityUtils.generate_secure_token(16)  # Unique token ID
        }
        
        if payload:
            to_encode.update(payload)
        
        encoded_jwt = jwt.encode(
            to_encode, 
            self.secret_key, 
            algorithm=self.algorithm
        )
        return encoded_jwt
    
    def create_refresh_token(
        self, 
        subject: str,
        payload: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create JWT refresh token"""
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
        to_encode = {
            "exp": expire,
            "sub": subject,
            "iat": datetime.utcnow(),
            "type": "refresh",
            "jti": SecurityUtils.generate_secure_token(16)
        }
        
        if payload:
            to_encode.update(payload)
        
        encoded_jwt = jwt.encode(
            to_encode, 
            self.secret_key, 
            algorithm=self.algorithm
        )
        return encoded_jwt
    
    def verify_token(
        self, 
        token: str, 
        token_type: str = "access"
    ) -> Dict[str, Any]:
        """Verify JWT token and return payload"""
        try:
            # Check if token is blacklisted
            if SecurityUtils.is_token_blacklisted(token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
            
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_aud": False}
            )
            
            # Verify token type
            if payload.get("type") != token_type:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token type. Expected {token_type}"
                )
            
            return payload
            
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def revoke_token(self, token: str) -> None:
        """Revoke token by adding to blacklist"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False}  # Don't verify expiration for revocation
            )
            
            # Calculate time until expiration
            exp_timestamp = payload.get("exp")
            if exp_timestamp:
                exp_time = datetime.fromtimestamp(exp_timestamp)
                time_until_expiry = exp_time - datetime.utcnow()
                
                # Only blacklist if token hasn't expired
                if time_until_expiry.total_seconds() > 0:
                    SecurityUtils.add_to_blacklist(
                        token, 
                        timedelta(seconds=time_until_expiry.total_seconds())
                    )
                    
        except JWTError:
            # If token is invalid, we don't need to blacklist it
            pass

# JWT Manager instance
jwt_manager = JWTManager()

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    request: Request = None
) -> Dict[str, Any]:
    """Dependency to get current user from JWT token"""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Rate limiting per token
    token_key = f"token:{credentials.credentials}"
    if not RateLimiter.check_rate_limit(token_key, 100):  # 100 requests per minute per token
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    # IP-based rate limiting
    client_ip = request.client.host if request else "unknown"
    ip_key = f"ip:{client_ip}"
    if not RateLimiter.check_rate_limit(ip_key, settings.RATE_LIMIT_PER_MINUTE):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="IP rate limit exceeded"
        )
    
    # Check if IP is blocked
    if IPBlocker.is_ip_blocked(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address temporarily blocked"
        )
    
    payload = jwt_manager.verify_token(credentials.credentials)
    return payload

async def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Dependency to check if user is active"""
    # Add any additional user status checks here
    if not current_user.get("active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user

async def optional_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """Optional authentication dependency"""
    if credentials is None:
        return None
    
    try:
        return jwt_manager.verify_token(credentials.credentials)
    except HTTPException:
        return None
