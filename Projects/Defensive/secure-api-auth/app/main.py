from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import uvicorn

from app.core.config import settings
from app.auth.jwt import jwt_manager, get_current_active_user, RateLimiter, IPBlocker
from app.auth.oauth import oauth_manager
from app.models.users import (
    UserCreate, UserInDB, Token, RefreshTokenRequest, 
    PasswordChangeRequest
)
from app.core.security import SecurityUtils

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SlowAPIMiddleware)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# In-memory user store (replace with database in production)
users_db = {}

@app.post("/auth/register", response_model=Token)
@limiter.limit("5 per minute")
async def register(
    request: Request,
    user_data: UserCreate
):
    """User registration endpoint"""
    # Check if user already exists
    if user_data.email in users_db or user_data.username in [u.username for u in users_db.values()]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )
    
    # Create user
    user_id = len(users_db) + 1
    hashed_password = SecurityUtils.hash_password(user_data.password)
    
    user = UserInDB(
        id=user_id,
        email=user_data.email,
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=hashed_password,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    users_db[user_id] = user
    
    # Create tokens
    access_token = jwt_manager.create_access_token(
        subject=user.username,
        payload={"user_id": user.id, "email": user.email}
    )
    
    refresh_token = jwt_manager.create_refresh_token(
        subject=user.username
    )
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@app.post("/auth/login", response_model=Token)
@limiter.limit("5 per minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """Login endpoint with rate limiting and security controls"""
    client_ip = request.client.host
    
    # Check if IP is blocked
    if IPBlocker.is_ip_blocked(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address temporarily blocked due to too many failed attempts"
        )
    
    # Find user
    user = next(
        (u for u in users_db.values() if u.username == form_data.username), 
        None
    )
    
    # Security: Use constant-time comparison
    valid_user = user is not None
    
    if valid_user:
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account temporarily locked"
            )
        
        # Verify password
        if SecurityUtils.verify_password(form_data.password, user.hashed_password):
            # Successful login
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            
            # Create tokens
            access_token = jwt_manager.create_access_token(
                subject=user.username,
                payload={"user_id": user.id, "email": user.email}
            )
            
            refresh_token = jwt_manager.create_refresh_token(
                subject=user.username
            )
            
            return Token(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            )
        else:
            # Failed login
            user.failed_login_attempts += 1
            
            if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(
                    minutes=settings.LOCKOUT_TIME_MINUTES
                )
                # Also block IP after multiple failures
                IPBlocker.block_ip(client_ip)
    
    # Simulate password verification for constant-time
    SecurityUtils.verify_password("dummy_password", SecurityUtils.hash_password("dummy"))
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password"
    )

@app.post("/auth/refresh", response_model=Token)
async def refresh_token(
    request: RefreshTokenRequest
):
    """Refresh access token using refresh token"""
    try:
        # Verify refresh token
        payload = jwt_manager.verify_token(
            request.refresh_token, 
            token_type="refresh"
        )
        
        # Revoke the old refresh token (refresh token rotation)
        jwt_manager.revoke_token(request.refresh_token)
        
        # Create new tokens
        access_token = jwt_manager.create_access_token(
            subject=payload["sub"],
            payload={k: v for k, v in payload.items() if k not in ["exp", "iat", "type", "jti"]}
        )
        
        refresh_token = jwt_manager.create_refresh_token(
            subject=payload["sub"]
        )
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@app.post("/auth/logout")
async def logout(
    current_user: dict = Depends(get_current_active_user),
    request: Request = None
):
    """Logout endpoint - revoke tokens"""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        jwt_manager.revoke_token(token)
    
    return {"message": "Successfully logged out"}

@app.post("/auth/revoke-all")
async def revoke_all_tokens(
    current_user: dict = Depends(get_current_active_user)
):
    """Revoke all tokens for current user"""
    # In production, you would maintain a list of tokens per user
    # and revoke all of them
    return {"message": "All tokens revoked"}

# OAuth endpoints
@app.get("/auth/google")
async def google_auth(request: Request):
    """Initiate Google OAuth flow"""
    return await oauth_manager.google_authorize(request)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    """Handle Google OAuth callback"""
    return await oauth_manager.google_callback(request)

# Protected endpoints
@app.get("/users/me")
@limiter.limit("60 per minute")
async def read_users_me(
    request: Request,
    current_user: dict = Depends(get_current_active_user)
):
    """Get current user information"""
    return {
        "username": current_user["sub"],
        "user_id": current_user.get("user_id"),
        "email": current_user.get("email")
    }

@app.post("/users/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: dict = Depends(get_current_active_user)
):
    """Change user password"""
    user = next(
        (u for u in users_db.values() if u.username == current_user["sub"]), 
        None
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify current password
    if not SecurityUtils.verify_password(password_data.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    user.hashed_password = SecurityUtils.hash_password(password_data.new_password)
    user.updated_at = datetime.utcnow()
    
    # Revoke all existing tokens (optional security measure)
    
    return {"message": "Password updated successfully"}

# Admin endpoints
@app.get("/admin/users")
async def list_users(
    current_user: dict = Depends(get_current_active_user)
):
    """Admin endpoint - list all users"""
    # Check if user has admin privileges
    if not current_user.get("is_superuser", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return list(users_db.values())

@app.get("/")
async def root():
    return {"message": "Secure API Authentication Service"}

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
