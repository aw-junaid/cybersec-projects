from typing import Optional, Dict, Any
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth
from app.core.config import settings
from app.auth.jwt import jwt_manager

# OAuth2 configuration
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/auth/authorize",
    tokenUrl="/auth/token",
    scopes={
        "read": "Read access",
        "write": "Write access",
        "admin": "Admin access"
    }
)

# OAuth client
oauth = OAuth()

# Configure OAuth providers
oauth.register(
    name='google',
    client_id=settings.OAUTH2_CLIENT_ID,
    client_secret=settings.OAUTH2_CLIENT_SECRET,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri=settings.OAUTH2_REDIRECT_URI,
    client_kwargs={'scope': 'openid email profile'},
)

class OAuthManager:
    def __init__(self):
        self.oauth = oauth
    
    async def google_authorize(self, request: Request):
        """Redirect to Google authorization endpoint"""
        return await self.oauth.google.authorize_redirect(
            request, 
            settings.OAUTH2_REDIRECT_URI
        )
    
    async def google_callback(self, request: Request) -> Dict[str, Any]:
        """Handle Google OAuth callback"""
        try:
            token = await self.oauth.google.authorize_access_token(request)
            user_info = token.get('userinfo')
            
            if not user_info:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not get user information"
                )
            
            # Validate and process user information
            user_data = await self.process_oauth_user(user_info, 'google')
            
            # Create JWT tokens
            access_token = jwt_manager.create_access_token(
                subject=user_data['id'],
                payload={
                    "email": user_data['email'],
                    "name": user_data.get('name'),
                    "provider": 'google'
                }
            )
            
            refresh_token = jwt_manager.create_refresh_token(
                subject=user_data['id']
            )
            
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth error: {str(e)}"
            )
    
    async def process_oauth_user(
        self, 
        user_info: Dict[str, Any], 
        provider: str
    ) -> Dict[str, Any]:
        """Process OAuth user information"""
        # Here you would typically:
        # 1. Check if user exists in your database
        # 2. Create new user if not exists
        # 3. Update existing user information
        
        # For demo purposes, return basic user data
        return {
            "id": user_info.get('sub'),
            "email": user_info.get('email'),
            "name": user_info.get('name'),
            "provider": provider
        }
    
    def validate_scopes(
        self, 
        required_scopes: list, 
        user_scopes: list
    ) -> bool:
        """Validate if user has required scopes"""
        return all(scope in user_scopes for scope in required_scopes)

# OAuth Manager instance
oauth_manager = OAuthManager()

# Dependency for scope-based authorization
def require_scope(required_scope: str):
    """Dependency to require specific scope"""
    async def scope_dependency(
        current_user: Dict[str, Any] = Depends(jwt_manager.get_current_user)
    ) -> Dict[str, Any]:
        user_scopes = current_user.get("scopes", [])
        
        if required_scope not in user_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope}' required"
            )
        
        return current_user
    return scope_dependency
