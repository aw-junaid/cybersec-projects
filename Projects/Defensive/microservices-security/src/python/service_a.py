from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
import jwt
import ssl
import json
import time
from prometheus_client import Counter, generate_latest, REGISTRY

app = FastAPI(title="Service A")
security = HTTPBearer()

# Metrics
requests_total = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
auth_failures = Counter('auth_failures_total', 'Authentication failures')

# In production, fetch from secure source
JWT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."""
ALLOWED_ISSUER = "spiffe://example.org/ns/default/sa/service-b"

class IdentityValidator:
    @staticmethod
    def validate_jwt(token: str) -> dict:
        try:
            payload = jwt.decode(
                token, 
                JWT_PUBLIC_KEY, 
                algorithms=["RS256"],
                audience=["service-a"],
                issuer=ALLOWED_ISSUER
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
    @staticmethod
    def get_client_cert_identity(request: Request) -> str:
        # Extract SPIFFE ID from client certificate
        if hasattr(request.scope.get('transport', {}), 'get_extra_info'):
            ssl_info = request.scope['transport'].get_extra_info('ssl_object')
            if ssl_info:
                cert = ssl_info.get_peer_certificate()
                if cert:
                    # Extract SPIFFE URI from SAN
                    for i in range(cert.get_extension_count()):
                        ext = cert.get_extension(i)
                        if 'subjectAltName' in str(ext.get_short_name()):
                            if 'URI:spiffe://' in str(ext):
                                return str(ext)
        return None

async def call_service_b(method: str = "mTLS"):
    """Call Service B using either mTLS or JWT fallback"""
    headers = {}
    
    if method == "mTLS":
        # Rely on service mesh mTLS
        url = "https://service-b:8080/api/data"
        # Client certs handled by sidecar
        async with httpx.AsyncClient(verify=False) as client:  # In prod, verify=True with trust bundle
            response = await client.get(url, headers=headers)
    else:
        # Fallback to JWT
        url = "http://service-b:8080/api/data"
        token = jwt.encode({
            "iss": "spiffe://example.org/ns/default/sa/service-a",
            "aud": "service-b", 
            "exp": time.time() + 300,
            "sub": "service-a"
        }, "secret", algorithm="HS256")
        headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
    
    return response.json()

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/api/protected")
async def protected_route(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
):
    # Validate JWT token
    identity = IdentityValidator.validate_jwt(credentials.credentials)
    
    # Also check mTLS identity if available
    cert_identity = IdentityValidator.get_client_cert_identity(request)
    
    requests_total.labels(method="GET", endpoint="/api/protected", status="200").inc()
    
    return {
        "message": "Access granted",
        "jwt_identity": identity,
        "mtls_identity": cert_identity
    }

@app.get("/api/call-b")
async def call_b_endpoint():
    try:
        result = await call_service_b()
        return {"service_b_response": result}
    except Exception as e:
        auth_failures.inc()
        raise HTTPException(status_code=503, detail=f"Service B unavailable: {str(e)}")

@app.get("/metrics")
async def metrics():
    return generate_latest(REGISTRY)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
