# Secure API Authentication Examples - JWT/OAuth Best Practices

## What this tool is for:
A comprehensive implementation of secure API authentication using JWT and OAuth 2.0 with industry best practices. Includes token management, refresh mechanisms, security controls, and protection against common authentication vulnerabilities.

## Security Features:
1. **JWT with secure configuration**
2. **OAuth 2.0 flows (Authorization Code, Client Credentials)**
3. **Refresh token rotation**
4. **Token revocation and blacklisting**
5. **Rate limiting and brute force protection**
6. **Secure cookie handling**
7. **CORS and CSRF protection**
8. **Audit logging**

---

## Python Implementation (FastAPI)

### Project Structure:
```
secure-api-auth/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt.py
│   │   ├── oauth.py
│   │   └── security.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── users.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   └── security.py
│   └── utils/
│       ├── __init__.py
│       └── security.py
├── requirements.txt
└── docker-compose.yml
```


## How to Run

### Python (FastAPI):
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export SECRET_KEY="your-very-secure-secret-key"
export DATABASE_URL="sqlite:///./test.db"
export REDIS_URL="redis://localhost:6379"

# Run the application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Node.js (Express):
```bash
# Install dependencies
npm install express jsonwebtoken bcryptjs express-rate-limit helmet cors redis

# Set environment variables
export JWT_ACCESS_SECRET="your-access-secret"
export JWT_REFRESH_SECRET="your-refresh-secret"

# Run the application
node app.js
```

## Best Practices Implemented:

### JWT Best Practices:
1. **Short-lived access tokens** (15 minutes)
2. **Secure refresh token rotation**
3. **Token blacklisting/revocation**
4. **Proper algorithm selection** (HS256/RS256)
5. **No sensitive data in tokens**
6. **Token expiration validation**

### OAuth 2.0 Best Practices:
1. **Authorization Code flow for web apps**
2. **PKCE for public clients**
3. **Secure token storage**
4. **Proper scope management**
5. **State parameter for CSRF protection**

### Security Controls:
1. **Rate limiting** on authentication endpoints
2. **IP-based blocking** for brute force protection
3. **Secure password hashing** with bcrypt
4. **CORS configuration**
5. **Security headers**
6. **Input validation**
7. **Audit logging**

This implementation provides a robust foundation for secure API authentication following industry best practices and protecting against common vulnerabilities.
