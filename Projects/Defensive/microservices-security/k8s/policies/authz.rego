package microservices.authz

import future.keywords.in

default allow = false

# Allow health checks without authentication
allow {
    input.request.method == "GET"
    input.request.path == "/health"
}

# Require valid SPIFFE identity from allowed namespaces
allow {
    valid_spiffe_identity
    allowed_operation
}

valid_spiffe_identity {
    # Extract SPIFFE ID from client certificate
    spiffe_id := input.attributes.source.principal
    startswith(spiffe_id, "spiffe://")
    parts := split(spiffe_id, "/")
    namespace := parts[4]  # spiffe://domain/ns/NAMESPACE/sa/SERVICE
    allowed_namespaces := {"default", "production"}
    namespace in allowed_namespaces
}

allowed_operation {
    # Service A can call Service B's API
    input.attributes.source.principal == "spiffe://example.org/ns/default/sa/service-a"
    input.request.path == "/api/data"
    input.request.method == "GET"
}

# JWT validation for fallback mode
allow {
    valid_jwt_token
}

valid_jwt_token {
    token := input.request.headers.authorization
    # Remove "Bearer " prefix
    jwt := substring(token, 7, -1)
    io.jwt.verify_rs256(jwt)
    claims := io.jwt.decode(jwt)
    claims.payload.iss == "spiffe://example.org/ns/default/sa/service-b"
    claims.payload.aud == ["service-a"]
    now := time.now_ns() / 1000000000
    claims.payload.exp > now
}

# Deny tokens older than 5 minutes
deny[msg] {
    token := input.request.headers.authorization
    jwt := substring(token, 7, -1)
    claims := io.jwt.decode(jwt)
    now := time.now_ns() / 1000000000
    claims.payload.iat < now - 300
    msg := "token too old"
}
