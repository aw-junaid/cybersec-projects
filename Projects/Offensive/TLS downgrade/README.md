# TLS Downgrade & MITM Tester

## What the Tool is For:
This tool tests for TLS/SSL vulnerabilities by attempting to force protocol downgrades and simulate Man-in-the-Middle (MITM) attacks to identify weak cipher suites, deprecated protocols, and improper certificate validation.

## About:
TLS downgrade attacks force clients to use weaker encryption protocols, making communications vulnerable to interception. This tool helps security professionals identify misconfigured servers that accept weak protocols or don't properly validate certificates.

## General Algorithm:
```
1. Connect to target server with different TLS versions
2. Attempt protocol downgrade (TLS 1.2 → TLS 1.0 → SSL 3.0)
3. Test weak cipher suites acceptance
4. Simulate certificate validation bypass
5. Check for compression methods (CRIME attack)
6. Analyze certificate chain validation
7. Generate security assessment report
```


## How to Run the Code:

### Python Version:
```bash
# Install dependencies
pip install pyopenssl cryptography

# Run the tool
python3 tls_downgrade_tester.py example.com
python3 tls_downgrade_tester.py --port 8443 192.168.1.1

# Example output will show protocol support and vulnerabilities
```

### C Version:
```bash
# Install OpenSSL development libraries
sudo apt-get install libssl-dev

# Compile the tool
gcc -o tls_tester tls_downgrade_tester.c -lssl -lcrypto

# Run the tool
./tls_tester example.com 443
./tls_tester 192.168.1.1 8443
```

## Key Features Tested:

1. **Protocol Support**: Tests TLS 1.3 down to SSL 2.0
2. **Cipher Suite Analysis**: Identifies weak encryption algorithms
3. **Certificate Validation**: Checks for expired or invalid certificates
4. **Downgrade Attack Simulation**: Attempts to force weaker protocols
5. **Security Reporting**: Generates detailed vulnerability reports

## Educational Value:

This tool helps students understand:
- TLS/SSL protocol handshakes
- Cryptographic weakness identification
- Certificate chain validation
- MITM attack methodologies
- Security assessment reporting

**Note**: Only use this tool on systems you own or have explicit permission to test. Unauthorized testing may be illegal.
