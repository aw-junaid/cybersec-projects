# Password Spraying Automation - Test Credential Reuse Patterns


## How to Run the Code

### Python Version
```bash
# Install dependencies
pip install requests paramiko

# Basic password spraying
python password_sprayer.py --usernames users.txt --passwords passwords.txt --services owa_exchange adfs

# With custom delay
python password_sprayer.py --usernames users.txt --passwords passwords.txt --delay 120

# Safe mode for testing
python password_sprayer.py --usernames users.txt --passwords passwords.txt --safe-mode

# Custom configuration
python password_sprayer.py --usernames users.txt --passwords passwords.txt --config my_config.json
```

### C Version
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libcurl4-openssl-dev

# Compile the C program
gcc -o password_sprayer password_sprayer.c -lcurl

# Run password spraying
./password_sprayer users.txt passwords.txt https://login.company.com 60
```

## Sample Wordlists

### Users.txt
```
admin
administrator
testuser
john.doe
jane.smith
service.account
backup.admin
```

### Passwords.txt
```
Spring2023!
Summer2023!
Company123!
Password123!
Welcome2023!
Winter2023!
Fall2023!
```

## Algorithm Explanation

### Password Spraying Methodology:

**1. Credential Loading & Validation:**
```
1. Load usernames from file (AD users, email addresses, etc.)
2. Load passwords from wordlist (seasonal, company-specific patterns)
3. Validate credential formats and remove duplicates
4. Apply safety checks and rate limiting
```

**2. Service-Specific Authentication:**
```
OWA/Exchange:
  - POST to /owa/auth.owa
  - Monitor for 302 redirects without error parameters
  - Check for successful session cookies

ADFS:
  - Handle SAML authentication flow
  - Extract and submit required form tokens
  - Parse response for success indicators

VPN Portals:
  - Submit credentials to VPN login endpoints
  - Check for portal access or error messages
  - Handle various VPN vendor implementations
```

**3. Rate Limiting & Stealth:**
```
Time-Based Delays:
  - Major delays (60+ seconds) between password changes
  - Minor delays (100-500ms) between user attempts
  - Randomized timing to avoid pattern detection

Stealth Techniques:
  - Rotating User-Agent strings
  - Respecting server rate limits
  - Distributed source IP addresses
  - Mimicking legitimate user behavior
```

**4. Results Analysis & Reporting:**
```
Success Detection:
  - HTTP status code analysis
  - Response content parsing
  - Redirect pattern analysis
  - Session cookie validation

Risk Assessment:
  - Password reuse patterns
  - Account lockout detection
  - Service vulnerability scoring
  - Security control effectiveness
```

## Tool Purpose & Overview

### What is Password Spraying?
Password spraying is a cyber attack technique that attempts to access many accounts (usernames) with a few commonly used passwords, avoiding account lockouts that would occur with traditional brute-force attacks.

### Cybersecurity Context: **Offensive Security**

**Primary Uses:**
1. **Penetration Testing**: Assess organizational password policies
2. **Red Team Exercises**: Simulate real-world attack techniques
3. **Security Validation**: Test authentication controls
4. **Incident Response**: Investigate potential credential compromises

### Real-World Applications:
- **External Security Assessments**: Testing internet-facing services
- **Internal Penetration Tests**: Assessing domain authentication
- **Cloud Security**: Testing SaaS application authentication
- **Compliance Testing**: Meeting regulatory requirements
- **Security Research**: Understanding attack patterns

### Legal & Ethical Considerations:

**Authorization Requirements:**
- Written permission from system owners
- Clear scope definition (which systems, which users)
- Legal review of testing methodology
- Compliance with local computer crime laws

**Safety Protocols:**
- Account lockout prevention mechanisms
- Rate limiting and careful timing
- Immediate cessation upon detection of issues
- Professional conduct throughout testing

**Responsible Disclosure:**
- Secure handling of discovered credentials
- Private reporting to appropriate stakeholders
- Recommendations for security improvements
- Documentation of testing methodology

### Detection & Prevention Strategies:

**Technical Controls:**
- Multi-factor authentication (MFA)
- Account lockout policies
- Anomaly detection systems
- IP address whitelisting/blacklisting
- Password policy enforcement

**Monitoring & Alerting:**
- Failed authentication monitoring
- Geographic anomaly detection
- Time-based pattern analysis
- User behavior analytics

This tool provides comprehensive password spraying capabilities for authorized security testing and should only be used with proper authorization and in compliance with all applicable laws and regulations.
