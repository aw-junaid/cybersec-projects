# Credential Dump Analyzer - Parse and Make Sense of Leaks


## How to Run the Code

### Python Version
```bash
# Install dependencies
pip install pandas sqlite3

# Analyze credential dumps
python credential_analyzer.py dump1.txt dump2.csv --analyze

# Store results in database
python credential_analyzer.py leaks/*.txt --analyze --store

# Search for specific accounts
python credential_analyzer.py --search "john.doe@company.com"

# Generate report
python credential_analyzer.py credential_dumps/ --analyze --output report.json
```

### C Version
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libsqlite3-dev

# Compile the C program
gcc -o credential_analyzer credential_analyzer.c -lsqlite3

# Analyze credential files
./credential_analyzer user_pass.txt leaked_creds.txt

# Use database for storage
./credential_analyzer --db my_database.db leak1.txt leak2.txt
```

## Sample Analysis Output

```
CREDENTIAL DUMP ANALYSIS REPORT
============================================================

SUMMARY:
  Total credentials: 1,247,382
  Unique users: 893,451
  Unique passwords: 342,167
  Password reuse ratio: 0.27

PASSWORD ANALYSIS:
  Most common passwords:
    Password123: 4,892 occurrences
    123456: 3,451 occurrences
    Company2023!: 2,187 occurrences

  Password strength distribution:
    very_weak: 412,894 (33.1%)
    weak: 389,122 (31.2%)
    medium: 287,456 (23.0%)
    strong: 125,910 (10.1%)
    very_strong: 32,000 (2.6%)

DOMAIN ANALYSIS (Top 10):
    gmail.com: 245,187 credentials
    company.com: 89,456 credentials
    yahoo.com: 67,892 credentials

CREDENTIAL REUSE:
  Password 'Spring2023!' used by 1,245 users: john.doe, jane.smith, ...
  Password 'Company123' used by 892 users: admin, administrator, ...

RECOMMENDATIONS:
  • High percentage of weak passwords (64.3%). Implement stronger password complexity requirements.
  • Found 4,892 instances of common passwords. Consider implementing a password blacklist.
  • Found 342 passwords reused across 12,458 accounts. Implement password history and prevent reuse.
```

## Algorithm Explanation

### Credential Analysis Pipeline:

**1. Multi-Format Parsing:**
```
Supported Formats:
  - Colon/Tab separated (user:pass)
  - JSON/JSONL structures
  - CSV/TSV files
  - SQL database dumps
  - Generic text parsing

Parsing Strategies:
  - Format detection via file extension and content analysis
  - Flexible separator detection (: ; | tab -> =>)
  - JSON path traversal for nested structures
  - SQL INSERT statement parsing
```

**2. Intelligence Extraction:**
```
Data Enrichment:
  - Email address extraction and validation
  - Domain identification from usernames
  - Hash type detection (MD5, SHA1, SHA256, NTLM, bcrypt)
  - Source attribution and metadata preservation

Pattern Analysis:
  - Password frequency and distribution
  - Character composition analysis
  - Common base word identification
  - Seasonal/year-based pattern detection
```

**3. Security Assessment:**
```
Risk Scoring:
  - Password strength evaluation (length, complexity, entropy)
  - Common password identification
  - Credential reuse analysis
  - Domain-specific threat assessment

Threat Intelligence:
  - Compromised account identification
  - Password policy effectiveness
  - Attack pattern recognition
  - Breach correlation across multiple sources
```

## Tool Purpose & Overview

### What is Credential Dump Analysis?
Credential dump analysis involves processing large collections of compromised credentials to extract security intelligence, identify patterns, and assess organizational risk from password breaches.

### Cybersecurity Context: **Defensive Security & Intelligence**

**Primary Uses:**
1. **Threat Intelligence**: Understand attacker tactics and compromised accounts
2. **Incident Response**: Identify breached credentials in your organization
3. **Security Monitoring**: Detect credential stuffing attacks
4. **Password Policy Validation**: Assess effectiveness of current policies
5. **Compliance**: Meet regulatory requirements for credential monitoring

### Real-World Applications:
- **SOC Operations**: Security Operations Center threat detection
- **CERT Teams**: Computer Emergency Response Team investigations
- **Identity Protection**: Monitoring for compromised employee accounts
- **Penetration Testing**: Understanding real-world password patterns
- **Security Research**: Academic and industry password studies

### Legal & Ethical Considerations:

**Authorized Usage:**
- Only analyze data you have legal rights to access
- Obtain proper authorization for organizational data
- Respect data privacy and protection regulations
- Follow responsible disclosure practices

**Data Handling:**
- Secure storage of sensitive credential data
- Proper encryption and access controls
- Limited retention periods
- Secure disposal after analysis

**Ethical Guidelines:**
- Use for defensive security purposes only
- Protect individual privacy
- Share findings responsibly
- Contribute to security community knowledge

### Intelligence Applications:

**Proactive Defense:**
- Identify weak passwords before attackers do
- Implement targeted security controls
- Develop effective password policies
- Train users based on real-world patterns

**Incident Response:**
- Rapid identification of compromised accounts
- Understanding breach scope and impact
- Guiding password reset campaigns
- Preventing credential stuffing attacks

This toolkit provides comprehensive credential analysis capabilities for legitimate security research and defensive operations, helping organizations protect against credential-based attacks and improve their overall security posture.
