# DNS Spoofing Simulator - Practice Detection/Attack Methods


## How to Run the Code

### Python Version
```bash
# Install dependencies (if any external libraries needed)
pip install -r requirements.txt  # Basic Python stdlib used

# Run simulation mode
python dns_spoofing_simulator.py --mode simulate --duration 60

# Add custom spoof record
python dns_spoofing_simulator.py --mode add-spoof --domain "mydomain.com" --ip "192.168.1.200"

# Run detection analysis
python dns_spoofing_simulator.py --mode detect
```

### C Version
```bash
# Compile the C program
gcc -o dns_spoof_sim dns_spoofing_simulator.c -lpthread

# Run the simulation
./dns_spoof_sim
```

## Algorithm Explanation

### DNS Spoofing Attack Methods:

**1. Cache Poisoning Algorithm:**
```
1. Attacker sends multiple DNS queries to target resolver
2. Simultaneously floods with spoofed responses
3. Uses transaction ID prediction/brute-force
4. Injects malicious records into DNS cache
5. Subsequent queries return spoofed IPs
```

**2. Man-in-the-Middle Algorithm:**
```
1. Intercept DNS queries on network
2. Forge responses with attacker-controlled IPs
3. Maintain session hijacking
4. Bypass DNSSEC validation (if weak implementation)
```

### Detection Methods:

**1. Response Analysis:**
- **TTL Monitoring**: Spoofed responses often have unusual TTL values
- **IP Reputation**: Check against known malicious IP databases
- **Geolocation**: Verify response IP matches expected location

**2. Behavioral Analysis:**
- **Query Frequency**: Detect rapid successive queries (DGA patterns)
- **Temporal Patterns**: Identify unusual query times
- **Client Profiling**: Baseline normal behavior per client

**3. Cryptographic Verification:**
- **DNSSEC Validation**: Verify digital signatures
- **Certificate Pinning**: Validate TLS certificates
- **Response Consistency**: Compare multiple resolver responses

### Simulation Flow:
```
1. Initialize spoofing database with domain->malicious_ip mappings
2. Start multiple client threads generating DNS queries
3. Intercept queries and randomly respond with spoofed/legitimate IPs
4. Detection engine analyzes all responses for spoofing indicators
5. Log all activities and generate detection reports
```

## Tool Purpose & Overview

### What is DNS Spoofing?
DNS spoofing (or DNS cache poisoning) is a cyber attack where corrupt Domain Name System data is introduced into the DNS resolver's cache, causing the name server to return an incorrect IP address and diverting traffic to the attacker's computer.

### Cybersecurity Context: **Both Offensive & Defensive**

**Offensive Uses:**
- Penetration testing DNS security
- Red team exercises
- Security control validation
- Social engineering attacks

**Defensive Uses:**
- IDS/IPS testing
- Security awareness training
- Detection rule development
- Incident response practice

### Real-World Applications:
- **Security Training**: Educate IT staff about DNS threats
- **Product Testing**: Validate DNS security products
- **Research**: Develop new detection algorithms
- **Compliance**: Meet security testing requirements

### Detection Techniques Implemented:

1. **TTL Analysis**: Monitor for unusually short TTL values
2. **IP Reputation**: Check responses against known-bad IPs
3. **Rate Limiting**: Detect query flooding attacks
4. **Response Consistency**: Compare multiple DNS servers
5. **Behavioral Analysis**: Identify anomalous query patterns

### Legal & Ethical Considerations:
- **Authorization Required**: Only use on owned networks
- **Educational Purpose**: Designed for learning and testing
- **Controlled Environment**: Isolate from production networks
- **Compliance**: Follow local cybersecurity laws

### Countermeasures Demonstrated:
- **DNSSEC Implementation**: Cryptographic verification
- **Response Rate Limiting**: Prevent query flooding
- **IP Filtering**: Block known malicious DNS servers
- **Monitoring**: Real-time DNS traffic analysis
- **Client Hardening**: Secure stub resolvers
