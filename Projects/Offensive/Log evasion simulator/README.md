# Log Evasion Simulator

## What the Tool is For:
A safe educational environment to study and understand various log evasion techniques used by attackers to avoid detection, covering log manipulation, anti-forensics, and detection avoidance methods.

## About:
This simulator provides a controlled lab environment to learn about log evasion techniques, their detection methods, and defensive strategies without risking real systems.

## General Algorithm:
```
1. Log Generation & Monitoring
   - Simulate system logs (Windows, Linux, Apache, etc.)
   - Real-time log monitoring
   - Alert generation

2. Evasion Technique Simulation
   - Log deletion and modification
   - Timestamp manipulation
   - Log injection and poisoning
   - Steganography in logs
   - Data obfuscation

3. Detection Mechanisms
   - Anomaly detection
   - Integrity checking
   - Pattern recognition
   - Statistical analysis

4. Defense Testing
   - Log protection mechanisms
   - Immutable logging
   - Centralized logging
   - Alert correlation
```

## How to Run the Code:

### Python Version:
```bash
# Install dependencies (if any needed)
pip install -r requirements.txt  # No external dependencies in basic version

# Run complete simulation (5 minutes)
python3 log_evasion_simulator.py --duration 300

# Run specific technique
python3 log_evasion_simulator.py --technique deletion
python3 log_evasion_simulator.py --technique injection

# Custom duration
python3 log_evasion_simulator.py --duration 60
```

### C Version:
```bash
# Compile
gcc -o log_evasion_simulator log_evasion_simulator.c

# Run
./log_evasion_simulator
```

## Example Evasion Techniques:

### 1. Log Deletion:
```bash
# Various deletion methods
rm /var/log/auth.log
echo "" > /var/log/syslog
shred -u sensitive.log
logrotate --force
```

### 2. Timestamp Manipulation:
```bash
# Modify file timestamps
touch -t 202301010000 /var/log/auth.log
# Inject fake timestamps in logs
echo "1970-01-01 00:00:00 kernel: Fake entry" >> /var/log/syslog
```

### 3. Data Obfuscation:
```python
# Base64 encoding
import base64
encoded = base64.b64encode(b"malicious command").decode()
print(f"DEBUG: {encoded}")

# Hex encoding
command = "rm -rf /"
hex_encoded = command.encode().hex()
print(f"Command: {hex_encoded}")
```

### 4. Log Injection:
```python
# Log poisoning
malicious_payload = "<?php system($_GET['cmd']); ?>"
print(f"ERROR: {malicious_payload}")

# Log flooding
print("DEBUG: " + "A" * 10000)
```

## Key Features:

1. **Multiple Evasion Techniques**: Log deletion, timestamp manipulation, data obfuscation, injection, poisoning
2. **Real-time Detection**: Pattern matching and anomaly detection
3. **Educational Scenarios**: Complete attack/defense simulations
4. **Safe Environment**: No risk to real systems
5. **Comprehensive Reporting**: Detailed analysis and recommendations

## Educational Value:

This simulator teaches:
- Log management and security
- Attack detection methodologies
- Forensic analysis techniques
- Security monitoring best practices
- Defense evasion patterns
- Incident response procedures


## Defense Strategies:

```python
DEFENSE_RECOMMENDATIONS = {
    "centralized_logging": "Use SIEM for log aggregation",
    "file_integrity": "Implement checksum monitoring", 
    "immutable_logs": "Use append-only log files",
    "access_controls": "Restrict log file permissions",
    "real_time_analysis": "Deploy log analysis tools",
    "backup_strategy": "Maintain secure log backups",
    "encryption": "Use encrypted log channels",
    "rate_limiting": "Implement log rate controls"
}
```

This log evasion simulator provides a safe environment to understand both offensive evasion techniques and defensive detection strategies, emphasizing the importance of proper log security in comprehensive cybersecurity postures.
