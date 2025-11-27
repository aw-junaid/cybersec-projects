# Rootkit Detection & Removal Toolkit - Heuristics and Scanners

## What this tool is for:
This toolkit detects and removes rootkits using multiple heuristic approaches and scanning techniques. Rootkits are malicious software designed to gain unauthorized access to a system while hiding their presence from normal detection methods.

## Algorithm Overview:
1. **Cross-View Detection**: Compare low-level system views with high-level API views
2. **Signature Scanning**: Check for known rootkit patterns and files
3. **Behavioral Analysis**: Monitor suspicious system activities
4. **Integrity Checking**: Verify system file hashes and digital signatures
5. **Memory Analysis**: Scan running processes and kernel memory
6. **Hook Detection**: Identify API hooks, SSDT hooks, and IAT hooks


## How to Run the Code

### Python Version:
```bash
# Install required dependencies
pip install psutil

# Run the toolkit (Linux/Windows)
python rootkit_scanner.py

# Run with admin privileges for better detection
sudo python rootkit_scanner.py
```

### C Version:
```bash
# Compile the C code (Linux)
gcc -o rootkit_detector rootkit_detector.c
sudo ./rootkit_detector

# Compile with debug information
gcc -g -o rootkit_detector rootkit_detector.c
```

## Detection Techniques Implemented:

### 1. **Cross-View Analysis**
- Compare process lists from `/proc` vs API
- Compare file system views (low-level vs high-level)
- Identify hidden processes and files

### 2. **Signature Scanning**
- Known rootkit file names and patterns
- Suspicious process names
- Network pattern detection

### 3. **Behavioral Analysis**
- Orphan processes (no parent)
- Processes in suspicious locations
- Hidden network ports
- Suspicious kernel modules

### 4. **Integrity Checking**
- System file hash verification
- Permission and ownership checks
- File size anomalies

### 5. **Hook Detection**
- API hook detection (Windows IAT/EAT)
- System call table integrity (Linux)
- Kernel symbol analysis

### 6. **Memory Analysis**
- Process memory pattern scanning
- Suspicious string detection
- Runtime behavior monitoring

## Heuristic Approaches:

1. **Anomaly Detection**: Baseline normal behavior vs current state
2. **Pattern Recognition**: Known malicious code signatures
3. **Behavioral Profiling**: Suspicious activity patterns
4. **Integrity Verification**: Checksum and digital signature validation
5. **Timing Analysis**: Detection latency measurements

## Security Notes:

- Run with appropriate privileges for comprehensive scanning
- Use in authorized environments only
- Some detection methods may trigger antivirus software
- Real rootkits may attempt to hide from detection tools
- Always verify findings with multiple detection methods
