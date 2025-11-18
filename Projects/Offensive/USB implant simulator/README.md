# USB Implant Simulator - Emulate Malicious USB Behaviors in Lab


## How to Run the Code

### Python Version
```bash
# Install dependencies
pip install pyautogui psutil

# List available attack profiles
python usb_implant_simulator.py --list-profiles

# Run a simulation
python usb_implant_simulator.py --simulate basic_keylogger

# Stop current simulation
python usb_implant_simulator.py --stop

# Generate report
python usb_implant_simulator.py --report
```

### C Version
```bash
# Compile the C program
# On Windows:
gcc -o usb_implant_simulator usb_implant_simulator.c

# On Linux:
gcc -o usb_implant_simulator usb_implant_simulator.c

# Run the simulator
./usb_implant_simulator
```

## Educational Content & Safety Guidelines

### USB Attack Vectors Simulated:

**1. BadUSB Attacks:**
- Keyboard injection attacks
- HID spoofing
- Command execution via virtual keyboard
- PowerShell payload delivery

**2. Data Exfiltration:**
- File system exploration
- Sensitive data location
- Compression and archiving
- Network transmission simulation

**3. Persistence Mechanisms:**
- Startup folder manipulation
- Scheduled task creation
- Registry modifications (Windows)
- Service installation simulation

### Safety Features:

**Controlled Environment:**
- All operations are simulated or use safe commands
- No actual malware is deployed
- Network operations limited to localhost
- File operations restricted to temp directories

**Educational Focus:**
- Clear logging of all actions
- Risk assessment for each behavior
- Comprehensive reporting
- Emphasis on detection and prevention

## Algorithm Explanation

### USB Implant Simulation Architecture:

**1. Behavior-Based Simulation:**
```
Attack Profile → Behavior Selection → Safe Execution → Logging & Monitoring
     ↓                ↓                  ↓                  ↓
 Predefined     Specific attack     Controlled       Real-time event
  scenarios       behaviors        environment        tracking
```

**2. Multi-Vector Attack Simulation:**
```
Keyboard Injection:
  - Virtual keyboard input simulation
  - Command prompt automation
  - PowerShell execution simulation

File System Operations:
  - Safe file creation/deletion
  - Directory exploration
  - Data gathering simulation

Network Activities:
  - Localhost network calls
  - DNS query simulation
  - Port scanning simulation

Persistence Mechanisms:
  - Startup configuration
  - Scheduled tasks
  - Registry modifications
```

**3. Monitoring & Detection:**
```
Real-time Monitoring:
  - Process creation tracking
  - Network connection monitoring
  - File system changes
  - System resource usage

Threat Detection:
  - Behavior pattern analysis
  - Anomaly detection
  - Risk scoring
  - Attack timeline reconstruction
```

## Tool Purpose & Overview

### What is USB Implant Simulation?
USB implant simulation involves creating controlled environments to study and understand the behaviors of malicious USB devices, helping security professionals develop detection and prevention strategies.

### Cybersecurity Context: **Defensive Security & Research**

**Primary Uses:**
1. **Security Training**: Educate about USB-based threats
2. **Detection Testing**: Validate security controls and monitoring
3. **Incident Response**: Understand attack patterns for better response
4. **Research**: Study USB attack methodologies in safe environments
5. **Product Development**: Test USB security solutions

### Real-World Applications:
- **Corporate Security**: Employee awareness training
- **Government**: Secure facility protection testing
- **Critical Infrastructure**: USB security validation
- **Digital Forensics**: Attack pattern analysis
- **Security Products**: Anti-malware solution testing

### Legal & Ethical Considerations:

**Authorized Usage Only:**
- Use only in controlled lab environments
- Obtain proper authorization for testing
- Never use on production systems
- Respect privacy and data protection laws

**Safety Protocols:**
- Network isolation during testing
- Regular system snapshots
- Comprehensive logging
- Immediate cleanup after testing

**Educational Purpose:**
- Focus on defensive security
- Document findings for security improvement
- Share knowledge with security community
- Contribute to better security practices

### Detection & Prevention Strategies:

**Technical Controls:**
- USB device whitelisting
- Endpoint protection systems
- Network segmentation
- Behavioral monitoring

**Policy Measures:**
- USB usage policies
- Device authorization procedures
- Regular security audits
- Employee training programs

This simulator provides a safe, controlled environment for understanding USB-based threats and should only be used for legitimate security research, educational purposes, and authorized testing in isolated lab environments.
