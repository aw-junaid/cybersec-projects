# Bluetooth Protocol Tester - Scan/Exploit Bluetooth Services


## How to Run the Code

### Python Version
```bash
# Install dependencies
sudo apt-get install bluetooth libbluetooth-dev
pip install pybluez

# Scan for nearby devices
python bluetooth_tester.py --scan

# Scan services on specific device
python bluetooth_tester.py --target XX:XX:XX:XX:XX:XX --services

# RFCOMM port scanning
python bluetooth_tester.py --target XX:XX:XX:XX:XX:XX --rfcomm-scan

# L2CAP PSM scanning  
python bluetooth_tester.py --target XX:XX:XX:XX:XX:XX --l2cap-scan

# Bluetooth stack fingerprinting
python bluetooth_tester.py --target XX:XX:XX:XX:XX:XX --fingerprint

# BlueBorne vulnerability testing
python bluetooth_tester.py --target XX:XX:XX:XX:XX:XX --blueborne

# Generate report
python bluetooth_tester.py --target XX:XX:XX:XX:XX:XX --services --report scan_results.json
```

### C Version
```bash
# Compile the C program
gcc -o bluetooth_tester bluetooth_tester.c -lbluetooth

# Scan for devices
sudo ./bluetooth_tester --scan

# Show adapter info
sudo ./bluetooth_tester --info

# RFCOMM scan on target
sudo ./bluetooth_tester --target XX:XX:XX:XX:XX:XX --rfcomm-scan

# L2CAP scan on target
sudo ./bluetooth_tester --target XX:XX:XX:XX:XX:XX --l2cap-scan

# Simulate DoS test (educational)
sudo ./bluetooth_tester --target XX:XX:XX:XX:XX:XX --dos-sim
```

## Algorithm Explanation

### Bluetooth Security Testing Methodology:

**1. Device Discovery:**
```
1. HCI Inquiry: Send Bluetooth inquiry packets
2. Device Enumeration: Collect responding device addresses and names
3. Classification: Identify device types based on names and classes
4. Signal Strength: Optional RSSI measurement for proximity
```

**2. Service Discovery:**
```
1. SDP Queries: Query Service Discovery Protocol on target devices
2. Service Enumeration: List all available services and profiles
3. Protocol Identification: Identify RFCOMM, L2CAP, OBEX services
4. Port/PSM Mapping: Map services to specific channels/ports
```

**3. Vulnerability Assessment:**
```
BlueBorne Vectors:
  - L2CAP Buffer Overflow: Send oversized L2CAP packets
  - SDP Information Disclosure: Extract sensitive service info
  - PIN Weakness: Test common default PINs

General Security Checks:
  - Open Ports: Unauthenticated service access
  - Information Leakage: Service names, device info
  - Denial of Service: Resource exhaustion tests
```

**4. Protocol-Specific Testing:**
```
RFCOMM Testing:
  - Channel scanning (1-30)
  - Protocol fuzzing
  - Authentication bypass

L2CAP Testing:
  - PSM scanning (1-100, 1001-1024)
  - MTU manipulation
  - Connection flooding

SDP Testing:
  - Service enumeration
  - Attribute extraction
  - Service hijacking detection
```

### Advanced Testing Techniques:

**Man-in-the-Middle Simulation:**
- L2CAP connection interception
- RFCOMM session hijacking
- BNEP network bridging

**Fuzzing Strategies:**
- Protocol field fuzzing
- Stateful fuzzing with session maintenance
- Model-based fuzzing for specific profiles

**Cryptographic Analysis:**
- Pairing mechanism testing
- Key exchange vulnerabilities
- Encryption strength assessment

## Tool Purpose & Overview

### What is Bluetooth Security Testing?
Bluetooth security testing involves assessing Bluetooth-enabled devices and protocols for vulnerabilities that could lead to unauthorized access, data theft, or device compromise.

### Cybersecurity Context: **Offensive Security**

**Primary Uses:**
1. **Penetration Testing**: Security assessment of Bluetooth implementations
2. **Vulnerability Research**: Discovering new Bluetooth vulnerabilities
3. **Product Security**: Testing commercial Bluetooth devices
4. **Incident Response**: Investigating Bluetooth-based attacks

### Real-World Applications:
- **IoT Devices**: Smart home devices, wearables, medical devices
- **Mobile Security**: Smartphones, tablets, laptops
- **Automotive**: Car infotainment systems, keyless entry
- **Industrial**: Bluetooth-enabled sensors and controllers
- **Consumer Electronics**: Headsets, speakers, peripherals

### Common Bluetooth Vulnerabilities:

1. **BlueBorne**: Airborne attacks requiring no user interaction
2. **BLESA**: Bluetooth Low Energy Spoofing Attacks
3. **KNOB Attack**: Key Negotiation Of Bluetooth
4. **BIAS Attack**: Bluetooth Impersonation AttackS
5. **Pairing Flaws**: Weak PINs, lack of authentication
6. **Information Disclosure**: Through SDP or device names

### Testing Methodology:

**Reconnaissance Phase:**
- Device discovery and classification
- Service enumeration
- Protocol identification

**Vulnerability Assessment:**
- Known vulnerability testing
- Protocol fuzzing
- Authentication bypass attempts

**Exploitation Phase:**
- Proof-of-concept development
- Privilege escalation testing
- Persistence mechanisms

### Legal & Ethical Considerations:
- **Authorization**: Only test owned or authorized devices
- **Responsible Disclosure**: Report vulnerabilities to vendors
- **Regulatory Compliance**: Follow local radio frequency regulations
- **Privacy Protection**: Avoid intercepting personal communications

### Countermeasures & Best Practices:
- **Device Visibility**: Set to non-discoverable when not needed
- **Authentication**: Use strong pairing mechanisms
- **Encryption**: Enable encryption for all sensitive communications
- **Firmware Updates**: Regular security patches
- **Service Hardening**: Disable unused services and profiles

This tool provides comprehensive Bluetooth security testing capabilities for educational and authorized security assessment purposes, helping identify and mitigate Bluetooth-related security risks.
