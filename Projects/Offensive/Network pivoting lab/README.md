# Network Pivoting Lab Scripts

## What the Tool is For:
A comprehensive network pivoting simulation framework that demonstrates lateral movement techniques, post-exploitation tactics, and multi-hop network traversal for red team exercises and penetration testing training.

## About:
Network pivoting involves using compromised systems as footholds to access otherwise inaccessible network segments. This lab provides automated scripts to simulate common pivoting techniques across various network scenarios.

## General Algorithm:
```
1. Network Discovery & Mapping
   - Host discovery and enumeration
   - Network topology mapping
   - Service identification

2. Initial Compromise
   - Exploit demonstration
   - Initial access establishment
   - Foothold maintenance

3. Lateral Movement
   - Credential harvesting and reuse
   - Pass-the-hash/ticket attacks
   - Service exploitation

4. Pivoting Techniques
   - SSH tunneling
   - SOCKS proxies
   - Port forwarding
   - VPN pivoting

5. Persistence & Control
   - Backdoor installation
   - C2 channel establishment
   - Persistence mechanisms
```

## How to Run the Code:

### Python Version:
```bash
# Install dependencies
pip install paramiko scapy

# Run complete scenario
python3 pivoting_lab.py --scenario

# Individual commands
python3 pivoting_lab.py --scan 10.0.2.0/24
python3 pivoting_lab.py --exploit 10.0.1.10 http
python3 pivoting_lab.py --tunnel 10.0.1.10 10.0.2.10 3306 3306
python3 pivoting_lab.py --socks 10.0.1.10 1080
python3 pivoting_lab.py --topology
```

### C Version:
```bash
# Compile
gcc -o pivoting_lab pivoting_lab.c -lpthread

# Run
./pivoting_lab
```

## Example Pivoting Scenarios:

### 1. SSH Pivoting:
```bash
# Local port forwarding
ssh -L 8080:internal-server:80 user@jump-host

# Dynamic SOCKS proxy
ssh -D 1080 user@jump-host

# Remote port forwarding  
ssh -R 3389:internal-server:3389 user@jump-host
```

### 2. Metasploit Pivoting:
```msf
# Add route through compromised host
route add 10.0.2.0 255.255.255.0 1

# Setup SOCKS proxy
use auxiliary/server/socks_proxy
set VERSION 4a
run

# Use with proxychains
proxychains nmap -sT 10.0.2.10
```

### 3. Windows Lateral Movement:
```powershell
# PsExec
PsExec.exe \\target-pc -u domain\user -p password cmd.exe

# WMI
Get-WmiObject -Class Win32_Process -ComputerName target-pc -Credential $cred

# PowerShell Remoting
Enter-PSSession -ComputerName target-pc -Credential $cred
```

## Key Features:

1. **Multi-Stage Pivoting**: Simulates complex network traversal
2. **Various Techniques**: SSH tunneling, SOCKS proxies, port forwarding
3. **Credential Attacks**: Pass-the-hash, credential reuse
4. **Lateral Movement**: Multiple techniques for horizontal spread
5. **Network Discovery**: Automated host and service enumeration
6. **Educational Scenarios**: Complete attack chain demonstrations

## Educational Value:

This lab teaches:
- Network segmentation and security
- Post-exploitation techniques
- Lateral movement methodologies
- Pivoting and tunneling concepts
- Defense evasion strategies
- Network security monitoring

## Common Pivoting Tools:

```python
PIVOTING_TOOLS = {
    "ssh": "Secure Shell tunneling",
    "proxychains": "SOCKS proxy wrapper", 
    "netsh": "Windows port forwarding",
    "socat": "Multipurpose relay",
    "plink": "Windows SSH client",
    "chisel": "Fast TCP/UDP tunnel",
    "dnscat2": "DNS tunneling",
    "iodine": "IP over DNS"
}
```
