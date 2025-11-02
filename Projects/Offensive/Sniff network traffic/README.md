## Comprehensive Usage Guide

### Installation & Setup

**1. Install Dependencies:**
```bash
# On Ubuntu/Debian:
sudo apt update && sudo apt install -y python3-scapy

# Or using pip:
pip install scapy
```

**2. Make Script Executable:**
```bash
chmod +x sniffer.py
```

### Basic Usage Examples

**1. Capture All HTTP Traffic:**
```bash
sudo python3 sniffer.py --iface eth0 --bpf "tcp port 80"
```
- Captures HTTP traffic on interface `eth0`
- Shows real-time statistics

**2. Capture Limited Number of Packets:**
```bash
sudo python3 sniffer.py --iface wlan0 --bpf "icmp" --count 50
```
- Captures only 50 ICMP packets
- Automatically stops after 50 packets

**3. Save Capture to PCAP File:**
```bash
sudo python3 sniffer.py --iface eth0 --save my_capture.pcap
```
- Saves all captured packets to `my_capture.pcap`
- File can be opened in Wireshark for detailed analysis

**4. Monitor Top Talkers:**
```bash
sudo python3 sniffer.py --iface any --top 5
```
- Shows top 5 most active IP addresses
- Uses `any` interface to capture all available interfaces

### Advanced Usage

**1. Complex BPF Filters:**
```bash
# Capture only SSH traffic
sudo python3 sniffer.py --iface eth0 --bpf "tcp port 22"

# Capture DNS queries and responses
sudo python3 sniffer.py --iface eth0 --bpf "udp port 53"

# Capture traffic from specific subnet
sudo python3 sniffer.py --iface eth0 --bpf "net 192.168.1.0/24"

# Combine multiple conditions
sudo python3 sniffer.py --iface eth0 --bpf "tcp and (port 80 or port 443)"
```

**2. Long-term Capture with Save:**
```bash
sudo python3 sniffer.py --iface eth0 --save long_capture.pcap --bpf "not port 22"
```
- Captures all non-SSH traffic
- Saves to file for later analysis
- Run until manually stopped with Ctrl+C

### Understanding Output

**Real-time Display:**
```
Pkts:150  Bytes:45920  PPS:25.3  BPS:7733.1  TopTalkers:10
```
- **Pkts**: Total packets captured
- **Bytes**: Total bytes captured  
- **PPS**: Packets per second
- **BPS**: Bytes per second

**Final Summary:**
```
=== Capture Summary =========================
Duration: 15.2s  Packets: 380  Bytes: 145230
Average Rate: 25.0 packets/sec, 9554.6 bytes/sec

Protocol Distribution:
  TCP        :    250 packets
  UDP        :     85 packets
  ICMP       :     45 packets

Top 5 Talkers:
  192.168.1.1     :    120 packets
  192.168.1.100   :     95 packets
  8.8.8.8         :     65 packets
```

### Common Use Cases

**Network Troubleshooting:**
```bash
# Monitor for suspicious traffic
sudo python3 sniffer.py --iface eth0 --bpf "port 23 or port 4444"

# Check for DNS issues
sudo python3 sniffer.py --iface eth0 --bpf "udp port 53" --save dns_debug.pcap
```

**Application Monitoring:**
```bash
# Monitor web traffic
sudo python3 sniffer.py --iface lo --bpf "tcp port 8080" --top 10

# Capture database traffic
sudo python3 sniffer.py --iface eth0 --bpf "port 5432"
```

**Security Analysis:**
```bash
# Capture all traffic for analysis
sudo python3 sniffer.py --iface eth0 --save security_audit.pcap

# Monitor for port scanning
sudo python3 sniffer.py --iface any --bpf "tcp and not port 22"
```

### Important Notes

1. **Root Privileges Required**: Always run with `sudo` for raw packet capture
2. **Interface Selection**: Use `ip link show` to see available interfaces
3. **BPF Syntax**: Uses standard tcpdump filter syntax
4. **Storage**: PCAP files can grow quickly - monitor disk space
5. **Legal Use**: Only use on networks you own or have permission to monitor

### Tips for Effective Use

- Start with specific filters to avoid information overload
- Use `--save` option for important captures to analyze later
- Combine with `tcpdump` or Wireshark for deeper analysis
- Use `--count` for automated captures to prevent running indefinitely
- Monitor the "Top Talkers" section to identify bandwidth hogs

This sniffer provides a powerful yet simple way to monitor and analyze network traffic for debugging, security, and educational purposes.
