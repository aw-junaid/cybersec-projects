mindmap
  root((Honeypot Project))
    Overview
      Purpose
        Learn & research
        Capture attack telemetry
        Deception (no execution)
      KeyPrinciples
        Isolated lab only
        No remote code exec
        Log & analyze
        ::icon(fa fa-shield-alt)
    Implementations
      Python
        socketserver Threaded
        hexdump logs
        log rotation
        quick to run
      C
        fork + pthreads
        low-level sockets
        hexdump logs
        performant
    Components
      Listener
        Bind sockets
        Accept connections
      Handler
        Send banners
        Read data (timeout)
        Close socket
      Logger
        Hex + printable dump
        Size-based rotation
      Viewer
        logviewer.js
        logs_viewer.html
        Optional: Flask JSON API
    Features
      Ports & Banners
        SSH-like banner
        HTTP response banner
      DataCapture
        Timestamp, IP, port
        Raw bytes hexdump
      Concurrency
        Threads / pthreads
      Limits
        Max bytes
        Read timeout
    Algorithms
      Init
        Configure ports & banners
      Run
        Create listeners
        Loop: accept -> spawn handler
      HandlerFlow
        Log start
        Send banner
        Receive data until timeout/EOF/limit
        Log hexdump
        Close -> rotate if needed
      Stop
        Graceful shutdown
    Usage
      Kali Setup
        chmod +x honeypot.py
        sudo ./honeypot.py
        gcc honeypot_c.c -o honeypot_c
        sudo ./honeypot_c
      Testing
        nc / curl / nmap / telnet
        tail -f honeypot.log
      ViewerUsage
        python3 -m http.server 8000
        open logs_viewer.html
    Security & Ethics
      Run in VM/container
      Protect logs
      Legal: authorized testing only
      Prevent outbound traffic (iptables)
    Enhancements
      Analysis
        geoip enrichment
        parse & alert script
      Integration
        ELK / Splunk / SIEM
        Flask JSON API for viewer
      Realism
        Fake login prompts (no exec)
        Service emulation
      Hardening
        Rate limiting
        Access controls
    NextSteps
      Add Flask API
      Add search/filter to viewer
      Add automated alerts
      Create deployment container (Docker)
      Mermaid


## How to Run

### Basic Usage:
```bash
# Run with default ports (2222, 8080)
python3 honeypot.py

# For ports below 1024, you need sudo
sudo python3 honeypot.py
```

### Custom Configuration:

1. **Change ports** by modifying the `LISTEN_PORTS` list:
   ```python
   LISTEN_PORTS = [22, 80, 443, 3389]  # Common service ports
   ```

2. **Add custom banners** in the `BANNERS` dictionary:
   ```python
   BANNERS = {
       22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
       80: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
       443: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
   }
   ```

3. **Change log location**:
   ```python
   LOG_FILE = "/var/log/honeypot.log"
   ```

### Testing the Honeypot:

After starting, test it by connecting to the ports:
```bash
# Test SSH port
telnet localhost 2222

# Test HTTP port
curl http://localhost:8080

# Or use netcat
nc localhost 2222
```

### Viewing Logs:
```bash
# Monitor logs in real-time
tail -f honeypot.log

# View entire log
cat honeypot.log
```

### Running as Service (Optional):
For production use, you might want to run it as a service using `systemd` or `supervisord`.

The honeypot will log all connection attempts, including:
- Timestamps
- Source IP and port
- Any data sent by the client (in hexdump format)
- Connection duration

This is great for detecting port scanning, brute force attempts, and other reconnaissance activities.
