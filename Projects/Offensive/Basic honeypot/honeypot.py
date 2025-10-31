#!/usr/bin/env python3
"""
honeypot.py - simple threaded TCP honeypot

Features:
- Listens on configurable TCP ports (default [2222, 8080])
- Sends a configurable banner (per-port)
- Logs connection metadata and raw input (hex + safe printable)
- Simple log rotation (size based)

Run:
sudo python3 honeypot.py
"""

import socketserver
import threading
import logging
import time
import os
import binascii
from datetime import datetime

# ===== CONFIGURATION SECTION =====
LISTEN_PORTS = [2222, 8080]   # default ports to listen on
BANNERS = {
    2222: b"SSH-2.0-OpenSSH_7.9p1 Kali-HP\r\n",   # SSH banner to mimic SSH server
    8080: b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",  # HTTP response to mimic web server
}
LOG_FILE = "honeypot.log"          # File where connections will be logged
MAX_LOG_SIZE = 5 * 1024 * 1024     # Rotate log when it reaches 5 MB

READ_TIMEOUT = 8  # seconds to wait for incoming data before closing connection

# ===== LOGGING SETUP =====
# Create logger instance
logger = logging.getLogger("honeypot")
logger.setLevel(logging.INFO)
# File handler to write logs to file
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)

def rotate_logs_if_needed():
    """Check if log file is too big and rotate it if necessary"""
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        # Create timestamp for the rotated log file
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        newname = f"{LOG_FILE}.{ts}"
        os.rename(LOG_FILE, newname)
        # Recreate handler to start fresh log file
        for h in logger.handlers[:]:
            logger.removeHandler(h)
        newh = logging.FileHandler(LOG_FILE)
        newh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(newh)

def hexdump(data: bytes, width=16):
    """Convert binary data to hexdump format for readable logging"""
    # Convert bytes to hex string and split into pairs
    hexed = binascii.hexlify(data).decode()
    parts = [hexed[i:i+2] for i in range(0, len(hexed), 2)]
    lines = []
    
    # Process data in chunks of 'width' bytes
    for i in range(0, len(parts), width):
        chunk = parts[i:i+width]
        hexpart = " ".join(chunk)  # Hex representation
        # Convert back to bytes for printable representation
        raw = bytes.fromhex("".join(chunk))
        # Create printable string (non-printable chars become '.')
        printable = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw])
        lines.append(f"{hexpart:<{width*3}}  {printable}")
    return "\n".join(lines)

class HPHandler(socketserver.BaseRequestHandler):
    """Handler class for each incoming connection"""
    
    def handle(self):
        """Main method called for each connection"""
        # Rotate logs if needed before handling connection
        rotate_logs_if_needed()
        
        # Get connection information
        peer = self.client_address  # (IP, port) of connecting client
        listen_port = self.server.server_address[1]  # Port we're listening on
        banner = BANNERS.get(listen_port, b"")  # Get appropriate banner for this port
        timestamp = datetime.utcnow().isoformat() + "Z"  # Current UTC time

        # Log connection start with metadata
        header = f"=== CONNECTION START ===\ntime: {timestamp}\nremote: {peer[0]}:{peer[1]}\nlocal_port: {listen_port}\n"
        logger.info(header)

        try:
            # Send banner to make service appear legitimate
            if banner:
                try:
                    self.request.sendall(banner)
                except Exception:
                    pass  # Ignore send errors

            # Set timeout to avoid hanging on recv()
            self.request.settimeout(READ_TIMEOUT)
            collected = b""  # Buffer for received data
            
            try:
                # Keep reading data until timeout or connection close
                while True:
                    chunk = self.request.recv(4096)  # Read up to 4KB
                    if not chunk:  # Empty chunk means connection closed
                        break
                    collected += chunk
                    # Stop collecting if we get too much data to avoid huge logs
                    if len(collected) > 200000:
                        break
            except socketserver.socket.timeout:
                pass  # Expected - timeout waiting for more data
            except Exception:
                pass  # Other errors (connection reset, etc.)

            # Log whatever data we received
            if collected:
                logdata = f"--- RAW DATA ({len(collected)} bytes) ---\n{hexdump(collected)}\n"
                logger.info(logdata)
            else:
                logger.info("--- NO DATA RECEIVED ---\n")
                
        finally:
            # Always log connection close and clean up
            footer = f"time_closed: {datetime.utcnow().isoformat()}Z\n=== CONNECTION END ===\n\n"
            logger.info(footer)
            try:
                self.request.close()  # Close the connection
            except Exception:
                pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server that can handle multiple connections simultaneously"""
    allow_reuse_address = True  # Allow quick restart without "address in use" errors

def start_listener(port):
    """Start a listener on specified port"""
    server = ThreadedTCPServer(("0.0.0.0", port), HPHandler)  # Listen on all interfaces
    t = threading.Thread(target=server.serve_forever, daemon=True)  # Run in background thread
    t.start()
    print(f"[+] Listening on 0.0.0.0:{port} (thread {t.name})")
    return server

def main():
    """Main function to start the honeypot"""
    servers = []
    
    # Start listeners for each configured port
    for p in LISTEN_PORTS:
        try:
            s = start_listener(p)
            servers.append(s)
        except PermissionError:
            print(f"Permission error: cannot bind to port {p}. Use ports >=1024 or run with sudo.")
        except Exception as e:
            print(f"Failed to bind {p}: {e}")

    # Exit if no servers started
    if not servers:
        print("No servers started. Exiting.")
        return

    print("Honeypot running. Logs ->", LOG_FILE)
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Clean shutdown on Ctrl+C
        print("Shutting down...")
        for s in servers:
            s.shutdown()
            s.server_close()

if __name__ == "__main__":
    main()
