import socket
import threading
import time
import json
import logging
from datetime import datetime
from pathlib import Path
import asyncio
import aiofiles

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LogCollector:
    def __init__(self, storage_handler):
        self.storage_handler = storage_handler
        self.collectors = []
        self.running = False
    
    def start_collectors(self):
        """Start all log collectors"""
        self.running = True
        
        # Start syslog collectors
        for source in self.storage_handler.settings.LOG_SOURCES:
            if source["type"] == "syslog":
                collector = SyslogCollector(
                    source["name"],
                    source["port"],
                    source.get("protocol", "udp"),
                    self.storage_handler
                )
                collector.start()
                self.collectors.append(collector)
                logger.info(f"Started syslog collector for {source['name']} on port {source['port']}")
            
            elif source["type"] == "file":
                collector = FileLogCollector(
                    source["name"],
                    source["path"],
                    self.storage_handler
                )
                collector.start()
                self.collectors.append(collector)
                logger.info(f"Started file collector for {source['name']} at {source['path']}")
    
    def stop_collectors(self):
        """Stop all log collectors"""
        self.running = False
        for collector in self.collectors:
            collector.stop()
        logger.info("All log collectors stopped")

class SyslogCollector(threading.Thread):
    def __init__(self, source_name, port, protocol="udp", storage_handler=None):
        super().__init__()
        self.source_name = source_name
        self.port = port
        self.protocol = protocol.lower()
        self.storage_handler = storage_handler
        self.running = False
        self.daemon = True
        
        # Create socket
        if self.protocol == "udp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def run(self):
        """Start collecting syslog messages"""
        self.running = True
        try:
            self.socket.bind(('0.0.0.0', self.port))
            if self.protocol == "tcp":
                self.socket.listen(5)
                self._handle_tcp_connections()
            else:
                self._handle_udp_messages()
        except Exception as e:
            logger.error(f"Syslog collector error: {e}")
        finally:
            self.socket.close()
    
    def _handle_udp_messages(self):
        """Handle UDP syslog messages"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(8192)
                message = data.decode('utf-8', errors='ignore').strip()
                self._process_message(message, addr[0])
            except Exception as e:
                logger.error(f"Error processing UDP message: {e}")
    
    def _handle_tcp_connections(self):
        """Handle TCP syslog connections"""
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting TCP connection: {e}")
    
    def _handle_tcp_client(self, client_socket, addr):
        """Handle individual TCP client connection"""
        try:
            while self.running:
                data = client_socket.recv(8192)
                if not data:
                    break
                message = data.decode('utf-8', errors='ignore').strip()
                self._process_message(message, addr[0])
        except Exception as e:
            logger.error(f"Error handling TCP client: {e}")
        finally:
            client_socket.close()
    
    def _process_message(self, message, source_ip):
        """Process and store syslog message"""
        try:
            event = {
                "timestamp": datetime.utcnow(),
                "source_ip": source_ip,
                "source": self.source_name,
                "raw_log": message,
                "event_type": "syslog",
                "severity": "info"
            }
            
            # Parse syslog message (basic parsing)
            if message.startswith("<"):
                # Parse PRI part
                end_pri = message.find(">")
                if end_pri != -1:
                    pri = message[1:end_pri]
                    try:
                        pri_int = int(pri)
                        facility = pri_int // 8
                        severity_code = pri_int % 8
                        
                        # Map severity codes to levels
                        severity_map = {
                            0: "emergency", 1: "alert", 2: "critical",
                            3: "error", 4: "warning", 5: "notice",
                            6: "info", 7: "debug"
                        }
                        event["severity"] = severity_map.get(severity_code, "info")
                        
                        # Extract message content
                        event["message"] = message[end_pri + 1:].strip()
                    except ValueError:
                        event["message"] = message
            else:
                event["message"] = message
            
            # Store event
            if self.storage_handler:
                self.storage_handler.store_event(event)
                
        except Exception as e:
            logger.error(f"Error processing syslog message: {e}")
    
    def stop(self):
        """Stop the collector"""
        self.running = False
        self.socket.close()

class FileLogCollector(threading.Thread):
    def __init__(self, source_name, file_path, storage_handler=None):
        super().__init__()
        self.source_name = source_name
        self.file_path = Path(file_path)
        self.storage_handler = storage_handler
        self.running = False
        self.daemon = True
        self.last_position = 0
    
    def run(self):
        """Start monitoring log file"""
        self.running = True
        
        # Check if file exists
        if not self.file_path.exists():
            logger.error(f"Log file not found: {self.file_path}")
            return
        
        # Get initial file size
        self.last_position = self.file_path.stat().st_size
        
        while self.running:
            try:
                current_size = self.file_path.stat().st_size
                
                if current_size < self.last_position:
                    # File was rotated
                    self.last_position = 0
                
                if current_size > self.last_position:
                    # Read new content
                    with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                        self.last_position = f.tell()
                    
                    # Process new lines
                    for line in new_lines:
                        self._process_line(line.strip())
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error monitoring log file: {e}")
                time.sleep(5)
    
    def _process_line(self, line):
        """Process a single log line"""
        try:
            event = {
                "timestamp": datetime.utcnow(),
                "source": self.source_name,
                "raw_log": line,
                "event_type": "file_log",
                "severity": "info"
            }
            
            # Basic parsing based on common log formats
            if "ERROR" in line.upper():
                event["severity"] = "error"
            elif "WARN" in line.upper():
                event["severity"] = "warning"
            elif "CRITICAL" in line.upper():
                event["severity"] = "critical"
            
            event["message"] = line
            
            # Extract IP addresses (basic pattern)
            import re
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, line)
            if ips:
                event["source_ip"] = ips[0] if len(ips) > 0 else None
                event["destination_ip"] = ips[1] if len(ips) > 1 else None
            
            # Store event
            if self.storage_handler:
                self.storage_handler.store_event(event)
                
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
    
    def stop(self):
        """Stop the collector"""
        self.running = False
