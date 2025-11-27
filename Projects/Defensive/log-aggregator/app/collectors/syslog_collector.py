import socketserver
import threading
import logging
import time
from typing import Callable, Dict, Any
import socket

logger = logging.getLogger(__name__)

class SyslogCollector:
    """Collect logs via syslog protocol (UDP and TCP)"""
    
    def __init__(self, config: Dict[str, Any], callback: Callable):
        self.config = config
        self.callback = callback
        self.servers = []
        self.threads = []
        self.running = False
    
    def start(self):
        """Start syslog collection"""
        logger.info("Starting syslog collector...")
        self.running = True
        
        # Start UDP server
        if self.config.get("udp_enabled", True):
            udp_port = self.config.get("udp_port", 514)
            udp_server = ThreadedUDPServer(('0.0.0.0', udp_port), SyslogUDPHandler, self.callback)
            udp_thread = threading.Thread(target=udp_server.serve_forever)
            udp_thread.daemon = True
            udp_thread.start()
            
            self.servers.append(udp_server)
            self.threads.append(udp_thread)
            logger.info(f"Syslog UDP server started on port {udp_port}")
        
        # Start TCP server
        if self.config.get("tcp_enabled", True):
            tcp_port = self.config.get("tcp_port", 1514)
            tcp_server = ThreadedTCPServer(('0.0.0.0', tcp_port), SyslogTCPHandler, self.callback)
            tcp_thread = threading.Thread(target=tcp_server.serve_forever)
            tcp_thread.daemon = True
            tcp_thread.start()
            
            self.servers.append(tcp_server)
            self.threads.append(tcp_thread)
            logger.info(f"Syslog TCP server started on port {tcp_port}")
        
        logger.info("Syslog collector started")
    
    def stop(self):
        """Stop syslog collection"""
        logger.info("Stopping syslog collector...")
        self.running = False
        
        for server in self.servers:
            server.shutdown()
            server.server_close()
        
        for thread in self.threads:
            thread.join(timeout=5)
        
        logger.info("Syslog collector stopped")

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handle UDP syslog messages"""
    
    def __init__(self, request, client_address, server, callback: Callable):
        self.callback = callback
        super().__init__(request, client_address, server)
    
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        
        try:
            message = data.decode('utf-8', errors='ignore')
            client_ip = self.client_address[0]
            
            log_entry = {
                "raw_message": message,
                "source_ip": client_ip,
                "source_type": "syslog_udp",
                "protocol": "udp",
                "timestamp": time.time()
            }
            
            self.callback(log_entry)
            
        except Exception as e:
            logger.error(f"Error processing UDP syslog message: {e}")

class SyslogTCPHandler(socketserver.BaseRequestHandler):
    """Handle TCP syslog messages"""
    
    def __init__(self, request, client_address, server, callback: Callable):
        self.callback = callback
        super().__init__(request, client_address, server)
    
    def handle(self):
        try:
            client_ip = self.client_address[0]
            data = self.request.recv(8192).strip()  # 8KB max message size
            
            while data:
                message = data.decode('utf-8', errors='ignore')
                
                log_entry = {
                    "raw_message": message,
                    "source_ip": client_ip,
                    "source_type": "syslog_tcp",
                    "protocol": "tcp",
                    "timestamp": time.time()
                }
                
                self.callback(log_entry)
                
                # Check for more data (non-blocking)
                self.request.settimeout(0.1)
                try:
                    data = self.request.recv(8192).strip()
                except socket.timeout:
                    data = None
                except Exception:
                    data = None
            
        except Exception as e:
            logger.error(f"Error processing TCP syslog message: {e}")

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Threaded UDP server for syslog"""
    
    def __init__(self, server_address, handler_class, callback: Callable):
        self.callback = callback
        super().__init__(server_address, handler_class)
    
    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass"""
        self.RequestHandlerClass(request, client_address, self, self.callback)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server for syslog"""
    
    def __init__(self, server_address, handler_class, callback: Callable):
        self.callback = callback
        super().__init__(server_address, handler_class)
    
    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass"""
        self.RequestHandlerClass(request, client_address, self, self.callback)
