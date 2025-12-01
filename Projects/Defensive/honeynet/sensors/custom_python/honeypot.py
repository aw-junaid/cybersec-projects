#!/usr/bin/env python3
"""
Custom Python Honeypot
Safety Notice: This honeypot must only run in isolated lab environments.
It logs all interactions but has no outbound network access.
"""

import socket
import threading
import logging
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, Any

class CustomHoneypot:
    def __init__(self, host='0.0.0.0', port=8022, service_name='custom_service'):
        self.host = host
        self.port = port
        self.service_name = service_name
        self.logger = self._setup_logging()
        
        # Service banner and responses
        self.banner = b"Welcome to Custom Service v2.1.3\r\n"
        self.commands = {
            b'HELP': b"Available commands: HELP, STATUS, INFO, LIST\r\n",
            b'STATUS': b"Service status: ONLINE\r\nSystem load: 23%\r\n",
            b'INFO': b"Custom Service v2.1.3 - Build 8472\r\n",
            b'LIST': b"file1.txt\tfile2.log\tconfig.conf\r\n",
        }
        
        self.logger.info(f"Initialized {service_name} honeypot on {host}:{port}")
    
    def _setup_logging(self):
        """Setup structured logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(f'honeypot-{self.service_name}')
    
    def _log_interaction(self, client_ip: str, command: bytes, response: bytes):
        """Log all interactions in structured format"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'service': self.service_name,
            'source_ip': client_ip,
            'command': command.decode('utf-8', errors='ignore'),
            'response_hash': hashlib.sha256(response).hexdigest(),
            'response_length': len(response)
        }
        
        self.logger.info(json.dumps(event))
        
        # Also write to local file for agent collection
        with open(f'/var/log/honeypot_{self.service_name}.json', 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def handle_client(self, client_socket: socket.socket, client_address: str):
        """Handle individual client connection"""
        self.logger.info(f"New connection from {client_address}")
        
        try:
            # Send banner
            client_socket.send(self.banner)
            
            while True:
                # Receive command
                data = client_socket.recv(1024)
                if not data:
                    break
                
                # Clean and process command
                command = data.strip().upper()
                
                # Generate response
                if command in self.commands:
                    response = self.commands[command]
                else:
                    response = b"ERROR: Unknown command\r\n"
                
                # Send response
                client_socket.send(response)
                
                # Log interaction
                self._log_interaction(client_address[0], command, response)
                
                # Simulate processing delay
                time.sleep(0.1)
                
        except Exception as e:
            self.logger.error(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            self.logger.info(f"Connection closed from {client_address}")
    
    def start(self):
        """Start the honeypot server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            self.logger.info(f"Honeypot listening on {self.host}:{self.port}")
            
            while True:
                client_socket, client_address = server.accept()
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            server.close()

if __name__ == "__main__":
    # Safety check
    if not os.getenv('HONEY_LAB_MODE'):
        print("ERROR: HONEY_LAB_MODE environment variable not set")
        print("This honeypot can only run in approved lab environments")
        sys.exit(1)
    
    honeypot = CustomHoneypot(
        host='0.0.0.0',
        port=8022,
        service_name='custom_tcp_service'
    )
    honeypot.start()
