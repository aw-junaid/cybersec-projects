#!/usr/bin/env python3
"""
IoT Device Fuzzing Tool
Purpose: Fuzz various IoT protocols to discover vulnerabilities
Use: Security testing of IoT devices, protocol implementation validation
"""

import socket
import struct
import random
import time
import threading
import argparse
import json
import os
from datetime import datetime
from collections import defaultdict, deque

class IoTFuzzer:
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.crash_log = []
        self.fuzz_cases = deque()
        self.is_fuzzing = False
        self.timeout = 5
        self.protocol = "HTTP"  # Default protocol
        
    def generate_fuzz_cases(self, base_payload, fuzz_type="all"):
        """
        Generate various fuzz test cases based on payload type
        """
        fuzz_cases = []
        
        # Basic boundary values
        boundary_cases = [
            b"",  # Empty
            b"A" * 1000,  # Long string
            b"A" * 10000,  # Very long string
            b"\x00" * 100,  # Null bytes
            b"\xff" * 100,  # Max bytes
        ]
        
        # Format string attacks
        format_strings = [
            b"%s" * 100,
            b"%x" * 100,
            b"%n" * 50,
            b"%p" * 50,
        ]
        
        # Integer overflow cases
        integer_cases = [
            struct.pack("<I", 0xFFFFFFFF),  # Max uint32
            struct.pack("<I", 0),  # Zero
            struct.pack("<I", 0x7FFFFFFF),  # Max int32
            struct.pack("<I", 0x80000000),  # Min int32
        ]
        
        # Command injection patterns
        command_injections = [
            b"; ls -la",
            b"| cat /etc/passwd",
            b"`id`",
            b"$(whoami)",
            b"&& reboot",
        ]
        
        # SQL injection patterns
        sql_injections = [
            b"' OR '1'='1",
            b"'; DROP TABLE users; --",
            b" UNION SELECT 1,2,3 --",
            b"' AND 1=1 --",
        ]
        
        # Combine based on fuzz type
        if fuzz_type in ["all", "boundary"]:
            fuzz_cases.extend(boundary_cases)
        if fuzz_type in ["all", "format"]:
            fuzz_cases.extend(format_strings)
        if fuzz_type in ["all", "integer"]:
            fuzz_cases.extend(integer_cases)
        if fuzz_type in ["all", "injection"]:
            fuzz_cases.extend(command_injections)
            fuzz_cases.extend(sql_injections)
        
        # Generate mutated versions of base payload
        for case in fuzz_cases[:20]:  # Limit number of cases
            mutated = self.mutate_payload(base_payload, case)
            fuzz_cases.append(mutated)
        
        return fuzz_cases
    
    def mutate_payload(self, base_payload, fuzz_value):
        """
        Mutate base payload with fuzz value at random positions
        """
        if not base_payload:
            return fuzz_value
        
        # Convert to bytes if string
        if isinstance(base_payload, str):
            base_payload = base_payload.encode()
        if isinstance(fuzz_value, str):
            fuzz_value = fuzz_value.encode()
        
        # Insert fuzz value at random position
        if len(base_payload) > 0:
            position = random.randint(0, len(base_payload))
            mutated = base_payload[:position] + fuzz_value + base_payload[position:]
        else:
            mutated = fuzz_value
        
        return mutated
    
    def http_fuzzer(self, path="/", method="GET", headers=None, data=None):
        """
        Fuzz HTTP/HTTPS endpoints common in IoT devices
        """
        if headers is None:
            headers = {}
        if data is None:
            data = b""
        
        base_request = f"{method} {path} HTTP/1.1\r\nHost: {self.target_ip}\r\n"
        for header, value in headers.items():
            base_request += f"{header}: {value}\r\n"
        base_request += "\r\n"
        
        if data:
            base_request = base_request.encode() + data
        else:
            base_request = base_request.encode()
        
        fuzz_cases = self.generate_fuzz_cases(base_request)
        
        print(f"[HTTP] Starting HTTP fuzzing on {self.target_ip}:{self.target_port}")
        self.run_fuzz_cases(fuzz_cases, "HTTP")
    
    def mqtt_fuzzer(self):
        """
        Fuzz MQTT protocol commonly used in IoT messaging
        """
        # MQTT Connect packet base
        client_id = "fuzzer_client"
        base_connect = bytearray([
            0x10,  # CONNECT packet type
            0x00,  # Remaining length (will be calculated)
            0x00, 0x04,  # Protocol name length
            0x4d, 0x51, 0x54, 0x54,  # "MQTT"
            0x04,  # Protocol level 4
            0x02,  # Connect flags (clean session)
            0x00, 0x3c,  # Keep alive (60 seconds)
        ])
        
        # Add client ID
        client_id_bytes = client_id.encode()
        base_connect.extend([len(client_id_bytes)])
        base_connect.extend(client_id_bytes)
        
        # Update remaining length
        base_connect[1] = len(base_connect) - 2
        
        fuzz_cases = self.generate_fuzz_cases(bytes(base_connect))
        
        print(f"[MQTT] Starting MQTT fuzzing on {self.target_ip}:{self.target_port}")
        self.run_fuzz_cases(fuzz_cases, "MQTT")
    
    def coap_fuzzer(self):
        """
        Fuzz CoAP protocol used in constrained IoT devices
        """
        # Basic CoAP GET request
        base_coap = bytearray([
            0x40,  # Version 1, CON, no token
            0x01,  # GET method
            0x00, 0x01,  # Message ID
            0xb1,  # Uri-Path option
            0x74, 0x65, 0x73, 0x74  # "test"
        ])
        
        fuzz_cases = self.generate_fuzz_cases(bytes(base_coap))
        
        print(f"[CoAP] Starting CoAP fuzzing on {self.target_ip}:{self.target_port}")
        self.run_fuzz_cases(fuzz_cases, "CoAP")
    
    def udp_fuzzer(self, base_payload=b"TEST"):
        """
        Generic UDP protocol fuzzing
        """
        fuzz_cases = self.generate_fuzz_cases(base_payload)
        
        print(f"[UDP] Starting UDP fuzzing on {self.target_ip}:{self.target_port}")
        self.run_fuzz_cases(fuzz_cases, "UDP", socket.SOCK_DGRAM)
    
    def tcp_fuzzer(self, base_payload=b"TEST"):
        """
        Generic TCP protocol fuzzing
        """
        fuzz_cases = self.generate_fuzz_cases(base_payload)
        
        print(f"[TCP] Starting TCP fuzzing on {self.target_ip}:{self.target_port}")
        self.run_fuzz_cases(fuzz_cases, "TCP", socket.SOCK_STREAM)
    
    def run_fuzz_cases(self, fuzz_cases, protocol, socket_type=socket.SOCK_STREAM):
        """
        Execute fuzz cases against target
        """
        self.is_fuzzing = True
        crash_count = 0
        case_count = 0
        
        for fuzz_payload in fuzz_cases:
            if not self.is_fuzzing:
                break
                
            case_count += 1
            print(f"[{protocol}] Test case {case_count}/{len(fuzz_cases)}: {len(fuzz_payload)} bytes")
            
            try:
                if socket_type == socket.SOCK_STREAM:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((self.target_ip, self.target_port))
                    sock.send(fuzz_payload)
                    
                    try:
                        response = sock.recv(1024)
                        print(f"  Response: {len(response)} bytes")
                    except socket.timeout:
                        print("  No response (timeout)")
                    except Exception as e:
                        print(f"  Receive error: {e}")
                    
                    sock.close()
                    
                else:  # UDP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    sock.sendto(fuzz_payload, (self.target_ip, self.target_port))
                    
                    try:
                        response, addr = sock.recvfrom(1024)
                        print(f"  Response: {len(response)} bytes from {addr}")
                    except socket.timeout:
                        print("  No response (timeout)")
                    except Exception as e:
                        print(f"  Receive error: {e}")
                    
                    sock.close()
                
                # Small delay to avoid overwhelming the device
                time.sleep(0.1)
                
            except Exception as e:
                crash_count += 1
                crash_info = {
                    'timestamp': datetime.now().isoformat(),
                    'protocol': protocol,
                    'case_number': case_count,
                    'payload_length': len(fuzz_payload),
                    'payload_preview': fuzz_payload[:100] if len(fuzz_payload) > 100 else fuzz_payload,
                    'error': str(e)
                }
                self.crash_log.append(crash_info)
                
                print(f"  [CRASH] Potential vulnerability detected!")
                print(f"    Error: {e}")
                print(f"    Payload: {fuzz_payload[:50]}...")
        
        print(f"[{protocol}] Fuzzing completed. Crashes detected: {crash_count}")
        self.is_fuzzing = False
    
    def smart_home_fuzzer(self):
        """
        Specialized fuzzer for common smart home protocols
        """
        print("[SmartHome] Starting smart home protocol fuzzing")
        
        # ZigBee-like payloads (simplified)
        zigbee_payloads = [
            b"\x01\x02\x03\x04",  # Basic frame
            b"\xff" * 50,  # Max values
            b"\x00" * 100,  # Null frame
        ]
        
        # Z-Wave-like payloads (simplified)
        zwave_payloads = [
            b"\x01\x07\x00\x13",  # Basic command
            b"\xff\xff\xff\xff",  # Broadcast
        ]
        
        # Bluetooth Low Energy (simplified)
        ble_payloads = [
            b"\x02\x01\x06",  # Advertising data
            b"\x11\x07",  # Service data
        ]
        
        all_payloads = zigbee_payloads + zwave_payloads + ble_payloads
        fuzz_cases = []
        
        for payload in all_payloads:
            fuzz_cases.extend(self.generate_fuzz_cases(payload, "boundary"))
        
        self.run_fuzz_cases(fuzz_cases, "SmartHome", socket.SOCK_DGRAM)
    
    def save_results(self, filename=None):
        """Save fuzzing results to file"""
        if filename is None:
            filename = f"fuzz_results_{self.target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        results = {
            'target': f"{self.target_ip}:{self.target_port}",
            'timestamp': datetime.now().isoformat(),
            'crashes_found': len(self.crash_log),
            'crash_details': self.crash_log
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Results saved to {filename}")
    
    def stop_fuzzing(self):
        """Stop ongoing fuzzing operations"""
        self.is_fuzzing = False
        print("Fuzzing stopped by user")

class AdvancedIoTFuzzer(IoTFuzzer):
    """
    Advanced fuzzer with stateful protocol support and intelligent mutation
    """
    
    def __init__(self, target_ip, target_port=80):
        super().__init__(target_ip, target_port)
        self.session_state = {}
        self.learned_protocol = None
        
    def protocol_learning(self, sample_traffic=None):
        """
        Learn protocol structure from sample traffic
        """
        print("[Learning] Analyzing protocol structure...")
        
        # Simple pattern recognition (enhanced in real implementation)
        if sample_traffic:
            if b"HTTP" in sample_traffic:
                self.learned_protocol = "HTTP"
            elif b"MQTT" in sample_traffic:
                self.learned_protocol = "MQTT"
            elif len(sample_traffic) < 10 and sample_traffic[0] in [0x40, 0x60]:
                self.learned_protocol = "CoAP"
            else:
                self.learned_protocol = "Custom"
        
        print(f"[Learning] Detected protocol: {self.learned_protocol}")
        return self.learned_protocol
    
    def stateful_http_fuzzer(self, login_sequence=None):
        """
        Stateful HTTP fuzzing with session maintenance
        """
        if login_sequence is None:
            # Default login sequence for common IoT devices
            login_sequence = [
                ("POST /login.php", b"username=admin&password=admin"),
                ("GET /status.php", b""),
            ]
        
        print("[StatefulHTTP] Starting stateful HTTP fuzzing")
        
        # Establish session
        session = requests.Session() if self.use_requests else None
        cookies = {}
        
        # Execute login sequence
        for endpoint, data in login_sequence:
            try:
                if session:
                    if data:
                        response = session.post(f"http://{self.target_ip}{endpoint.split(' ')[1]}", 
                                              data=data, timeout=self.timeout)
                    else:
                        response = session.get(f"http://{self.target_ip}{endpoint.split(' ')[1]}", 
                                             timeout=self.timeout)
                    cookies = session.cookies.get_dict()
                else:
                    # Raw socket implementation
                    pass
                    
            except Exception as e:
                print(f"  Session setup failed: {e}")
                return
        
        # Fuzz authenticated endpoints
        auth_endpoints = ["/config", "/admin", "/settings", "/update"]
        for endpoint in auth_endpoints:
            base_request = f"GET {endpoint} HTTP/1.1\r\nHost: {self.target_ip}\r\n"
            if cookies:
                cookie_header = "Cookie: " + "; ".join([f"{k}={v}" for k, v in cookies.items()]) + "\r\n"
                base_request += cookie_header
            base_request += "\r\n"
            
            fuzz_cases = self.generate_fuzz_cases(base_request.encode())
            self.run_fuzz_cases(fuzz_cases, "StatefulHTTP")
    
    def intelligent_mutation(self, base_payload, iterations=10):
        """
        Intelligent payload mutation based on protocol semantics
        """
        mutated_payloads = []
        
        for i in range(iterations):
            mutated = bytearray(base_payload)
            
            # Random bit flipping
            for _ in range(max(1, len(mutated) // 10)):
                if mutated:
                    pos = random.randint(0, len(mutated) - 1)
                    mutated[pos] ^= random.randint(1, 255)
            
            # Field boundary manipulation
            if len(mutated) > 4:
                # Manipulate potential length fields
                for pos in range(len(mutated) - 2):
                    if mutated[pos] == len(mutated) - pos - 1:
                        mutated[pos] = random.randint(0, 255)
            
            mutated_payloads.append(bytes(mutated))
        
        return mutated_payloads

def main():
    parser = argparse.ArgumentParser(description='IoT Device Fuzzing Tool')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=80, help='Target port')
    parser.add_argument('--protocol', choices=['http', 'mqtt', 'coap', 'udp', 'tcp', 'smarthome', 'all'], 
                       default='http', help='Protocol to fuzz')
    parser.add_argument('--timeout', type=float, default=5, help='Socket timeout')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    print(f"IoT Fuzzing Tool targeting {args.target}:{args.port}")
    print("=" * 50)
    
    fuzzer = IoTFuzzer(args.target, args.port)
    fuzzer.timeout = args.timeout
    
    try:
        if args.protocol == 'http' or args.protocol == 'all':
            fuzzer.http_fuzzer()
        
        if args.protocol == 'mqtt' or args.protocol == 'all':
            fuzzer.mqtt_fuzzer()
        
        if args.protocol == 'coap' or args.protocol == 'all':
            fuzzer.coap_fuzzer()
        
        if args.protocol == 'udp' or args.protocol == 'all':
            fuzzer.udp_fuzzer()
        
        if args.protocol == 'tcp' or args.protocol == 'all':
            fuzzer.tcp_fuzzer()
        
        if args.protocol == 'smarthome' or args.protocol == 'all':
            fuzzer.smart_home_fuzzer()
        
        # Save results
        fuzzer.save_results(args.output)
        
        # Print summary
        print("\n" + "=" * 50)
        print("FUZZING SUMMARY")
        print("=" * 50)
        print(f"Target: {args.target}:{args.port}")
        print(f"Crashes detected: {len(fuzzer.crash_log)}")
        
        if fuzzer.crash_log:
            print("\nCrash details:")
            for crash in fuzzer.crash_log[-5:]:  # Show last 5 crashes
                print(f"  Protocol: {crash['protocol']}")
                print(f"  Error: {crash['error']}")
                print(f"  Payload: {crash['payload_preview']}")
                print("  " + "-" * 40)
        
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
        fuzzer.stop_fuzzing()
        fuzzer.save_results(args.output)

if __name__ == "__main__":
    main()
