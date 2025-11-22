#!/usr/bin/env python3
import socket
import ssl
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import argparse
import json
import sys
from datetime import datetime

class TLSDowngradeTester:
    def __init__(self, target_host, target_port=443):
        self.target_host = target_host
        self.target_port = target_port
        self.results = {
            'target': f"{target_host}:{target_port}",
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': []
        }
    
    def test_tls_versions(self):
        """Test different TLS/SSL versions"""
        print("\n[+] Testing TLS/SSL protocol versions...")
        
        protocols = {
            'TLSv1.3': ssl.PROTOCOL_TLS,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'SSLv3': ssl.PROTOCOL_SSLv3,
            'SSLv2': getattr(ssl, 'PROTOCOL_SSLv2', None)
        }
        
        for protocol_name, protocol in protocols.items():
            if protocol is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                        version = ssock.version()
                        cipher = ssock.cipher()
                        print(f"  ✓ {protocol_name}: SUPPORTED - {cipher[0]} ({cipher[1]})")
                        
                        if protocol_name in ['SSLv3', 'SSLv2', 'TLSv1.0']:
                            self.results['vulnerabilities'].append({
                                'type': 'WEAK_PROTOCOL',
                                'severity': 'HIGH',
                                'protocol': protocol_name,
                                'description': f'Server supports deprecated {protocol_name}'
                            })
                        
                        # Test certificate validation
                        self.test_certificate_validation(protocol)
                        
            except Exception as e:
                print(f"  ✗ {protocol_name}: NOT SUPPORTED - {str(e)}")
    
    def test_certificate_validation(self, protocol):
        """Test certificate validation bypass"""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                        issuer = x509_cert.issuer.rfc4514_string()
                        subject = x509_cert.subject.rfc4514_string()
                        not_after = x509_cert.not_valid_after
                        
                        # Check certificate expiration
                        if not_after < datetime.now():
                            self.results['vulnerabilities'].append({
                                'type': 'EXPIRED_CERTIFICATE',
                                'severity': 'HIGH',
                                'description': 'Server certificate has expired'
                            })
                        
                        print(f"    Certificate: {subject}")
                        print(f"    Issuer: {issuer}")
                        print(f"    Expires: {not_after}")
            
        except Exception as e:
            print(f"    Certificate test failed: {e}")
    
    def test_cipher_suites(self):
        """Test weak cipher suites"""
        print("\n[+] Testing cipher suites...")
        
        weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ANON'
        ]
        
        try:
            context = ssl.create_default_context()
            context.set_ciphers('ALL:@SECLEVEL=0')
            
            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cipher = ssock.cipher()
                    print(f"  Current cipher: {cipher[0]} ({cipher[1]})")
                    
                    for weak_cipher in weak_ciphers:
                        if weak_cipher in cipher[0].upper():
                            self.results['vulnerabilities'].append({
                                'type': 'WEAK_CIPHER',
                                'severity': 'MEDIUM',
                                'cipher': cipher[0],
                                'description': f'Server uses weak cipher: {cipher[0]}'
                            })
                            break
                            
        except Exception as e:
            print(f"  Cipher test failed: {e}")
    
    def simulate_mitm_downgrade(self):
        """Simulate MITM downgrade attack"""
        print("\n[+] Simulating MITM downgrade attack...")
        
        try:
            # Attempt to force TLS 1.0
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    if ssock.version() == 'TLSv1':
                        self.results['vulnerabilities'].append({
                            'type': 'TLS_DOWNGRADE_VULNERABLE',
                            'severity': 'MEDIUM',
                            'description': 'Server vulnerable to TLS downgrade attacks'
                        })
                        print("  ✓ Vulnerable to TLS downgrade attacks")
                    else:
                        print("  ✗ Not vulnerable to basic TLS downgrade")
                        
        except Exception as e:
            print(f"  MITM simulation failed: {e}")
    
    def run_tests(self):
        """Run all security tests"""
        print(f"Starting TLS Security Assessment for {self.target_host}:{self.target_port}")
        print("=" * 60)
        
        self.test_tls_versions()
        self.test_cipher_suites()
        self.simulate_mitm_downgrade()
        
        self.generate_report()
    
    def generate_report(self):
        """Generate security assessment report"""
        print("\n" + "=" * 60)
        print("SECURITY ASSESSMENT REPORT")
        print("=" * 60)
        
        if self.results['vulnerabilities']:
            print(f"\nFound {len(self.results['vulnerabilities'])} vulnerabilities:")
            for vuln in self.results['vulnerabilities']:
                print(f"\n[{vuln['severity']}] {vuln['type']}")
                print(f"  Description: {vuln['description']}")
        else:
            print("\n✓ No major vulnerabilities found")
        
        # Save results to file
        filename = f"tls_scan_{self.target_host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed report saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description='TLS Downgrade & MITM Tester')
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    
    args = parser.parse_args()
    
    tester = TLSDowngradeTester(args.host, args.port)
    tester.run_tests()

if __name__ == "__main__":
    main()
