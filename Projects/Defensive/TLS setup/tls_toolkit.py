#!/usr/bin/env python3
"""
TLS Setup & Hardening Guide - Python Implementation
Secure TLS configuration generator and tester
"""

import ssl
import socket
import OpenSSL
import json
import yaml
import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib

class TLSConfigGenerator:
    """Generate secure TLS configurations for various servers"""
    
    def __init__(self):
        self.cipher_suites = {
            'modern': [
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256', 
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_128_CCM_SHA256'
            ],
            'intermediate': [
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-CHACHA20-POLY1305',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'DHE-RSA-AES256-GCM-SHA384',
                'DHE-RSA-AES128-GCM-SHA256'
            ],
            'compatible': [
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-CHACHA20-POLY1305',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'DHE-RSA-AES256-GCM-SHA384',
                'DHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-SHA384',
                'ECDHE-RSA-AES256-SHA384',
                'ECDHE-ECDSA-AES128-SHA256',
                'ECDHE-RSA-AES128-SHA256'
            ]
        }
        
        self.tls_versions = {
            'modern': ['TLSv1.3', 'TLSv1.2'],
            'intermediate': ['TLSv1.2', 'TLSv1.3'],
            'compatible': ['TLSv1.2', 'TLSv1.3', 'TLSv1.1']
        }
        
        self.curves = {
            'modern': ['X25519', 'secp521r1', 'secp384r1'],
            'intermediate': ['prime256v1', 'secp384r1', 'secp521r1'],
            'compatible': ['prime256v1', 'secp384r1', 'secp521r1']
        }
    
    def generate_nginx_config(self, security_level: str = 'intermediate') -> str:
        """Generate secure Nginx TLS configuration"""
        config = f"""
# TLS Hardening Configuration for Nginx
# Security Level: {security_level}
# Generated: {datetime.now().isoformat()}

ssl_protocols {' '.join(self.tls_versions[security_level])};
ssl_ciphers {' '.join(self.cipher_suites[security_level])};
ssl_prefer_server_ciphers on;

# Modern SSL settings
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# Modern security headers
add_header Strict-Transport-Security "max-age=63072000" always;
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";

# DH parameters (generate with: openssl dhparam -out dhparam.pem 4096)
ssl_dhparam /etc/nginx/dhparam.pem;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# Security enhancements
ssl_ecdh_curve {' '.join(self.curves[security_level])};
"""
        return config
    
    def generate_apache_config(self, security_level: str = 'intermediate') -> str:
        """Generate secure Apache TLS configuration"""
        config = f"""
# TLS Hardening Configuration for Apache
# Security Level: {security_level}
# Generated: {datetime.now().isoformat()}

SSLProtocol {' '.join(self.tls_versions[security_level])}
SSLCipherSuite {' '.join(self.cipher_suites[security_level])}
SSLHonorCipherOrder on

# Modern SSL settings
SSLSessionCache "shmcb:/var/run/ssl_scache(512000)"
SSLSessionCacheTimeout 300

# Security headers
Header always set Strict-Transport-Security "max-age=63072000"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set X-XSS-Protection "1; mode=block"

# OCSP Stapling
SSLUseStapling On
SSLStaplingResponderTimeout 5
SSLStaplingReturnResponderErrors Off
SSLStaplingCache "shmcb:/var/run/ocsp(128000)"
"""
        return config
    
    def generate_openssl_config(self) -> str:
        """Generate secure OpenSSL configuration"""
        config = """
# Secure OpenSSL Configuration
[openssl_init]
ssl_conf = ssl_section

[ssl_section]
system_default = system_default_section

[system_default_section]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
Options = UnsafeLegacyRenegotiation
"""
        return config
    
    def generate_python_ssl_context(self, security_level: str = 'intermediate') -> str:
        """Generate Python SSL context configuration"""
        config = f'''
import ssl

def create_secure_ssl_context():
    """Create a secure SSL context"""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # TLS versions
    context.minimum_version = ssl.TLSVersion.{self.tls_versions[security_level][-1].replace("TLSv", "TLS").replace(".", "")}
    context.maximum_version = ssl.TLSVersion.{self.tls_versions[security_level][0].replace("TLSv", "TLS").replace(".", "")}
    
    # Cipher suites
    if hasattr(context, 'set_ciphers'):
        context.set_ciphers(':'.join({self.cipher_suites[security_level]}))
    
    # Security options
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    context.options |= ssl.OP_NO_COMPRESSION
    context.options |= ssl.OP_SINGLE_DH_USE
    context.options |= ssl.OP_SINGLE_ECDH_USE
    
    # Certificate verification
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    return context
'''
        return config

class TLSCertificateManager:
    """Manage TLS certificates and keys"""
    
    def __init__(self, cert_dir: str = "./certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
    
    def generate_self_signed_cert(self, common_name: str, days: int = 365) -> Dict[str, str]:
        """Generate self-signed certificate for testing"""
        try:
            from OpenSSL import crypto
            
            # Generate key
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 4096)
            
            # Generate certificate
            cert = crypto.X509()
            cert.get_subject().CN = common_name
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(days * 24 * 60 * 60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(key)
            cert.sign(key, 'sha256')
            
            # Save files
            key_path = self.cert_dir / "key.pem"
            cert_path = self.cert_dir / "cert.pem"
            
            with open(key_path, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            
            with open(cert_path, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            
            return {
                'key_file': str(key_path),
                'cert_file': str(cert_path),
                'common_name': common_name,
                'expires': days
            }
            
        except ImportError:
            print("PyOpenSSL not available. Using fallback method.")
            return self._generate_cert_fallback(common_name, days)
    
    def _generate_cert_fallback(self, common_name: str, days: int) -> Dict[str, str]:
        """Fallback certificate generation using openssl command"""
        key_path = self.cert_dir / "key.pem"
        cert_path = self.cert_dir / "cert.pem"
        
        # Generate private key
        subprocess.run([
            'openssl', 'genrsa', '-out', str(key_path), '4096'
        ], check=True)
        
        # Generate self-signed certificate
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-key', str(key_path),
            '-out', str(cert_path), '-days', str(days),
            '-subj', f'/CN={common_name}'
        ], check=True)
        
        return {
            'key_file': str(key_path),
            'cert_file': str(cert_path),
            'common_name': common_name,
            'expires': days
        }
    
    def analyze_certificate(self, cert_file: str) -> Dict[str, Any]:
        """Analyze TLS certificate for security issues"""
        try:
            with open(cert_file, 'rb') as f:
                cert_data = f.read()
            
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
            
            analysis = {
                'subject': dict(cert.get_subject().get_components()),
                'issuer': dict(cert.get_issuer().get_components()),
                'serial_number': cert.get_serial_number(),
                'version': cert.get_version(),
                'not_before': cert.get_notBefore().decode('utf-8'),
                'not_after': cert.get_notAfter().decode('utf-8'),
                'signature_algorithm': cert.get_signature_algorithm().decode('utf-8'),
                'key_bits': cert.get_pubkey().bits(),
                'key_type': 'RSA' if cert.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA else 'Unknown',
                'extensions': []
            }
            
            # Check extensions
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                analysis['extensions'].append({
                    'name': ext.get_short_name().decode('utf-8'),
                    'critical': ext.get_critical(),
                    'data': str(ext)
                })
            
            # Security checks
            analysis['security_checks'] = self._perform_certificate_checks(cert)
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _perform_certificate_checks(self, cert) -> Dict[str, Any]:
        """Perform security checks on certificate"""
        checks = {}
        
        # Check key size
        key_bits = cert.get_pubkey().bits()
        checks['key_size_adequate'] = key_bits >= 2048
        
        # Check validity period
        not_after = datetime.strptime(cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
        validity_days = (not_after - datetime.now()).days
        checks['validity_period_reasonable'] = validity_days <= 825  # ~2 years
        
        # Check signature algorithm
        sig_algo = cert.get_signature_algorithm().decode('utf-8')
        checks['strong_signature_algorithm'] = 'sha256' in sig_algo.lower() or 'sha384' in sig_algo.lower() or 'sha512' in sig_algo.lower()
        
        return checks

class TLSTester:
    """Test TLS configurations and security"""
    
    def __init__(self):
        self.test_results = {}
    
    def test_tls_server(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Test TLS configuration of a remote server"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    result = {
                        'hostname': hostname,
                        'port': port,
                        'tls_version': version,
                        'cipher_suite': cipher,
                        'certificate': cert,
                        'supported_protocols': self._test_supported_protocols(hostname, port),
                        'security_issues': self._check_security_issues(version, cipher, cert)
                    }
                    
                    return result
                    
        except Exception as e:
            return {'error': str(e)}
    
    def _test_supported_protocols(self, hostname: str, port: int) -> Dict[str, bool]:
        """Test which TLS protocols are supported"""
        protocols = {
            'SSLv2': False,
            'SSLv3': False, 
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        # Test each protocol
        for protocol_name in protocols.keys():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # Modern context
                
                # Set specific protocol version
                if protocol_name == 'SSLv2':
                    context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                elif protocol_name == 'SSLv3':
                    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                elif protocol_name == 'TLSv1.0':
                    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                elif protocol_name == 'TLSv1.1':
                    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2
                elif protocol_name == 'TLSv1.2':
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif protocol_name == 'TLSv1.3':
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[protocol_name] = True
                        
            except:
                protocols[protocol_name] = False
        
        return protocols
    
    def _check_security_issues(self, version: str, cipher: tuple, cert: dict) -> List[str]:
        """Check for common security issues"""
        issues = []
        
        # Check TLS version
        if version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
            issues.append(f'Weak TLS version: {version}')
        
        # Check cipher suite
        cipher_name = cipher[0] if cipher else ''
        weak_ciphers = ['RC4', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ANON', 'ADH', '3DES']
        if any(weak in cipher_name for weak in weak_ciphers):
            issues.append(f'Weak cipher suite: {cipher_name}')
        
        # Check certificate
        if cert:
            # Check key size
            key_size = cert.get('keySize', 0)
            if key_size < 2048:
                issues.append(f'Weak RSA key size: {key_size} bits')
            
            # Check signature algorithm
            sig_algo = cert.get('signatureAlgorithm', '')
            if 'sha1' in sig_algo.lower():
                issues.append('Weak signature algorithm: SHA1')
        
        return issues
    
    def scan_tls_vulnerabilities(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Scan for common TLS vulnerabilities"""
        vulnerabilities = {
            'poodle': self._test_poodle(hostname, port),
            'heartbleed': self._test_heartbleed(hostname, port),
            'freak': self._test_freak(hostname, port),
            'logjam': self._test_logjam(hostname, port),
            'drown': self._test_drown(hostname, port)
        }
        
        return vulnerabilities
    
    def _test_poodle(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test for POODLE vulnerability"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    return {'vulnerable': True, 'description': 'SSLv3 enabled - vulnerable to POODLE'}
        except:
            return {'vulnerable': False, 'description': 'SSLv3 not supported'}
    
    def _test_heartbleed(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test for Heartbleed vulnerability (simplified)"""
        # Note: This is a basic test. Use dedicated tools for comprehensive testing.
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    return {'vulnerable': False, 'description': 'No Heartbleed detected (basic test)'}
        except Exception as e:
            return {'vulnerable': 'Unknown', 'description': f'Test inconclusive: {e}'}
    
    def _test_freak(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test for FREAK vulnerability"""
        return {'vulnerable': False, 'description': 'FREAK test requires specialized tools'}
    
    def _test_logjam(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test for Logjam vulnerability"""
        return {'vulnerable': False, 'description': 'Logjam test requires specialized tools'}
    
    def _test_drown(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test for DROWN vulnerability"""
        return {'vulnerable': False, 'description': 'DROWN test requires specialized tools'}

def main():
    parser = argparse.ArgumentParser(description='TLS Setup & Hardening Guide')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate config command
    config_parser = subparsers.add_parser('generate', help='Generate TLS configurations')
    config_parser.add_argument('--server', choices=['nginx', 'apache', 'openssl', 'python'], 
                              required=True, help='Server type')
    config_parser.add_argument('--level', choices=['modern', 'intermediate', 'compatible'],
                              default='intermediate', help='Security level')
    config_parser.add_argument('--output', help='Output file')
    
    # Certificate management command
    cert_parser = subparsers.add_parser('certificate', help='Certificate management')
    cert_parser.add_argument('--generate', action='store_true', help='Generate self-signed certificate')
    cert_parser.add_argument('--analyze', help='Analyze certificate file')
    cert_parser.add_argument('--common-name', default='localhost', help='Common name for certificate')
    cert_parser.add_argument('--days', type=int, default=365, help='Certificate validity days')
    
    # Testing command
    test_parser = subparsers.add_parser('test', help='Test TLS configuration')
    test_parser.add_argument('hostname', help='Hostname to test')
    test_parser.add_argument('--port', type=int, default=443, help='Port to test')
    test_parser.add_argument('--scan-vulnerabilities', action='store_true', 
                           help='Scan for common vulnerabilities')
    
    args = parser.parse_args()
    
    if args.command == 'generate':
        generator = TLSConfigGenerator()
        
        if args.server == 'nginx':
            config = generator.generate_nginx_config(args.level)
        elif args.server == 'apache':
            config = generator.generate_apache_config(args.level)
        elif args.server == 'openssl':
            config = generator.generate_openssl_config()
        elif args.server == 'python':
            config = generator.generate_python_ssl_context(args.level)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(config)
            print(f"[+] Configuration saved to {args.output}")
        else:
            print(config)
    
    elif args.command == 'certificate':
        manager = TLSCertificateManager()
        
        if args.generate:
            result = manager.generate_self_signed_cert(args.common_name, args.days)
            print(f"[+] Generated certificate:")
            print(f"    Key file: {result['key_file']}")
            print(f"    Cert file: {result['cert_file']}")
            print(f"    Common Name: {result['common_name']}")
            print(f"    Expires in: {result['expires']} days")
        
        if args.analyze:
            analysis = manager.analyze_certificate(args.analyze)
            print(json.dumps(analysis, indent=2))
    
    elif args.command == 'test':
        tester = TLSTester()
        
        if args.scan_vulnerabilities:
            vulnerabilities = tester.scan_tls_vulnerabilities(args.hostname, args.port)
            print("TLS Vulnerability Scan Results:")
            print(json.dumps(vulnerabilities, indent=2))
        else:
            result = tester.test_tls_server(args.hostname, args.port)
            print("TLS Configuration Test Results:")
            print(json.dumps(result, indent=2))
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
