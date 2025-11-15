#!/usr/bin/env python3
"""
Firmware Reverse Engineering Toolkit
Purpose: Analyze embedded firmware for security vulnerabilities
Use: Security assessment, vulnerability research, IoT device testing
"""

import os
import struct
import hashlib
import binascii
import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional

class FirmwareAnalyzer:
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.firmware_data = None
        self.analysis_results = {}
        self.vulnerabilities = []
        
    def load_firmware(self):
        """Load firmware file into memory"""
        try:
            with open(self.firmware_path, 'rb') as f:
                self.firmware_data = f.read()
            print(f"Loaded firmware: {len(self.firmware_data)} bytes")
            return True
        except Exception as e:
            print(f"Error loading firmware: {e}")
            return False
    
    def identify_file_type(self):
        """Identify firmware file type using magic bytes"""
        magic_bytes = {
            b'\x7fELF': 'ELF Executable',
            b'\xce\xfa\xed\xfe': 'Mach-O Binary',
            b'MZ': 'Windows PE',
            b'\x27\x05\x19\x56': 'uImage',
            b'\x55\xaa': 'MBR Bootloader',
            b'UBI#': 'UBI Image',
            b'TRX': 'TRX Firmware',
            b'HSQS': 'SquashFS',
        }
        
        for magic, file_type in magic_bytes.items():
            if self.firmware_data.startswith(magic):
                return file_type
        
        # Check for common compressed formats
        if self.firmware_data.startswith(b'\x1f\x8b'):
            return 'GZIP Compressed'
        elif self.firmware_data.startswith(b'\x42\x5a\x68'):
            return 'BZIP2 Compressed'
        elif self.firmware_data.startswith(b'\xfd7zXZ'):
            return 'XZ Compressed'
        
        return 'Unknown'
    
    def extract_strings(self, min_length=4):
        """Extract ASCII strings from firmware"""
        strings = []
        current_string = ""
        
        for byte in self.firmware_data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def analyze_encryption(self):
        """Check for encryption and weak cryptography"""
        crypto_indicators = {
            'MD5': hashlib.md5(b'test').digest()[:4],
            'SHA1': hashlib.sha1(b'test').digest()[:4],
            'AES': b'\x63\x20\x63\x68',  # Common AES constants
            'DES': b'\x0e\x32\xfc\xf7',
            'RSA': b'\x30\x82',  # PKCS#8 header
        }
        
        crypto_found = []
        for algo, pattern in crypto_indicators.items():
            if pattern in self.firmware_data:
                crypto_found.append(algo)
        
        return crypto_found
    
    def search_hardcoded_secrets(self):
        """Search for hardcoded credentials and secrets"""
        secrets_found = []
        
        # Common password patterns
        password_patterns = [
            rb'password[\s=:]+["\']([^"\']+)["\']',
            rb'passwd[\s=:]+["\']([^"\']+)["\']',
            rb'pwd[\s=:]+["\']([^"\']+)["\']',
            rb'admin:([^:\n]+)',
            rb'root:([^:\n]+)',
        ]
        
        strings = self.extract_strings()
        for string in strings:
            # Check for API keys
            if re.match(r'[A-Za-z0-9]{32}', string):
                secrets_found.append(f"Possible API Key: {string}")
            
            # Check for default passwords
            common_passwords = ['admin', 'password', '1234', 'default', 'root']
            if string.lower() in common_passwords:
                secrets_found.append(f"Default Password: {string}")
        
        return secrets_found
    
    def analyze_network_services(self):
        """Identify potential network services and ports"""
        network_indicators = []
        
        # Common port numbers in binary
        common_ports = [80, 443, 22, 23, 21, 25, 53, 8080, 8443]
        for port in common_ports:
            # Search for port in big and little endian
            port_be = struct.pack('>H', port)
            port_le = struct.pack('<H', port)
            
            if port_be in self.firmware_data or port_le in self.firmware_data:
                network_indicators.append(f"Port {port} reference found")
        
        # Search for common network function names
        network_functions = ['socket', 'bind', 'listen', 'accept', 'connect',
                           'send', 'recv', 'httpd', 'telnetd', 'sshd']
        
        for func in network_functions:
            if func.encode() in self.firmware_data:
                network_indicators.append(f"Network function: {func}")
        
        return network_indicators
    
    def check_binary_protections(self):
        """Check for common binary security features"""
        protections = {}
        
        # This is a simplified check - real implementation would use binwalk or similar
        strings = self.extract_strings()
        
        # Check for stack protection
        stack_protection_indicators = ['stack_chk_fail', '__stack_chk_guard']
        if any(indicator in strings for indicator in stack_protection_indicators):
            protections['Stack Canary'] = 'Present'
        else:
            protections['Stack Canary'] = 'Absent'
        
        # Check for ASLR/PIE (simplified)
        if b'/proc/self/exe' in self.firmware_data:
            protections['ASLR/PIE'] = 'Possible'
        else:
            protections['ASLR/PIE'] = 'Unknown'
        
        return protections
    
    def search_vulnerable_functions(self):
        """Search for potentially dangerous functions"""
        dangerous_functions = {
            'strcpy': 'Use strncpy instead',
            'gets': 'Extremely dangerous - use fgets',
            'sprintf': 'Use snprintf to prevent buffer overflow',
            'strcat': 'Use strncat with proper bounds checking',
            'system': 'Command injection risk',
            'popen': 'Command injection risk',
        }
        
        found_functions = []
        for func, risk in dangerous_functions.items():
            if func.encode() in self.firmware_data:
                found_functions.append(f"{func}: {risk}")
        
        return found_functions
    
    def generate_hex_dump(self, offset=0, length=512):
        """Generate hex dump of firmware section"""
        if offset + length > len(self.firmware_data):
            length = len(self.firmware_data) - offset
        
        data_slice = self.firmware_data[offset:offset + length]
        hex_dump = binascii.hexlify(data_slice).decode('ascii')
        
        # Format with 16 bytes per line
        formatted = []
        for i in range(0, len(hex_dump), 32):
            line = hex_dump[i:i+32]
            ascii_repr = ''.join(chr(int(line[j:j+2], 16)) 
                               if 32 <= int(line[j:j+2], 16) <= 126 else '.' 
                               for j in range(0, len(line), 2))
            formatted.append(f"{offset + i//2:08x}: {line}  {ascii_repr}")
        
        return '\n'.join(formatted)
    
    def comprehensive_analysis(self):
        """Perform comprehensive firmware analysis"""
        if not self.load_firmware():
            return False
        
        print("Starting firmware analysis...")
        print("=" * 50)
        
        # File type identification
        file_type = self.identify_file_type()
        print(f"File Type: {file_type}")
        
        # Cryptographic analysis
        crypto = self.analyze_encryption()
        if crypto:
            print(f"Crypto Found: {', '.join(crypto)}")
        
        # Security protections
        protections = self.check_binary_protections()
        print("Binary Protections:")
        for protection, status in protections.items():
            print(f"  {protection}: {status}")
        
        # Network services
        network_services = self.analyze_network_services()
        if network_services:
            print("Network Services Found:")
            for service in network_services[:5]:  # Show first 5
                print(f"  {service}")
        
        # Vulnerable functions
        dangerous_funcs = self.search_vulnerable_functions()
        if dangerous_funcs:
            print("Potentially Dangerous Functions:")
            for func in dangerous_funcs:
                print(f"  {func}")
        
        # Hardcoded secrets
        secrets = self.search_hardcoded_secrets()
        if secrets:
            print("Hardcoded Secrets Found:")
            for secret in secrets[:5]:  # Show first 5
                print(f"  {secret}")
        
        # Sample hex dump
        print("\nSample Hex Dump (first 512 bytes):")
        print(self.generate_hex_dump())
        
        return True

class FirmwareExtractor:
    """Advanced firmware extraction and analysis"""
    
    def __init__(self):
        self.compressions = {
            b'\x1f\x8b': 'gzip',
            b'\x42\x5a\x68': 'bzip2', 
            b'\xfd7zXZ': 'xz',
            b'\x50\x4b\x03\x04': 'zip',
        }
    
    def extract_filesystem(self, firmware_data, output_dir):
        """Attempt to extract embedded filesystem"""
        try:
            import binwalk
            # This would use binwalk API for real extraction
            print("Filesystem extraction would require binwalk integration")
            return False
        except ImportError:
            print("Binwalk not available for advanced extraction")
            return False
    
    def analyze_elf_sections(self, firmware_path):
        """Analyze ELF binary sections"""
        try:
            import elftools
            from elftools.elf.elffile import ELFFile
            
            with open(firmware_path, 'rb') as f:
                elf = ELFFile(f)
                
                print("ELF Sections:")
                for section in elf.iter_sections():
                    print(f"  {section.name}: {section['sh_size']} bytes")
                    
            return True
        except ImportError:
            print("pyelftools required for ELF analysis")
            return False

def main():
    parser = argparse.ArgumentParser(description='Firmware Reverse Engineering Tool')
    parser.add_argument('firmware', help='Path to firmware file')
    parser.add_argument('--extract', action='store_true', help='Attempt filesystem extraction')
    parser.add_argument('--strings', action='store_true', help='Extract strings only')
    parser.add_argument('--crypto', action='store_true', help='Cryptographic analysis only')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.firmware):
        print(f"Error: Firmware file {args.firmware} not found")
        return
    
    analyzer = FirmwareAnalyzer(args.firmware)
    
    if args.strings:
        analyzer.load_firmware()
        strings = analyzer.extract_strings()
        print(f"Found {len(strings)} strings:")
        for string in strings[:50]:  # Show first 50
            print(f"  {string}")
    elif args.crypto:
        analyzer.load_firmware()
        crypto = analyzer.analyze_encryption()
        print("Cryptographic analysis:")
        print(f"  Algorithms found: {crypto}")
    else:
        analyzer.comprehensive_analysis()

if __name__ == "__main__":
    main()
