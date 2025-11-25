#!/usr/bin/env python3
"""
Obfuscation & Packer Research Toolkit - Python Implementation
Includes packer, analyzer, and detection capabilities
"""

import os
import sys
import struct
import random
import hashlib
import zlib
import base64
import marshal
import lzma
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CodeObfuscator:
    """Advanced code obfuscation techniques"""
    
    def __init__(self):
        self.obfuscation_methods = [
            'variable_renaming',
            'string_encoding', 
            'control_flow_flattening',
            'dead_code_insertion',
            'instruction_substitution'
        ]
    
    def rename_variables(self, code):
        """Rename variables to meaningless names"""
        variables = self.extract_variables(code)
        mapping = {}
        
        for var in variables:
            new_name = f"var_{random.randint(1000, 9999)}"
            mapping[var] = new_name
        
        for old, new in mapping.items():
            code = code.replace(old, new)
        
        return code
    
    def extract_variables(self, code):
        """Extract variable names from code (simplified)"""
        # This is a simplified version - real implementation would use AST
        variables = set()
        lines = code.split('\n')
        for line in lines:
            if '=' in line and not line.strip().startswith('#'):
                var = line.split('=')[0].strip()
                if var and not var.startswith(' '):
                    variables.add(var)
        return list(variables)
    
    def encode_strings(self, code):
        """Encode strings with various methods"""
        import re
        
        # Find all strings in code
        strings = re.findall(r'\"[^\"]*\"|\'[^\']*\'', code)
        
        for string in strings:
            original = string
            # Choose random encoding method
            method = random.choice(['base64', 'hex', 'xor'])
            
            if method == 'base64':
                encoded = base64.b64encode(string[1:-1].encode()).decode()
                replacement = f"base64.b64decode('{encoded}').decode()"
            elif method == 'hex':
                encoded = string[1:-1].encode().hex()
                replacement = f"bytes.fromhex('{encoded}').decode()"
            else:  # xor
                key = random.randint(1, 255)
                encoded_bytes = [ord(c) ^ key for c in string[1:-1]]
                encoded_hex = ''.join(f'{b:02x}' for b in encoded_bytes)
                replacement = f"''.join(chr(b ^ {key}) for b in bytes.fromhex('{encoded_hex}'))"
            
            code = code.replace(original, replacement)
        
        return code
    
    def flatten_control_flow(self, code):
        """Basic control flow flattening"""
        # This would normally use AST manipulation
        # Simplified version for demonstration
        lines = code.split('\n')
        obfuscated = []
        
        # Add random state machine
        obfuscated.append("state = 0")
        obfuscated.append("while True:")
        obfuscated.append("    if state == 0:")
        
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('#'):
                indent = "    " * 2
                obfuscated.append(f"{indent}{line}")
                if i < len(lines) - 1:
                    obfuscated.append(f"{indent}state = {i + 1}")
                    obfuscated.append(f"{indent}continue")
                else:
                    obfuscated.append(f"{indent}break")
                obfuscated.append(f"    elif state == {i + 1}:")
        
        obfuscated.append("        break")
        
        return '\n'.join(obfuscated)
    
    def insert_dead_code(self, code):
        """Insert meaningless code that doesn't affect execution"""
        dead_code_patterns = [
            "x = {}; x = None",
            "for _ in range(random.randint(1, 10)): pass", 
            "if random.random() > 1: print('never executed')",
            "__temp = hashlib.md5(str(time.time()).encode()).hexdigest()",
            "while False: break"
        ]
        
        lines = code.split('\n')
        new_lines = []
        
        for line in lines:
            new_lines.append(line)
            if random.random() > 0.7 and line.strip() and not line.strip().startswith('#'):
                dead_code = random.choice(dead_code_patterns)
                new_lines.append(f"    {dead_code}")
        
        return '\n'.join(new_lines)

class BinaryPacker:
    """Advanced binary packing techniques"""
    
    def __init__(self, key=None):
        self.key = key or os.urandom(32)
        self.compression_methods = ['none', 'zlib', 'lzma']
    
    def create_stub(self, packed_data, decryption_key, compression_method):
        """Create unpacking stub"""
        stub_code = f'''
import zlib, lzma, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Unpacker:
    def __init__(self):
        self.packed_data = {packed_data}
        self.key = {decryption_key}
    
    def decompress(self, data, method):
        if method == "zlib":
            return zlib.decompress(data)
        elif method == "lzma":
            return lzma.decompress(data)
        return data
    
    def decrypt(self, data, key):
        cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        # Remove padding
        return decrypted.rstrip(b'\\x00')
    
    def execute(self):
        # Decrypt and decompress
        compressed_data = self.decrypt(self.packed_data, self.key)
        original_code = self.decompress(compressed_data, "{compression_method}")
        exec(original_code)

if __name__ == "__main__":
    unpacker = Unpacker()
    unpacker.execute()
'''
        return stub_code
    
    def pack_file(self, input_file, output_file, compression='zlib', encrypt=True):
        """Pack a Python file with compression and encryption"""
        with open(input_file, 'r') as f:
            original_code = f.read()
        
        # Compress
        if compression == 'zlib':
            compressed_data = zlib.compress(original_code.encode())
        elif compression == 'lzma':
            compressed_data = lzma.compress(original_code.encode())
        else:
            compressed_data = original_code.encode()
        
        # Encrypt
        if encrypt:
            # Simple XOR encryption for demonstration
            key = os.urandom(32)
            encrypted_data = bytearray()
            for i, byte in enumerate(compressed_data):
                encrypted_data.append(byte ^ key[i % len(key)])
            encrypted_data = bytes(encrypted_data)
        else:
            encrypted_data = compressed_data
            key = b'\x00' * 32
        
        # Create packed payload
        packed_payload = base64.b64encode(encrypted_data).decode()
        
        # Generate unpacking stub
        stub = self.create_stub(packed_payload, list(key), compression)
        
        with open(output_file, 'w') as f:
            f.write(stub)
        
        print(f"[+] Packed {input_file} -> {output_file}")
        print(f"[+] Compression: {compression}, Encryption: {encrypt}")
        print(f"[+] Original size: {len(original_code)}, Packed size: {len(stub)}")

class PackerAnalyzer:
    """Analyze packed files and detect packers"""
    
    def __init__(self):
        self.packer_signatures = {
            'UPX': [b'UPX!', b'UPX0', b'UPX1'],
            'ASPack': [b'ASPack'],
            'PECompact': [b'PEC2', b'PEC3'],
            'Themida': [b'Themida'],
            'VMProtect': [b'VMProtect'],
        }
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        
        return entropy
    
    def detect_packer(self, file_path):
        """Detect packer signatures in file"""
        with open(file_path, 'rb') as f:
            content = f.read()
        
        detected_packers = []
        
        for packer, signatures in self.packer_signatures.items():
            for signature in signatures:
                if signature in content:
                    detected_packers.append(packer)
                    break
        
        return detected_packers
    
    def analyze_file(self, file_path):
        """Comprehensive file analysis"""
        print(f"\n[*] Analyzing: {file_path}")
        print("-" * 50)
        
        # Basic file info
        file_size = os.path.getsize(file_path)
        print(f"[+] File size: {file_size} bytes")
        
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Entropy analysis
        entropy = self.calculate_entropy(content)
        print(f"[+] Entropy: {entropy:.4f}")
        
        if entropy > 7.0:
            print("[!] High entropy - likely packed or encrypted")
        elif entropy > 6.0:
            print("[!] Moderate entropy - possibly packed")
        else:
            print("[+] Low entropy - likely uncompressed")
        
        # Packer detection
        packers = self.detect_packer(file_path)
        if packers:
            print(f"[!] Detected packers: {', '.join(packers)}")
        else:
            print("[+] No known packer signatures detected")
        
        # Section analysis (for PE files)
        if content.startswith(b'MZ'):
            self.analyze_pe_file(content)
        
        print("-" * 50)
    
    def analyze_pe_file(self, content):
        """Basic PE file analysis"""
        print("\n[PE File Analysis]")
        
        try:
            # PE header offset
            pe_offset = struct.unpack('<L', content[0x3C:0x40])[0]
            print(f"[+] PE header offset: 0x{pe_offset:X}")
            
            # Number of sections
            num_sections = struct.unpack('<H', content[pe_offset + 6:pe_offset + 8])[0]
            print(f"[+] Number of sections: {num_sections}")
            
            # Analyze sections
            section_offset = pe_offset + 0xF8
            for i in range(num_sections):
                section_name = content[section_offset:section_offset + 8].rstrip(b'\x00')
                section_size = struct.unpack('<L', content[section_offset + 16:section_offset + 20])[0]
                section_entropy = self.calculate_entropy(content[section_offset:section_offset + section_size])
                
                print(f"    Section {section_name.decode('ascii', errors='ignore')}: "
                      f"Size={section_size}, Entropy={section_entropy:.4f}")
                
                section_offset += 0x28
                
        except Exception as e:
            print(f"[-] PE analysis failed: {e}")

def main():
    parser = argparse.ArgumentParser(description='Obfuscation & Packer Research Toolkit')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Obfuscate command
    obfuscate_parser = subparsers.add_parser('obfuscate', help='Obfuscate Python code')
    obfuscate_parser.add_argument('-i', '--input', required=True, help='Input file')
    obfuscate_parser.add_argument('-o', '--output', required=True, help='Output file')
    obfuscate_parser.add_argument('-m', '--method', choices=['all', 'variables', 'strings', 'controlflow', 'deadcode'],
                                 default='all', help='Obfuscation method')
    
    # Pack command
    pack_parser = subparsers.add_parser('pack', help='Pack Python file')
    pack_parser.add_argument('-i', '--input', required=True, help='Input file')
    pack_parser.add_argument('-o', '--output', required=True, help='Output file')
    pack_parser.add_argument('-c', '--compression', choices=['none', 'zlib', 'lzma'], 
                            default='zlib', help='Compression method')
    pack_parser.add_argument('--no-encrypt', action='store_true', help='Disable encryption')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze file for packing')
    analyze_parser.add_argument('-i', '--input', required=True, help='Input file')
    
    args = parser.parse_args()
    
    if args.command == 'obfuscate':
        obfuscator = CodeObfuscator()
        with open(args.input, 'r') as f:
            code = f.read()
        
        if args.method == 'all' or args.method == 'variables':
            code = obfuscator.rename_variables(code)
        if args.method == 'all' or args.method == 'strings':
            code = obfuscator.encode_strings(code)
        if args.method == 'all' or args.method == 'controlflow':
            code = obfuscator.flatten_control_flow(code)
        if args.method == 'all' or args.method == 'deadcode':
            code = obfuscator.insert_dead_code(code)
        
        with open(args.output, 'w') as f:
            f.write(code)
        
        print(f"[+] Obfuscated code written to {args.output}")
    
    elif args.command == 'pack':
        packer = BinaryPacker()
        packer.pack_file(args.input, args.output, args.compression, not args.no_encrypt)
    
    elif args.command == 'analyze':
        analyzer = PackerAnalyzer()
        analyzer.analyze_file(args.input)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
