import os
import hashlib
import hmac
import secrets
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import json
import base64
import getpass
from dataclasses import dataclass
from typing import List, Tuple
import threading
import time

@dataclass
class EncryptionKey:
    key_id: str
    key_data: bytes
    created: float
    expires: float
    version: int
    metadata: dict

class FullDiskEncryptionDemo:
    def __init__(self, sector_size=512):
        self.sector_size = sector_size
        self.keys = {}
        self.current_key_id = None
        self.backend = default_backend()
        
    def generate_secure_key(self, key_size=32) -> bytes:
        """Generate cryptographically secure random key"""
        return secrets.token_bytes(key_size)
    
    def derive_key_from_passphrase(self, passphrase: str, salt: bytes = None, 
                                 key_length=32, iterations=100000) -> Tuple[bytes, bytes]:
        """Derive encryption key from passphrase using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        
        key = kdf.derive(passphrase.encode())
        return key, salt
    
    def create_key_version(self, key_id: str, key_data: bytes, 
                         validity_days=365, metadata=None) -> EncryptionKey:
        """Create a new key version with metadata"""
        if metadata is None:
            metadata = {}
            
        key = EncryptionKey(
            key_id=key_id,
            key_data=key_data,
            created=time.time(),
            expires=time.time() + (validity_days * 24 * 60 * 60),
            version=len([k for k in self.keys.values() if k.key_id == key_id]) + 1,
            metadata=metadata
        )
        
        self.keys[key.key_id + f"_v{key.version}"] = key
        return key
    
    def encrypt_sector(self, plaintext: bytes, sector_number: int, 
                     key: EncryptionKey) -> bytes:
        """Encrypt a single disk sector using AES-XTS mode"""
        if len(plaintext) != self.sector_size:
            raise ValueError(f"Sector size must be {self.sector_size} bytes")
        
        # For demo purposes, we'll use AES-CBC. In production, use AES-XTS
        # Generate sector-specific IV from sector number
        iv = hashlib.sha256(struct.pack('<Q', sector_number)).digest()[:16]
        
        # Split key for XTS (tweakable encryption)
        key1 = key.key_data[:16]  # Data encryption key
        key2 = key.key_data[16:]  # Tweak key
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key1), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad data if necessary (in real FDE, sectors are fixed size)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data
    
    def decrypt_sector(self, ciphertext: bytes, sector_number: int,
                     key: EncryptionKey) -> bytes:
        """Decrypt a single disk sector"""
        # Generate sector-specific IV
        iv = hashlib.sha256(struct.pack('<Q', sector_number)).digest()[:16]
        key1 = key.key_data[:16]
        
        cipher = Cipher(algorithms.AES(key1), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted_data
    
    def simulate_disk_encryption(self, data: str, key: EncryptionKey) -> dict:
        """Simulate full-disk encryption on sample data"""
        print("Simulating full-disk encryption...")
        
        # Convert data to sectors
        sectors = []
        for i in range(0, len(data), self.sector_size):
            sector = data[i:i + self.sector_size]
            # Pad sector to full size
            sector = sector.ljust(self.sector_size, '\x00')
            sectors.append(sector.encode())
        
        # Encrypt each sector
        encrypted_sectors = []
        for i, sector in enumerate(sectors):
            encrypted_sector = self.encrypt_sector(sector, i, key)
            encrypted_sectors.append(encrypted_sector)
        
        # Decrypt to verify
        decrypted_sectors = []
        for i, encrypted_sector in enumerate(encrypted_sectors):
            decrypted_sector = self.decrypt_sector(encrypted_sector, i, key)
            decrypted_sectors.append(decrypted_sector)
        
        # Reconstruct original data
        decrypted_data = b''.join(decrypted_sectors).decode('utf-8').rstrip('\x00')
        
        return {
            'original': data,
            'encrypted': encrypted_sectors,
            'decrypted': decrypted_data,
            'sector_count': len(sectors),
            'verification_successful': data == decrypted_data
        }

class KeyManager:
    """Secure Key Management System"""
    
    def __init__(self, keystore_path="keystore"):
        self.keystore_path = keystore_path
        os.makedirs(keystore_path, exist_ok=True)
        
    def generate_key_hierarchy(self) -> dict:
        """Generate master key and derived keys"""
        # Master Key
        master_key = secrets.token_bytes(32)
        
        # Key Encryption Key (KEK)
        kek = secrets.token_bytes(32)
        
        # Data Encryption Keys
        file_key = secrets.token_bytes(32)
        database_key = secrets.token_bytes(32)
        
        return {
            'master_key': master_key,
            'kek': kek,
            'file_key': file_key,
            'database_key': database_key
        }
    
    def protect_master_key(self, master_key: bytes, passphrase: str) -> dict:
        """Protect master key with passphrase and splitting"""
        # Derive key from passphrase
        salt = secrets.token_bytes(16)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        wrapping_key = kdf.derive(passphrase.encode())
        
        # Encrypt master key
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(wrapping_key), modes.CBC(iv), 
                       backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_key = padder.update(master_key) + padder.finalize()
        encrypted_master_key = encryptor.update(padded_key) + encryptor.finalize()
        
        # Split key for recovery (Shamir's Secret Sharing simplified)
        key_parts = self.split_key(master_key, parts=3, threshold=2)
        
        return {
            'encrypted_master_key': encrypted_master_key,
            'salt': salt,
            'iv': iv,
            'key_parts': key_parts
        }
    
    def split_key(self, key: bytes, parts: int = 3, threshold: int = 2) -> List[bytes]:
        """Simple key splitting (simplified version of secret sharing)"""
        if threshold > parts:
            raise ValueError("Threshold cannot be greater than total parts")
        
        # Generate random parts
        key_parts = [secrets.token_bytes(len(key)) for _ in range(parts - 1)]
        
        # Calculate last part to reconstruct original key
        last_part = bytearray(key)
        for part in key_parts:
            for i in range(len(key)):
                last_part[i] ^= part[i]
        
        key_parts.append(bytes(last_part))
        return key_parts
    
    def recover_key(self, key_parts: List[bytes]) -> bytes:
        """Recover original key from parts"""
        if len(key_parts) < 2:
            raise ValueError("At least 2 parts required for recovery")
        
        recovered = bytearray(len(key_parts[0]))
        for part in key_parts:
            for i in range(len(part)):
                recovered[i] ^= part[i]
        
        return bytes(recovered)
    
    def rotate_keys(self, old_key: EncryptionKey, new_algorithm="AES-256") -> EncryptionKey:
        """Rotate encryption keys following best practices"""
        print(f"Rotating key {old_key.key_id}...")
        
        # Generate new key
        new_key_data = secrets.token_bytes(32)
        
        # Create new key version
        new_key = EncryptionKey(
            key_id=old_key.key_id,
            key_data=new_key_data,
            created=time.time(),
            expires=time.time() + (365 * 24 * 60 * 60),  # 1 year
            version=old_key.version + 1,
            metadata={'previous_version': old_key.version, 'algorithm': new_algorithm}
        )
        
        # Keep old key for data re-encryption period
        old_key.metadata['superseded_by'] = new_key.version
        old_key.expires = time.time() + (30 * 24 * 60 * 60)  # 30 days grace period
        
        return new_key
    
    def export_key_bundle(self, keys: dict, passphrase: str) -> str:
        """Export encrypted key bundle for backup"""
        # Create key bundle
        bundle = {
            'version': '1.0',
            'timestamp': time.time(),
            'keys': {}
        }
        
        # Encrypt each key
        for key_name, key_data in keys.items():
            if isinstance(key_data, bytes):
                salt = secrets.token_bytes(16)
                kdf = PBKDF2(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                bundle_key = kdf.derive(passphrase.encode())
                
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(bundle_key), modes.CBC(iv), 
                               backend=default_backend())
                encryptor = cipher.encryptor()
                
                padder = padding.PKCS7(128).padder()
                padded_key = padder.update(key_data) + padder.finalize()
                encrypted_key = encryptor.update(padded_key) + encryptor.finalize()
                
                bundle['keys'][key_name] = {
                    'encrypted_data': base64.b64encode(encrypted_key).decode(),
                    'salt': base64.b64encode(salt).decode(),
                    'iv': base64.b64encode(iv).decode()
                }
        
        return json.dumps(bundle, indent=2)

class EncryptionDemoCLI:
    """Command-line interface for the FDE demo"""
    
    def __init__(self):
        self.fde = FullDiskEncryptionDemo()
        self.key_manager = KeyManager()
    
    def run_demo(self):
        """Run interactive full-disk encryption demo"""
        print("=" * 60)
        print("    FULL-DISK ENCRYPTION & KEY MANAGEMENT DEMO")
        print("=" * 60)
        print("\nWARNING: This is a DEMONSTRATION tool only!")
        print("Do not use for actual disk encryption!\n")
        
        while True:
            print("\nOptions:")
            print("1. Generate Encryption Keys")
            print("2. Simulate Disk Encryption")
            print("3. Key Management Demo")
            print("4. Key Rotation Demo")
            print("5. Export Key Bundle")
            print("6. Exit")
            
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                self.demo_key_generation()
            elif choice == '2':
                self.demo_disk_encryption()
            elif choice == '3':
                self.demo_key_management()
            elif choice == '4':
                self.demo_key_rotation()
            elif choice == '5':
                self.demo_key_export()
            elif choice == '6':
                print("Exiting demo...")
                break
            else:
                print("Invalid choice. Please try again.")
    
    def demo_key_generation(self):
        """Demonstrate secure key generation"""
        print("\n--- KEY GENERATION DEMO ---")
        
        # Generate keys using different methods
        print("1. Generating random key...")
        random_key = self.fde.generate_secure_key()
        print(f"   Random Key: {random_key.hex()[:32]}...")
        
        print("2. Generating key from passphrase...")
        passphrase = getpass.getpass("   Enter passphrase: ")
        derived_key, salt = self.fde.derive_key_from_passphrase(passphrase)
        print(f"   Derived Key: {derived_key.hex()[:32]}...")
        print(f"   Salt: {salt.hex()}")
        
        print("3. Creating key version...")
        key_obj = self.fde.create_key_version("demo_disk_key", random_key)
        print(f"   Key ID: {key_obj.key_id}")
        print(f"   Version: {key_obj.version}")
        print(f"   Expires: {time.ctime(key_obj.expires)}")
    
    def demo_disk_encryption(self):
        """Demonstrate disk encryption process"""
        print("\n--- DISK ENCRYPTION SIMULATION ---")
        
        sample_data = "This is sample data that would be stored on an encrypted disk. " * 10
        print(f"Original data length: {len(sample_data)} bytes")
        
        # Generate encryption key
        key_data = self.fde.generate_secure_key()
        key = self.fde.create_key_version("demo_encryption", key_data)
        
        # Simulate encryption
        result = self.fde.simulate_disk_encryption(sample_data, key)
        
        print(f"Number of sectors: {result['sector_count']}")
        print(f"Encryption successful: {result['verification_successful']}")
        print(f"Data integrity verified: {result['original'] == result['decrypted']}")
        
        # Show encrypted sector sample
        if result['encrypted']:
            sample_sector = result['encrypted'][0]
            print(f"Sample encrypted sector (first 32 bytes): {sample_sector.hex()[:64]}...")
    
    def demo_key_management(self):
        """Demonstrate key management features"""
        print("\n--- KEY MANAGEMENT DEMO ---")
        
        # Generate key hierarchy
        print("1. Generating key hierarchy...")
        hierarchy = self.key_manager.generate_key_hierarchy()
        for key_name, key_data in hierarchy.items():
            print(f"   {key_name}: {key_data.hex()[:24]}...")
        
        # Protect master key
        print("\n2. Protecting master key...")
        passphrase = getpass.getpass("   Enter protection passphrase: ")
        protected = self.key_manager.protect_master_key(hierarchy['master_key'], passphrase)
        print(f"   Master key encrypted and split into {len(protected['key_parts'])} parts")
        
        # Demonstrate key recovery
        print("\n3. Demonstrating key recovery...")
        recovered_key = self.key_manager.recover_key(protected['key_parts'][:2])
        print(f"   Recovery successful: {recovered_key == hierarchy['master_key']}")
    
    def demo_key_rotation(self):
        """Demonstrate key rotation process"""
        print("\n--- KEY ROTATION DEMO ---")
        
        # Create initial key
        key_data = self.fde.generate_secure_key()
        old_key = self.fde.create_key_version("rotatable_key", key_data)
        
        print(f"Original Key:")
        print(f"  ID: {old_key.key_id}")
        print(f"  Version: {old_key.version}")
        print(f"  Created: {time.ctime(old_key.created)}")
        print(f"  Expires: {time.ctime(old_key.expires)}")
        
        # Rotate key
        new_key = self.key_manager.rotate_keys(old_key)
        
        print(f"\nNew Rotated Key:")
        print(f"  ID: {new_key.key_id}")
        print(f"  Version: {new_key.version}")
        print(f"  Created: {time.ctime(new_key.created)}")
        print(f"  Expires: {time.ctime(new_key.expires)}")
        print(f"  Metadata: {new_key.metadata}")
    
    def demo_key_export(self):
        """Demonstrate secure key export"""
        print("\n--- KEY EXPORT DEMO ---")
        
        # Generate sample keys
        keys = {
            'master_key': self.fde.generate_secure_key(),
            'file_encryption_key': self.fde.generate_secure_key(),
            'database_key': self.fde.generate_secure_key()
        }
        
        passphrase = getpass.getpass("Enter export passphrase: ")
        verify_passphrase = getpass.getpass("Verify passphrase: ")
        
        if passphrase != verify_passphrase:
            print("Error: Passphrases do not match!")
            return
        
        # Export key bundle
        bundle = self.key_manager.export_key_bundle(keys, passphrase)
        
        # Save to file
        filename = f"key_backup_{int(time.time())}.json"
        with open(filename, 'w') as f:
            f.write(bundle)
        
        print(f"Key bundle exported to: {filename}")
        print("This file contains encrypted keys and should be stored securely!")

def main():
    """Main function"""
    demo = EncryptionDemoCLI()
    demo.run_demo()

if __name__ == "__main__":
    main()
