# Full-Disk Encryption Demo & Key Management - Best Practices

## What this tool is for:
This educational tool demonstrates full-disk encryption concepts and implements proper cryptographic key management practices. It shows how encryption works at the disk level and provides secure key generation, storage, rotation, and recovery mechanisms.

## Algorithm Overview:
1. **Key Generation**: Use cryptographically secure random number generation
2. **Encryption Process**: 
   - Read disk sectors/chunks
   - Apply AES-XTS encryption (standard for disk encryption)
   - Write encrypted data
3. **Key Management**:
   - Secure key storage with proper access controls
   - Key rotation and versioning
   - Backup and recovery procedures
4. **Master Key Protection**: 
   - Key derivation from passphrase (PBKDF2)
   - Key splitting for recovery
   - Secure key escrow

## How to Run the Code

### Python Version:
```bash
# Install required dependencies
pip install cryptography

# Run the demo
python fde_demo.py
```

### C Version:
```bash
# Install OpenSSL development libraries
sudo apt-get install libssl-dev  # Ubuntu/Debian

# Compile the C code
gcc -o fde_demo fde_demo.c -lssl -lcrypto

# Run the demo
./fde_demo
```

## Key Management Best Practices Demonstrated:

1. **Secure Key Generation**: Using cryptographically secure random number generators
2. **Key Derivation**: PBKDF2 for passphrase-based key derivation
3. **Key Rotation**: Regular key updates with grace periods
4. **Key Splitting**: Shamir's Secret Sharing for recovery
5. **Secure Storage**: Encrypted key bundles with proper access controls
6. **Key Hierarchy**: Master keys, key encryption keys, and data keys
7. **Key Expiration**: Time-based key validity periods
8. **Secure Backup**: Encrypted key export with strong passphrase protection
