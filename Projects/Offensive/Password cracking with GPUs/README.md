## How to Use This GPU MD5 Cracker

### Installation Requirements

**On Kali Linux:**
```bash
sudo apt update
sudo apt install -y python3-pip ocl-icd-opencl-dev
pip3 install pyopencl numpy
```

**On Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3-pip ocl-icd-libopencl1
pip3 install pyopencl numpy
```

**On Windows:**
```bash
pip install pyopencl numpy
# You may need to install OpenCL drivers from your GPU manufacturer
```

### Basic Usage

1. **Save the script** as `gpu_md5_cracker.py`

2. **Run the script:**
```bash
python3 gpu_md5_cracker.py
```

### Example Output
```
Target MD5 hash: 5ebe2294ecd0e0f08eab7690d2a6ee69
Candidates to test: ['password', '123456', 'letmein', 'passw0rd', 'admin', 'secret']
Preparing data for GPU processing...
Initializing OpenCL...
Compiling MD5 kernel...
Executing MD5 computation on GPU...

=== RESULTS ===
🎯 [MATCH FOUND] candidate='secret' md5=5ebe2294ecd0e0f08eab7690d2a6ee69

All computed hashes:
  password     -> 5f4dcc3b5aa765d61d8327deb882cf99
  123456       -> e10adc3949ba59abbe56e057f20f883e
  letmein      -> 0d107d09f5bbe40cade3de5c71e9e9b7
  passw0rd     -> bed128365216c019988915ed3add75fb
  admin        -> 21232f297a57a5a743894a0e4a801fc3
  secret       -> 5ebe2294ecd0e0f08eab7690d2a6ee69
```

### Customizing for Your Needs

**1. Change the target hash:**
```python
# Replace the demo target with your own MD5 hash
TARGET_HEX = "5d41402abc4b2a76b9719d911017c592"  # MD5 of "hello"
```

**2. Add more password candidates:**
```python
CANDIDATES = [
    "password", "123456", "hello", "welcome", 
    "qwerty", "password123", "admin123", "letmein"
]
```

**3. Use a wordlist file:**
```python
# Read candidates from a file
with open("wordlist.txt", "r") as f:
    CANDIDATES = [line.strip() for line in f.readlines()[:1000]]  # First 1000 lines
```

### Advanced Usage

**Testing with your own hashes:**
```python
# Generate MD5 hash of a known password
import hashlib
password = "mypassword"
hash_value = hashlib.md5(password.encode()).hexdigest()
print(f"MD5 of '{password}': {hash_value}")

# Use this hash as your target
TARGET_HEX = hash_value
CANDIDATES = ["password", "123456", "mypassword", "admin"]
```

**Performance Testing:**
```python
# Add timing to measure performance
import time
start_time = time.time()
# ... existing code ...
end_time = time.time()
print(f"GPU computation time: {end_time - start_time:.4f} seconds")
```

### Important Notes

⚠️ **Legal and Ethical Considerations:**
- **FOR EDUCATIONAL USE ONLY** - This demonstrates GPU computing concepts
- Only test on hashes you own or have explicit permission to crack
- Unauthorized password cracking may be illegal
- Use responsibly in lab environments

**Technical Limitations:**
- This demo only handles passwords ≤55 characters
- Production MD5 crackers are much more optimized
- Real tools handle salts, multiple hash types, and larger wordlists

**Supported Platforms:**
- Works on systems with OpenCL support (most modern GPUs)
- Falls back to CPU if no GPU available
- Tested on NVIDIA, AMD, and Intel graphics

### Troubleshooting

**"pyopencl not found" error:**
```bash
pip3 install --upgrade pip
pip3 install pyopencl
```

**"No OpenCL platforms found" error:**
- Install GPU drivers (NVIDIA, AMD, or Intel)
- On some systems, install: `sudo apt install beignet` (Intel)

**Memory errors with large wordlists:**
- Reduce the number of candidates
- The demo is optimized for small batches for educational purposes

This tool demonstrates the massive parallel processing power of GPUs for cryptographic operations, which is why modern password security requires strong, unique passwords and proper hashing algorithms like bcrypt or Argon2.
