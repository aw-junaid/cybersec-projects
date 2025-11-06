#!/usr/bin/env python3
"""
gpu_md5_pyopencl.py
Educational demo: compute MD5 of a small candidate list on GPU (OpenCL via pyopencl)
Only for lab use and testing on hashes you own.

Install (Kali):
  sudo apt update
  sudo apt install -y python3-pip ocl-icd-opencl-dev
  pip3 install pyopencl

Run:
  python3 gpu_md5_pyopencl.py
"""

import binascii
import pyopencl as cl
import numpy as np
import hashlib

# --- CONFIG ---
# List of password candidates to test
CANDIDATES = ["password", "123456", "letmein", "passw0rd", "admin", "secret"]
# Target MD5 hash to find (this is the MD5 of 'secret' for demonstration)
TARGET_HEX = hashlib.md5(b"secret").hexdigest()  # change to your own hash if you test

# OpenCL kernel code that runs on the GPU
# This implements a simplified MD5 hashing algorithm optimized for GPU execution
KERNEL_SRC = r"""
// Minimal educational MD5 kernel: accepts fixed-length input blocks of 64 bytes and writes 16-byte digest.
// This implementation is intentionally compact and not optimized for performance.
// It supports inputs <= 55 bytes effectively (single-block MD5). For learning only.

// MD5 constant table - predefined constants used in the MD5 algorithm
__constant uint K[64] = {
  0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
  0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
  0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
  0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
  0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
  0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
  0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
  0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

// Bit rotation macro - rotates bits left by n positions
inline uint ROTATE(uint x, uint n) { return (x << n) | (x >> (32 - n)); }

// Main GPU kernel function - executed in parallel for each password candidate
__kernel void md5_kernel(__global const uchar *inblk,     // input blocks (N x 64 bytes)
                         __global uchar *outdigests,      // output digests (N x 16 bytes)
                         const uint stride) {
    int gid = get_global_id(0);  // Get unique thread ID (0, 1, 2, ...)
    const __global uchar *data = inblk + gid * stride; // stride=64
    
    // Load 64-byte input block as 16 little-endian 32-bit words
    uint M[16];
    for (int i=0;i<16;i++) {
        M[i] = (uint)data[i*4] | ((uint)data[i*4+1]<<8) | ((uint)data[i*4+2]<<16) | ((uint)data[i*4+3]<<24);
    }
    
    // MD5 initial hash values (standard initialization constants)
    uint a0 = 0x67452301;
    uint b0 = 0xefcdab89;
    uint c0 = 0x98badcfe;
    uint d0 = 0x10325476;
    uint A=a0,B=b0,C=c0,D=d0;
    
    // MD5 shift amounts for each round
    const uint s[] = { 7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                       5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                       4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                       6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    
    // Main MD5 computation loop - 64 rounds of processing
    for (int i=0;i<64;i++) {
        uint F, g;
        // Different functions for each round
        if (i < 16) { F = (B & C) | ((~B) & D); g = i; }
        else if (i < 32) { F = (D & B) | ((~D) & C); g = (5*i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3*i + 5) & 15; }
        else { F = C ^ (B | (~D)); g = (7*i) & 15; }
        
        // Update state variables
        uint tmp = D;
        D = C;
        C = B;
        uint sum = A + F + K[i] + M[g];
        B = B + ROTATE(sum, s[i]);
        A = tmp;
    }
    
    // Add initial values to final state (MD5 finalization)
    A += a0; B += b0; C += c0; D += d0;
    
    // Write output digest as 16 little-endian bytes
    uint out[4] = {A, B, C, D};
    for (int i=0;i<4;i++) {
        uint v = out[i];
        int off = (i*4);
        outdigests[gid*16 + off + 0] = (uchar)(v & 0xFF);
        outdigests[gid*16 + off + 1] = (uchar)((v>>8) & 0xFF);
        outdigests[gid*16 + off + 2] = (uchar)((v>>16) & 0xFF);
        outdigests[gid*16 + off + 3] = (uchar)((v>>24) & 0xFF);
    }
}
"""

def pad_to_block(s: bytes, block_size=64):
    """
    Apply MD5 padding to input data to create a 64-byte block.
    This follows the MD5 specification for messages that fit in one block.
    """
    l = len(s)
    if l > 55:
        raise ValueError("This demo supports inputs <=55 bytes")
    
    # Create 64-byte block filled with zeros
    b = bytearray(block_size)
    b[0:l] = s  # Copy original message
    b[l] = 0x80  # Append '1' bit followed by zeros (standard MD5 padding)
    
    # Append message length in bits as 64-bit little-endian integer
    bit_len = l * 8
    b[56:60] = np.frombuffer(np.uint32(bit_len).tobytes(), dtype=np.uint8)
    # Note: Upper 4 bytes remain zero for messages < 2^32 bits
    
    return bytes(b)

def main():
    """Main function that orchestrates the GPU MD5 cracking process"""
    print(f"Target MD5 hash: {TARGET_HEX}")
    print(f"Candidates to test: {CANDIDATES}")
    print("Preparing data for GPU processing...")
    
    # Step 1: Prepare input data for GPU
    # Convert each candidate to properly padded MD5 blocks
    cand_bytes = [pad_to_block(c.encode('utf-8')) for c in CANDIDATES]
    N = len(cand_bytes)
    buf = b"".join(cand_bytes)  # Concatenate all blocks into one buffer

    # Step 2: Initialize OpenCL (GPU/CPU compute framework)
    print("Initializing OpenCL...")
    ctx = cl.create_some_context()  # Automatically selects available OpenCL device
    queue = cl.CommandQueue(ctx)    # Command queue for executing operations
    mf = cl.mem_flags
    
    # Step 3: Create GPU memory buffers
    # Input buffer: contains all padded password candidates
    inbuf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=buf)
    # Output buffer: will store computed MD5 hashes (16 bytes per candidate)
    outbuf = cl.Buffer(ctx, mf.WRITE_ONLY, size=N * 16)

    # Step 4: Compile and build the OpenCL kernel
    print("Compiling MD5 kernel...")
    prg = cl.Program(ctx, KERNEL_SRC).build()
    
    # Step 5: Execute the kernel on GPU
    stride = np.uint32(64)  # Each input block is 64 bytes
    print("Executing MD5 computation on GPU...")
    prg.md5_kernel(queue, (N,), None, inbuf, outbuf, stride)

    # Step 6: Copy results back from GPU to CPU
    out = np.empty(N * 16, dtype=np.uint8)
    cl.enqueue_copy(queue, out, outbuf).wait()

    # Step 7: Analyze results
    print("\n=== RESULTS ===")
    target = bytes.fromhex(TARGET_HEX)  # Convert target hex string to bytes
    found = False
    
    # Check each computed hash against the target
    for i in range(N):
        digest = bytes(out[i*16:(i+1)*16])  # Extract 16-byte MD5 hash
        if digest == target:
            print(f"🎯 [MATCH FOUND] candidate='{CANDIDATES[i]}' md5={TARGET_HEX}")
            found = True
            break  # Stop after first match
    
    if not found:
        print("❌ No matches found in this batch.")
    
    # Display all computed hashes for educational purposes
    print("\nAll computed hashes:")
    for i in range(N):
        hash_hex = binascii.hexlify(bytes(out[i*16:(i+1)*16])).decode()
        print(f"  {CANDIDATES[i]:<12} -> {hash_hex}")

if __name__ == "__main__":
    main()
