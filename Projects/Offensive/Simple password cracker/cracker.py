#!/usr/bin/env python3
"""
cracker.py - simple educational password cracker (dictionary + brute-force)

AUTHORIZED USE ONLY: This tool is intended for educational purposes, 
security research, and authorized penetration testing only.

Usage examples:
  # Dictionary attack on MD5 hash
  python3 cracker.py --mode dict --hash-type md5 --target d41d8cd98f00b204e9800998ecf8427e --wordlist rockyou.txt

  # Brute-force SHA256 hash with lowercase letters, max length 5
  python3 cracker.py --mode brute --hash-type sha256 --target <hash> --charset abcdefghijklmnopqrstuvwxyz --max-len 5

  # Brute-force with custom charset (alphanumeric + symbols)
  python3 cracker.py --mode brute --hash-type md5 --target <hash> --charset "abcdefghijklmnopqrstuvwxyz0123456789!@#$" --min-len 4 --max-len 6

  # Dictionary attack with password mangling
  python3 cracker.py --mode dict --hash-type sha1 --target <hash> --wordlist passwords.txt --mangle

  # Attack multiple hashes from a file
  python3 cracker.py --mode dict --hash-type md5 --target hashes.txt --wordlist rockyou.txt --stop-on-first

Supported hash types: md5, sha1, sha256
"""

import argparse
import hashlib
import itertools
import sys
import os
from typing import Callable

# Dictionary mapping hash algorithm names to hashlib functions
HASH_FUNCS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Educational password cracker (dictionary + brute-force)")
    
    # Required arguments
    parser.add_argument("--mode", choices=["dict", "brute"], required=True, 
                       help="Operation mode: 'dict' for dictionary attacks, 'brute' for brute-force")
    parser.add_argument("--hash-type", choices=HASH_FUNCS.keys(), required=True,
                       help="Hash algorithm used for the target hashes")
    parser.add_argument("--target", required=True,
                       help="Target hash (hex string) or file containing newline-separated hashes")
    
    # Dictionary mode arguments
    parser.add_argument("--wordlist", 
                       help="Wordlist file path (required for dictionary mode)")
    parser.add_argument("--mangle", action="store_true",
                       help="Apply basic mangling to dictionary words (lower/upper/capital + common suffixes)")
    
    # Brute-force mode arguments  
    parser.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789",
                       help="Character set for brute-force attacks")
    parser.add_argument("--min-len", type=int, default=1,
                       help="Minimum password length for brute-force")
    parser.add_argument("--max-len", type=int, default=4,
                       help="Maximum password length for brute-force (WARNING: high values cause exponential growth)")
    
    # Common options
    parser.add_argument("--stop-on-first", action="store_true",
                       help="Stop after finding first match (useful for single hash targets)")
    
    return parser.parse_args()

def load_targets(target_arg):
    """
    Load target hashes from either a single hash string or a file
    
    Args:
        target_arg: Either a hash string or path to a file containing hashes
        
    Returns:
        List of target hash strings (lowercase)
    """
    if os.path.exists(target_arg):
        # Read hashes from file (one per line)
        with open(target_arg, "r") as f:
            return [line.strip().lower() for line in f if line.strip()]
    else:
        # Single hash provided directly
        return [target_arg.strip().lower()]

def hash_candidate(candidate: str, algo_name: str) -> str:
    """
    Hash a password candidate using the specified algorithm
    
    Args:
        candidate: Password string to hash
        algo_name: Hash algorithm name (md5/sha1/sha256)
        
    Returns:
        Hexadecimal hash string
    """
    hfunc = HASH_FUNCS[algo_name]
    h = hfunc()
    h.update(candidate.encode("utf-8", errors="ignore"))
    return h.hexdigest().lower()

def dict_mode(wordlist_path: str, algo: str, targets, mangle: bool, stop_on_first: bool):
    """
    Perform dictionary attack using a wordlist
    
    Args:
        wordlist_path: Path to wordlist file
        algo: Hash algorithm name
        targets: List of target hashes to crack
        mangle: Whether to apply password mangling rules
        stop_on_first: Stop after first successful crack
        
    Returns:
        True if any password was cracked, False otherwise
    """
    if not wordlist_path or not os.path.exists(wordlist_path):
        print("ERROR: valid --wordlist required for dict mode.", file=sys.stderr)
        sys.exit(2)
    
    found_any = False
    with open(wordlist_path, "r", errors="ignore") as f:
        for line_num, raw in enumerate(f, 1):
            word = raw.rstrip("\n\r")
            candidates = [word]
            
            # Apply password mangling if requested
            if mangle:
                # Basic mangling: different case variations and common suffixes
                candidates = list({word, word.lower(), word.upper(), word.title()})
                
                # Add common suffixes to base variations
                for base in list(candidates):
                    candidates.append(base + "1")      # Add '1'
                    candidates.append(base + "123")    # Add '123'  
                    candidates.append(base + "!")      # Add '!'
            
            # Test each candidate variation
            for cand in candidates:
                h = hash_candidate(cand, algo)
                
                # Check against all target hashes
                for target_hash in targets:
                    if h == target_hash:
                        print(f"[FOUND] {target_hash} -> '{cand}' (dict)")
                        found_any = True
                        if stop_on_first:
                            return True
            
            # Optional: progress indicator for large wordlists
            if line_num % 10000 == 0:
                print(f"[*] Processed {line_num} words...")
    
    return found_any

def brute_mode(charset: str, min_len: int, max_len: int, algo: str, targets, stop_on_first: bool):
    """
    Perform brute-force attack by generating all possible combinations
    
    Args:
        charset: Characters to use in brute-force
        min_len: Minimum password length  
        max_len: Maximum password length
        algo: Hash algorithm name
        targets: List of target hashes to crack
        stop_on_first: Stop after first successful crack
        
    Returns:
        True if any password was cracked, False otherwise
    """
    found_any = False
    
    # Iterate through each password length
    for length in range(min_len, max_len + 1):
        # Calculate number of combinations for this length
        combinations = len(charset) ** length
        print(f"[+] Trying length {length} ({combinations} combinations)...")
        
        # Generate all possible combinations of given length
        for char_tuple in itertools.product(charset, repeat=length):
            candidate = ''.join(char_tuple)
            hash_value = hash_candidate(candidate, algo)
            
            # Check against all target hashes
            for target_hash in targets:
                if hash_value == target_hash:
                    print(f"[FOUND] {target_hash} -> '{candidate}' (bruteforce, len={length})")
                    found_any = True
                    if stop_on_first:
                        return True
        
        print(f"[*] Completed length {length}")
    
    return found_any

def main():
    """Main function - orchestrate the cracking process"""
    args = parse_args()
    
    # Load target hashes
    targets = load_targets(args.target)
    print(f"[+] Mode: {args.mode}, Hash: {args.hash_type}, Targets: {len(targets)}")
    
    # Safety warning for high-complexity brute-force
    if args.mode == "brute":
        if args.max_len > 6 and len(args.charset) > 36:
            print("WARNING: High-complexity brute-force detected!")
            print(f"         Charset size: {len(args.charset)}, Max length: {args.max_len}")
            print("         This may take extremely long or be infeasible.")
            response = input("Continue? (y/N): ")
            if response.lower() != 'y':
                print("Aborted.")
                sys.exit(0)
    
    # Execute the appropriate attack mode
    if args.mode == "dict":
        found = dict_mode(args.wordlist, args.hash_type, targets, args.mangle, args.stop_on_first)
    else:  # brute mode
        found = brute_mode(args.charset, args.min_len, args.max_len, args.hash_type, targets, args.stop_on_first)
    
    # Final status
    if not found:
        print("[+] Completed. No matches found (or search exhausted).")

if __name__ == "__main__":
    main()
