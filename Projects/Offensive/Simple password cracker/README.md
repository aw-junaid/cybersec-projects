## How to Run

### Basic Dictionary Attack
```bash
# Crack a single MD5 hash
python3 cracker.py --mode dict --hash-type md5 --target 5d41402abc4b2a76b9719d911017c592 --wordlist rockyou.txt

# Crack multiple hashes from a file
python3 cracker.py --mode dict --hash-type sha1 --target hashes.txt --wordlist passwords.txt

# With password mangling (more variations)
python3 cracker.py --mode dict --hash-type md5 --target <hash> --wordlist wordlist.txt --mangle
```

### Basic Brute-Force Attack
```bash
# 4-digit PIN (0-9)
python3 cracker.py --mode brute --hash-type md5 --target <hash> --charset "0123456789" --min-len 4 --max-len 4

# Lowercase letters, length 1-5
python3 cracker.py --mode brute --hash-type sha256 --target <hash> --charset "abcdefghijklmnopqrstuvwxyz" --max-len 5

# Alphanumeric + symbols
python3 cracker.py --mode brute --hash-type md5 --target <hash> --charset "abcdefghijklmnopqrstuvwxyz0123456789!@#$" --min-len 6 --max-len 8
```

### Advanced Examples
```bash
# Stop after first match found
python3 cracker.py --mode dict --hash-type md5 --target hashes.txt --wordlist rockyou.txt --stop-on-first

# Complex brute-force with confirmation
python3 cracker.py --mode brute --hash-type sha256 --target <hash> --charset "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" --min-len 1 --max-len 6
```

## Important Notes

1. **Legal Use Only**: Only use on systems you own or have explicit permission to test
2. **Performance**: Brute-force complexity grows exponentially with length and charset size
3. **Wordlists**: Common wordlists include rockyou.txt, SecLists, and custom dictionaries
4. **Hash Examples**: 
   - MD5 of "hello": `5d41402abc4b2a76b9719d911017c592`
   - SHA1 of "hello": `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`
   - SHA256 of "hello": `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`

The tool provides both dictionary attacks (fast but limited to known passwords) and brute-force attacks (comprehensive but slow).
