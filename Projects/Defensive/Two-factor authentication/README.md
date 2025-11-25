# Two-Factor Authentication Demo Implementation

### What the Tool Is For:
This tool demonstrates 2FA implementation with TOTP, SMS, and backup codes, while also showing common vulnerabilities and bypass techniques for educational purposes in security testing.

### About:
Two-factor authentication adds an extra layer of security beyond passwords. This demo shows proper implementation while also demonstrating how attackers might bypass weak 2FA implementations, helping developers understand both defensive and offensive perspectives.

##  How to Run the Code

### Python Version:
```bash
# Install dependencies
pip3 install qrcode[pil] pyopenssl

# Register a user
python3 2fa_demo.py register alice password123 --phone +1234567890

# Enable TOTP 2FA
python3 2fa_demo.py enable-2fa alice --method totp

# Enable SMS 2FA
python3 2fa_demo.py enable-2fa alice --method sms

# Login with 2FA
python3 2fa_demo.py login alice password123 --code 123456

# Generate QR code for authenticator app
python3 2fa_demo.py qr alice MyApp --output qr.png

# Run security tests
python3 2fa_demo.py test
```

### C Version:
```bash
# Compile with dependencies
gcc -o 2fa_demo 2fa_demo.c -lssl -lcrypto -lsqlite3

# Register user
./2fa_demo register alice password123 +1234567890

# Enable 2FA
./2fa_demo enable-2fa alice totp

# Login
./2fa_demo login alice password123

# Verify 2FA code (use session ID from login)
./2fa_demo verify SESSION_ID 123456
```

---

##  Algorithm Explanation

### How the 2FA Implementation Works:

**TOTP (Time-based One-Time Password):**
1. **Secret Generation** - Random base32 string shared with user
2. **Time Calculation** - Current time divided into 30-second intervals
3. **HMAC-SHA1** - Hash-based message authentication code
4. **Dynamic Truncation** - Extract 31-bit number from HMAC result
5. **Digit Conversion** - Convert to 6-digit code

**SMS-based 2FA:**
1. **Code Generation** - Random 6-digit number
2. **Delivery Simulation** - "Send" via SMS (prints to console)
3. **Expiry Management** - Codes valid for 10 minutes
4. **Single Use** - Codes consumed after verification

**Backup Codes:**
1. **Generation** - Create set of unique recovery codes
2. **Storage** - Store as one-time use tokens
3. **Verification** - Check and consume on use
4. **Regeneration** - Allow new code generation when depleted

**Security Features:**
- Rate limiting on failed attempts
- Session timeouts
- Constant-time comparison
- Code expiry
- Brute force protection
