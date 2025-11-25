#!/usr/bin/env python3
"""
Two-Factor Authentication Demo Implementation - Python
Includes TOTP, SMS, backup codes, and security testing
"""

import hashlib
import hmac
import base64
import secrets
import time
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import argparse
import qrcode
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
import random

class TOTPGenerator:
    """Time-based One-Time Password generator (RFC 6238)"""
    
    def __init__(self, secret: str = None, digits: int = 6, interval: int = 30):
        self.digits = digits
        self.interval = interval
        self.secret = secret or self.generate_secret()
    
    @staticmethod
    def generate_secret(length: int = 20) -> str:
        """Generate a random secret key"""
        return base64.b32encode(secrets.token_bytes(length)).decode('utf-8')
    
    def generate_totp(self, timestamp: int = None) -> str:
        """Generate TOTP code for current time"""
        if timestamp is None:
            timestamp = int(time.time())
        
        time_counter = timestamp // self.interval
        time_bytes = time_counter.to_bytes(8, byteorder='big')
        
        # Decode secret
        secret_bytes = base64.b32decode(self.secret, casefold=True)
        
        # Generate HMAC-SHA1
        hmac_hash = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0xf
        code = ((hmac_hash[offset] & 0x7f) << 24 |
                (hmac_hash[offset + 1] & 0xff) << 16 |
                (hmac_hash[offset + 2] & 0xff) << 8 |
                (hmac_hash[offset + 3] & 0xff))
        
        # Convert to digit string
        code = code % (10 ** self.digits)
        return str(code).zfill(self.digits)
    
    def verify_totp(self, code: str, timestamp: int = None, window: int = 1) -> bool:
        """Verify TOTP code with time window"""
        if timestamp is None:
            timestamp = int(time.time())
        
        # Check current and previous intervals
        for i in range(-window, window + 1):
            expected_code = self.generate_totp(timestamp + i * self.interval)
            if hmac.compare_digest(code, expected_code):
                return True
        return False
    
    def get_provisioning_uri(self, username: str, issuer: str) -> str:
        """Generate Google Authenticator provisioning URI"""
        return (f"otpauth://totp/{issuer}:{username}?"
                f"secret={self.secret}&issuer={issuer}&digits={self.digits}&period={self.interval}")

class SMSAuthenticator:
    """SMS-based 2FA implementation"""
    
    def __init__(self):
        self.sent_codes = {}  # phone -> (code, expiry)
    
    def generate_sms_code(self, digits: int = 6) -> str:
        """Generate random SMS code"""
        return ''.join([str(random.randint(0, 9)) for _ in range(digits)])
    
    def send_sms_code(self, phone_number: str, code: str) -> bool:
        """Simulate sending SMS code"""
        print(f"[SMS] Sending code {code} to {phone_number}")
        
        # Store code with expiry (10 minutes)
        expiry = datetime.now() + timedelta(minutes=10)
        self.sent_codes[phone_number] = (code, expiry)
        return True
    
    def verify_sms_code(self, phone_number: str, code: str) -> bool:
        """Verify SMS code"""
        if phone_number not in self.sent_codes:
            return False
        
        stored_code, expiry = self.sent_codes[phone_number]
        
        # Check expiry
        if datetime.now() > expiry:
            del self.sent_codes[phone_number]
            return False
        
        # Verify code
        if hmac.compare_digest(code, stored_code):
            del self.sent_codes[phone_number]
            return True
        
        return False

class BackupCodeManager:
    """Backup codes for 2FA recovery"""
    
    def __init__(self):
        self.backup_codes = {}  # user_id -> set of codes
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes"""
        codes = set()
        while len(codes) < count:
            code = f"{secrets.randbelow(1000000):06d}-{secrets.randbelow(1000000):06d}"
            codes.add(code)
        return list(codes)
    
    def assign_backup_codes(self, user_id: str) -> List[str]:
        """Assign new backup codes to user"""
        codes = self.generate_backup_codes()
        self.backup_codes[user_id] = set(codes)  # Store as set for easy removal
        return codes
    
    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify and consume backup code"""
        if user_id not in self.backup_codes:
            return False
        
        if code in self.backup_codes[user_id]:
            self.backup_codes[user_id].remove(code)
            return True
        
        return False
    
    def get_remaining_codes(self, user_id: str) -> int:
        """Get number of remaining backup codes"""
        return len(self.backup_codes.get(user_id, []))

class TwoFactorAuth:
    """Main 2FA implementation with multiple methods"""
    
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.init_database()
        
        self.totp = TOTPGenerator()
        self.sms_auth = SMSAuthenticator()
        self.backup_mgr = BackupCodeManager()
        
        # User sessions
        self.sessions = {}  # session_id -> user_data
        self.failed_attempts = {}  # user_id -> count
    
    def init_database(self):
        """Initialize user database"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                phone_number TEXT,
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                two_factor_method TEXT DEFAULT 'totp',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                success BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT
            )
        ''')
        
        self.conn.commit()
    
    def register_user(self, username: str, password: str, phone: str = None) -> Dict[str, Any]:
        """Register new user"""
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash, phone_number) VALUES (?, ?, ?)',
                (username, password_hash, phone)
            )
            self.conn.commit()
            
            return {
                'success': True,
                'user_id': cursor.lastrowid,
                'message': 'User registered successfully'
            }
        except sqlite3.IntegrityError:
            return {
                'success': False,
                'message': 'Username already exists'
            }
    
    def enable_2fa(self, username: str, method: str = 'totp') -> Dict[str, Any]:
        """Enable 2FA for user"""
        cursor = self.conn.cursor()
        
        if method == 'totp':
            # Generate TOTP secret
            totp_secret = TOTPGenerator.generate_secret()
            cursor.execute(
                'UPDATE users SET two_factor_enabled = TRUE, two_factor_method = ?, totp_secret = ? WHERE username = ?',
                (method, totp_secret, username)
            )
            
            # Generate backup codes
            backup_codes = self.backup_mgr.assign_backup_codes(username)
            
            self.conn.commit()
            
            return {
                'success': True,
                'totp_secret': totp_secret,
                'backup_codes': backup_codes,
                'message': '2FA enabled with TOTP'
            }
        
        elif method == 'sms':
            cursor.execute(
                'UPDATE users SET two_factor_enabled = TRUE, two_factor_method = ? WHERE username = ?',
                (method, username)
            )
            
            # Generate backup codes
            backup_codes = self.backup_mgr.assign_backup_codes(username)
            
            self.conn.commit()
            
            return {
                'success': True,
                'backup_codes': backup_codes,
                'message': '2FA enabled with SMS'
            }
        
        return {'success': False, 'message': 'Invalid 2FA method'}
    
    def login_step1(self, username: str, password: str) -> Dict[str, Any]:
        """First login step - verify credentials"""
        # Check rate limiting
        if self.failed_attempts.get(username, 0) >= 5:
            return {
                'success': False,
                'message': 'Account temporarily locked due to too many failed attempts'
            }
        
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT id, password_hash, two_factor_enabled, two_factor_method, totp_secret, phone_number FROM users WHERE username = ?',
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            self._record_login_attempt(username, False)
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            return {
                'success': False,
                'message': 'Invalid credentials'
            }
        
        user_id, password_hash, two_factor_enabled, two_factor_method, totp_secret, phone_number = user
        
        # Verify password
        if hashlib.sha256(password.encode()).hexdigest() != password_hash:
            self._record_login_attempt(username, False)
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            return {
                'success': False,
                'message': 'Invalid credentials'
            }
        
        # Generate session token for second step
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            'user_id': user_id,
            'username': username,
            'two_factor_enabled': two_factor_enabled,
            'two_factor_method': two_factor_method,
            'totp_secret': totp_secret,
            'phone_number': phone_number,
            'expires': datetime.now() + timedelta(minutes=10)
        }
        
        self._record_login_attempt(username, True)
        
        result = {
            'success': True,
            'session_token': session_token,
            'two_factor_required': two_factor_enabled,
            'two_factor_method': two_factor_method
        }
        
        # If 2FA enabled, initiate second factor
        if two_factor_enabled:
            if two_factor_method == 'sms' and phone_number:
                sms_code = self.sms_auth.generate_sms_code()
                self.sms_auth.send_sms_code(phone_number, sms_code)
                result['message'] = 'SMS code sent to your phone'
            elif two_factor_method == 'totp':
                result['message'] = 'Enter your TOTP code'
        
        return result
    
    def login_step2(self, session_token: str, code: str, use_backup_code: bool = False) -> Dict[str, Any]:
        """Second login step - verify 2FA code"""
        if session_token not in self.sessions:
            return {
                'success': False,
                'message': 'Invalid or expired session'
            }
        
        session = self.sessions[session_token]
        
        # Check session expiry
        if datetime.now() > session['expires']:
            del self.sessions[session_token]
            return {
                'success': False,
                'message': 'Session expired'
            }
        
        # If 2FA not enabled, proceed directly
        if not session['two_factor_enabled']:
            del self.sessions[session_token]
            return {
                'success': True,
                'user_id': session['user_id'],
                'username': session['username'],
                'message': 'Login successful'
            }
        
        # Verify 2FA code
        verification_success = False
        
        if use_backup_code:
            verification_success = self.backup_mgr.verify_backup_code(session['username'], code)
        else:
            if session['two_factor_method'] == 'totp':
                totp = TOTPGenerator(session['totp_secret'])
                verification_success = totp.verify_totp(code)
            elif session['two_factor_method'] == 'sms':
                verification_success = self.sms_auth.verify_sms_code(session['phone_number'], code)
        
        if verification_success:
            del self.sessions[session_token]
            self.failed_attempts.pop(session['username'], None)  # Reset failed attempts
            
            return {
                'success': True,
                'user_id': session['user_id'],
                'username': session['username'],
                'message': 'Login successful'
            }
        else:
            return {
                'success': False,
                'message': 'Invalid 2FA code'
            }
    
    def _record_login_attempt(self, username: str, success: bool):
        """Record login attempt for auditing"""
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT INTO login_attempts (username, success) VALUES (?, ?)',
            (username, success)
        )
        self.conn.commit()

class TwoFactorBypassTester:
    """Test 2FA bypass techniques for educational purposes"""
    
    def __init__(self, two_fa: TwoFactorAuth):
        self.two_fa = two_fa
    
    def test_weak_code_entropy(self):
        """Test if codes have weak entropy"""
        print("\n[TEST] Weak Code Entropy Analysis")
        
        # Generate sample codes and check patterns
        sample_codes = [self.two_fa.sms_auth.generate_sms_code() for _ in range(1000)]
        
        # Check for repeated codes
        unique_codes = len(set(sample_codes))
        print(f"Unique codes in 1000 samples: {unique_codes}/1000")
        
        if unique_codes < 990:
            print("⚠️  WARNING: Low code entropy detected")
    
    def test_time_based_attacks(self):
        """Test timing attacks on code verification"""
        print("\n[TEST] Timing Attack Analysis")
        
        # This would measure response times for valid vs invalid codes
        print("Timing attack simulation not implemented (requires precise timing)")
        print("Recommendation: Use constant-time comparison (hmac.compare_digest)")
    
    def test_code_reuse(self):
        """Test if codes can be reused"""
        print("\n[TEST] Code Reuse Vulnerability")
        
        # Simulate code reuse attempt
        username = "test_user"
        phone = "+1234567890"
        
        # Register test user
        self.two_fa.register_user(username, "password123", phone)
        self.two_fa.enable_2fa(username, "sms")
        
        # Get a code
        sms_code = self.two_fa.sms_auth.generate_sms_code()
        self.two_fa.sms_auth.send_sms_code(phone, sms_code)
        
        # Try to reuse the code
        session = self.two_fa.login_step1(username, "password123")
        result1 = self.two_fa.login_step2(session['session_token'], sms_code)
        result2 = self.two_fa.login_step2(session['session_token'], sms_code)
        
        if result1['success'] and result2['success']:
            print("⚠️  CRITICAL: Code reuse vulnerability detected!")
        else:
            print("✅ Code reuse prevented")
    
    def test_brute_force_protection(self):
        """Test brute force protection"""
        print("\n[TEST] Brute Force Protection")
        
        username = "brute_test"
        password = "password123"
        
        # Register user
        self.two_fa.register_user(username, password)
        
        # Simulate multiple failed attempts
        for i in range(6):
            result = self.two_fa.login_step1(username, "wrong_password")
            print(f"Attempt {i+1}: {result.get('message', 'Unknown')}")
        
        # Check if account is locked
        result = self.two_fa.login_step1(username, password)
        if "locked" in result.get('message', '').lower():
            print("✅ Brute force protection working")
        else:
            print("⚠️  WARNING: Brute force protection weak")
    
    def run_all_tests(self):
        """Run all security tests"""
        print("=== 2FA Security Testing ===")
        self.test_weak_code_entropy()
        self.test_time_based_attacks()
        self.test_code_reuse()
        self.test_brute_force_protection()

def generate_qr_code(provisioning_uri: str, output_file: str = None):
    """Generate QR code for TOTP setup"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    if output_file:
        img.save(output_file)
        print(f"[+] QR code saved to {output_file}")
    else:
        # Display in terminal (basic representation)
        print("[QR Code] - Use a QR code generator for better visualization")
        print(f"Provisioning URI: {provisioning_uri}")

def main():
    parser = argparse.ArgumentParser(description='Two-Factor Authentication Demo')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Register command
    register_parser = subparsers.add_parser('register', help='Register new user')
    register_parser.add_argument('username', help='Username')
    register_parser.add_argument('password', help='Password')
    register_parser.add_argument('--phone', help='Phone number for SMS 2FA')
    
    # Enable 2FA command
    enable_parser = subparsers.add_parser('enable-2fa', help='Enable 2FA for user')
    enable_parser.add_argument('username', help='Username')
    enable_parser.add_argument('--method', choices=['totp', 'sms'], default='totp', help='2FA method')
    
    # Login command
    login_parser = subparsers.add_parser('login', help='Login with 2FA')
    login_parser.add_argument('username', help='Username')
    login_parser.add_argument('password', help='Password')
    login_parser.add_argument('--code', help='2FA code')
    login_parser.add_argument('--backup-code', action='store_true', help='Use backup code')
    
    # Security testing command
    test_parser = subparsers.add_parser('test', help='Run security tests')
    
    # Generate QR code command
    qr_parser = subparsers.add_parser('qr', help='Generate QR code for TOTP')
    qr_parser.add_argument('username', help='Username')
    qr_parser.add_argument('issuer', help='Issuer name')
    qr_parser.add_argument('--output', help='Output file for QR code')
    
    args = parser.parse_args()
    
    two_fa = TwoFactorAuth()
    
    if args.command == 'register':
        result = two_fa.register_user(args.username, args.password, args.phone)
        print(json.dumps(result, indent=2))
    
    elif args.command == 'enable-2fa':
        result = two_fa.enable_2fa(args.username, args.method)
        print(json.dumps(result, indent=2))
        
        if args.method == 'totp' and result['success']:
            totp = TOTPGenerator(result['totp_secret'])
            uri = totp.get_provisioning_uri(args.username, "2FADemo")
            print(f"\nTOTP Setup URI: {uri}")
            print(f"Backup codes: {result['backup_codes']}")
    
    elif args.command == 'login':
        # Step 1: Verify credentials
        step1_result = two_fa.login_step1(args.username, args.password)
        print("Step 1:", json.dumps(step1_result, indent=2))
        
        if step1_result['success'] and step1_result.get('two_factor_required'):
            if args.code:
                # Step 2: Verify 2FA code
                step2_result = two_fa.login_step2(
                    step1_result['session_token'], 
                    args.code, 
                    args.backup_code
                )
                print("Step 2:", json.dumps(step2_result, indent=2))
            else:
                print("\n2FA required. Provide --code argument with your 2FA code")
        
        elif step1_result['success']:
            print("Login successful (no 2FA enabled)")
    
    elif args.command == 'test':
        tester = TwoFactorBypassTester(two_fa)
        tester.run_all_tests()
    
    elif args.command == 'qr':
        # Generate a TOTP secret and QR code
        totp = TOTPGenerator()
        uri = totp.get_provisioning_uri(args.username, args.issuer)
        generate_qr_code(uri, args.output)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
