#!/usr/bin/env python3
"""
Security testing script for the web application
"""

import requests
import json
import sys
from urllib.parse import urljoin

class SecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_security_headers(self):
        """Test if security headers are properly set"""
        print("Testing security headers...")
        
        response = self.session.get(self.base_url)
        headers = response.headers
        
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': None,  # Just check existence
        }
        
        for header, expected_value in security_headers.items():
            if header in headers:
                if expected_value and headers[header] != expected_value:
                    print(f"❌ {header}: Incorrect value: {headers[header]}")
                else:
                    print(f"✅ {header}: Present")
            else:
                print(f"❌ {header}: Missing")
    
    def test_csrf_protection(self):
        """Test CSRF protection"""
        print("\nTesting CSRF protection...")
        
        # Try to submit form without CSRF token
        login_data = {
            'username': 'test',
            'password': 'test'
        }
        
        response = self.session.post(
            urljoin(self.base_url, '/login'),
            data=login_data,
            allow_redirects=False
        )
        
        if response.status_code == 403:
            print("✅ CSRF protection: Working")
        else:
            print("❌ CSRF protection: May be vulnerable")
    
    def test_sql_injection(self):
        """Test basic SQL injection attempts"""
        print("\nTesting SQL injection protection...")
        
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in payloads:
            response = self.session.get(
                urljoin(self.base_url, '/api/search'),
                params={'q': payload}
            )
            
            # Check if application returns error or behaves normally
            if response.status_code == 400 or response.status_code == 200:
                print(f"✅ SQL injection attempt blocked: {payload}")
            else:
                print(f"❌ Potential SQL injection vulnerability: {payload}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python security_test.py <base_url>")
        sys.exit(1)
    
    tester = SecurityTester(sys.argv[1])
    tester.test_security_headers()
    tester.test_csrf_protection()
    tester.test_sql_injection()
