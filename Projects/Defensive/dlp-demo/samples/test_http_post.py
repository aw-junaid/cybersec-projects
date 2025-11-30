#!/usr/bin/env python3
"""
Synthetic HTTP POST exfiltration test
LAB USE ONLY - NEVER RUN AGAINST PRODUCTION
"""

import requests
import json
import argparse
import base64
from dlptools.safety import SafetyChecker

def test_http_post_exfil(target_url, confirm_token=None):
    """Test HTTP POST data exfiltration detection"""
    SafetyChecker.verify_lab_mode()
    
    if confirm_token:
        SafetyChecker.confirm_destructive_action(confirm_token)
    
    # Synthetic sensitive data
    test_data = {
        "fake_credit_cards": [
            "4111-1111-1111-1111",
            "5500-0000-0000-0004" 
        ],
        "fake_ssn": "123-45-6789",
        "fake_api_key": "AKIAIOSFODNN7EXAMPLE",
        "message": "This is synthetic test data for DLP demo"
    }
    
    # Encode as base64 to simulate binary data
    data_str = json.dumps(test_data)
    data_b64 = base64.b64encode(data_str.encode()).decode()
    
    # Large payload to trigger size-based detection
    large_payload = data_b64 * 100  # Repeat to create large payload
    
    headers = {
        'User-Agent': 'Test-Client/1.0',
        'Content-Type': 'application/octet-stream'
    }
    
    try:
        print(f"Sending test data to {target_url}")
        response = requests.post(
            target_url,
            data=large_payload,
            headers=headers,
            timeout=10
        )
        
        print(f"Response: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HTTP POST Exfil Test - Lab Only')
    parser.add_argument('--target', default='http://localhost:8080/upload',
                       help='Target URL for POST request')
    parser.add_argument('--confirm-token', required=True,
                       help='Confirmation token to enable test')
    
    args = parser.parse_args()
    
    test_http_post_exfil(args.target, args.confirm_token)
