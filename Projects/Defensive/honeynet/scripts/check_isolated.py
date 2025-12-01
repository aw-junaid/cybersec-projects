#!/usr/bin/env python3
"""
Network Isolation Checker
Safety: This script verifies the host is properly isolated before allowing honeynet operations
"""

import os
import socket
import subprocess
import sys
from typing import List

def check_safety_mode() -> bool:
    """Verify HONEY_LAB_MODE is set"""
    if os.getenv('HONEY_LAB_MODE') != '1':
        print("ERROR: HONEY_LAB_MODE environment variable not set to 1")
        return False
    return True

def check_private_network() -> bool:
    """Verify we're on a private network"""
    try:
        # Get host IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Check if IP is in private ranges
        if local_ip.startswith(('10.', '172.', '192.168.', '127.')):
            print(f"✓ Private IP address: {local_ip}")
            return True
        else:
            print(f"✗ Public IP address detected: {local_ip}")
            return False
            
    except Exception as e:
        print(f"✗ Network check failed: {e}")
        return False

def check_default_route() -> bool:
    """Check if default route exists (indicating internet access)"""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            print("✗ Default route detected - system has internet access")
            return False
        else:
            print("✓ No default route detected")
            return True
            
    except Exception as e:
        print(f"✗ Route check failed: {e}")
        return False

def check_firewall_rules() -> bool:
    """Verify basic firewall rules are in place"""
    try:
        # Check if iptables has restrictive rules
        result = subprocess.run(
            ['iptables', '-L', '-n'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # Basic check for restrictive policies
            if 'DROP' in result.stdout or 'REJECT' in result.stdout:
                print("✓ Restrictive firewall rules detected")
                return True
            else:
                print("✗ No restrictive firewall rules")
                return False
        else:
            print("✗ Failed to check firewall rules")
            return False
            
    except Exception as e:
        print(f"✗ Firewall check failed: {e}")
        return False

def main():
    """Main isolation check"""
    print("Honeynet Network Isolation Check")
    print("=" * 40)
    
    checks = [
        ("Safety Mode", check_safety_mode()),
        ("Private Network", check_private_network()),
        ("No Default Route", check_default_route()),
        ("Firewall Rules", check_firewall_rules()),
    ]
    
    print("\n" + "=" * 40)
    
    all_passed = all(result for _, result in checks)
    
    for check_name, result in checks:
        status = "PASS" if result else "FAIL"
        print(f"{check_name}: {status}")
    
    if all_passed:
        print("\n✓ All safety checks passed")
        sys.exit(0)
    else:
        print("\n✗ Safety checks failed - do not proceed")
        sys.exit(1)

if __name__ == "__main__":
    main()
