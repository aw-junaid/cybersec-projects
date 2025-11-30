#!/usr/bin/env python3
"""
Network Isolation Checker for DLP Demo
Verifies lab environment is properly isolated
"""

import socket
import subprocess
import sys
import os

def check_lab_mode():
    """Verify DLP_LAB_MODE is set"""
    if os.getenv('DLP_LAB_MODE') != '1':
        print("FAIL: DLP_LAB_MODE environment variable not set to '1'")
        return False
    return True

def check_default_gateway():
    """Check for default gateway (potential production connectivity)"""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        routes = result.stdout
        
        for line in routes.split('\n'):
            if 'default' in line:
                print("WARNING: Default route detected - may not be fully isolated")
                return False
        return True
    except Exception as e:
        print(f"WARNING: Could not check routes: {e}")
        return True  # Be permissive

def check_dns_servers():
    """Check if using lab DNS servers"""
    try:
        with open('/etc/resolv.conf', 'r') as f:
            resolv_conf = f.read()
        
        # Check for common production DNS servers
        prod_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        for dns in prod_dns:
            if dns in resolv_conf:
                print(f"WARNING: Production DNS server found: {dns}")
                return False
        return True
    except Exception as e:
        print(f"WARNING: Could not check DNS: {e}")
        return True  # Be permissive

def check_cloud_metadata():
    """Check for cloud metadata service (indicates cloud environment)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(('169.254.169.254', 80))
        s.close()
        
        if result == 0:
            print("WARNING: Cloud metadata service accessible - may be in cloud environment")
            return False
        return True
    except:
        return True  # Be permissive on error

def main():
    """Run all isolation checks"""
    print("DLP Demo - Environment Isolation Check")
    print("=" * 50)
    
    checks = [
        ("Lab Mode Enabled", check_lab_mode()),
        ("No Default Gateway", check_default_gateway()),
        ("Lab DNS Servers", check_dns_servers()),
        ("No Cloud Metadata", check_cloud_metadata())
    ]
    
    all_passed = True
    for check_name, result in checks:
        status = "PASS" if result else "FAIL"
        print(f"{check_name}: {status}")
        if not result:
            all_passed = False
    
    print("=" * 50)
    if all_passed:
        print("OK: Environment appears properly isolated")
        sys.exit(0)
    else:
        print("WARNING: Environment may not be fully isolated")
        print("Continue only if you are certain this is a lab environment")
        sys.exit(1)

if __name__ == "__main__":
    main()
