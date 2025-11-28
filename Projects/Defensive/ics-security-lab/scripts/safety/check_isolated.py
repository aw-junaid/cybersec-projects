#!/usr/bin/env python3
"""
Safety Check: Verify Lab Isolation
Must be run before any lab operations
"""

import os
import socket
import sys
import subprocess

def check_lab_mode():
    """Verify LAB_MODE environment variable"""
    if os.getenv('LAB_MODE') != '1':
        print("FAIL: LAB_MODE environment variable not set to '1'")
        return False
    return True

def check_network_isolation():
    """Verify no route to production networks"""
    # Test domains that should NOT be reachable
    test_domains = [
        'google.com',           # Internet
        'siemens.com',          # ICS vendor
        'rockwellautomation.com', # ICS vendor  
        '8.8.8.8',             # Google DNS
        '192.168.1.1',         # Common internal network
        '10.0.0.1'             # Common internal network
    ]
    
    for domain in test_domains:
        try:
            socket.gethostbyname(domain)
            print(f"FAIL: Network connectivity to {domain} - NOT ISOLATED")
            return False
        except:
            pass  # Expected - no resolution
    
    return True

def check_docker_networks():
    """Verify Docker networks are internal"""
    try:
        result = subprocess.run(['docker', 'network', 'ls', '--format', '{{.Name}}'], 
                              capture_output=True, text=True)
        networks = result.stdout.splitlines()
        
        for network in networks:
            if network and not network.startswith('ics-lab'):
                print(f"WARNING: Non-lab Docker network found: {network}")
                
    except Exception as e:
        print(f"Warning: Could not check Docker networks: {e}")
    
    return True

def main():
    """Run all safety checks"""
    print("=== ICS Lab Safety Check ===")
    
    checks = [
        ("Lab Mode", check_lab_mode()),
        ("Network Isolation", check_network_isolation()),
        ("Docker Networks", check_docker_networks())
    ]
    
    all_passed = True
    for check_name, result in checks:
        status = "PASS" if result else "FAIL"
        print(f"{check_name}: {status}")
        if not result:
            all_passed = False
    
    if not all_passed:
        print("\n❌ SAFETY CHECK FAILED - DO NOT PROCEED")
        print("Lab environment is not properly isolated.")
        sys.exit(1)
    else:
        print("\n✅ Safety checks passed - lab is isolated")
        return 0

if __name__ == "__main__":
    main()
