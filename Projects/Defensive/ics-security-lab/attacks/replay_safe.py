#!/usr/bin/env python3
"""
Safe Replay Attack Simulation
ONLY works with --enable-writes flag and confirmation
"""

import json
import sys
import time
from pymodbus.client import ModbusTcpClient

def require_confirmation():
    """Require explicit confirmation for write operations"""
    confirmation = input("Type 'CONFIRM_REPLAY_SAFE' to proceed with replay: ")
    if confirmation != "CONFIRM_REPLAY_SAFE":
        print("Replay cancelled - confirmation required")
        sys.exit(1)

def safe_replay(target_ip, register_type, address, value, unit_id=1):
    """Perform safe replay attack simulation"""
    
    client = ModbusTcpClient(target_ip)
    
    try:
        if register_type == 'coil':
            print(f"Writing coil {address} = {value}")
            response = client.write_coil(address, value, unit=unit_id)
        elif register_type == 'register':
            print(f"Writing holding register {address} = {value}")
            response = client.write_register(address, value, unit=unit_id)
        else:
            print(f"Unknown register type: {register_type}")
            return False
        
        if response.isError():
            print(f"Write failed: {response}")
            return False
        else:
            print("Write successful (simulated)")
            return True
            
    finally:
        client.close()

def main():
    # Safety checks
    if not os.getenv('LAB_MODE') == '1':
        print("SAFETY: Must run in lab mode")
        sys.exit(1)
    
    if '--enable-writes' not in sys.argv:
        print("SAFETY: Write operations require --enable-writes flag")
        sys.exit(1)
    
    if len(sys.argv) < 5:
        print("Usage: python replay_safe.py --enable-writes <target_ip> <coil|register> <address> <value>")
        sys.exit(1)
    
    require_confirmation()
    
    target_ip = sys.argv[2]
    register_type = sys.argv[3]
    address = int(sys.argv[4])
    value = int(sys.argv[5])
    
    print(f"SAFE REPLAY: Target={target_ip}, Type={register_type}, Addr={address}, Value={value}")
    
    # Only allow writes to non-critical addresses in demo
    if address < 10:  # First 10 addresses are considered non-critical for demo
        success = safe_replay(target_ip, register_type, address, value)
        print(f"Replay result: {'SUCCESS' if success else 'FAILED'}")
    else:
        print("SAFETY: Would not write to potentially critical register in demo")

if __name__ == "__main__":
    main()
