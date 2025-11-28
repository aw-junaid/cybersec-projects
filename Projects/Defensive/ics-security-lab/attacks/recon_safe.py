#!/usr/bin/env python3
"""
Safe Reconnaissance Tool for ICS Lab
Read-only operations only
"""

import json
import sys
import socket
import time
from pymodbus.client import ModbusTcpClient

def safety_check():
    """Verify we're in lab environment"""
    if not os.getenv('LAB_MODE') == '1':
        print("SAFETY: Must run in lab mode with LAB_MODE=1")
        sys.exit(1)

def modbus_recon(target_ip, port=5020):
    """Perform safe Modbus reconnaissance"""
    results = {
        'target': target_ip,
        'port': port,
        'unit_ids': [],
        'coils': {},
        'holding_registers': {},
        'timestamp': time.time()
    }
    
    client = ModbusTcpClient(target_ip, port=port)
    
    try:
        # Scan for unit IDs
        for unit_id in range(1, 20):
            try:
                # Try to read a holding register
                response = client.read_holding_registers(0, 1, unit=unit_id)
                if not response.isError():
                    results['unit_ids'].append(unit_id)
                    print(f"Found Unit ID: {unit_id}")
            except Exception as e:
                pass
        
        # For found unit IDs, read some data
        for unit_id in results['unit_ids']:
            # Read first 10 coils
            try:
                response = client.read_coils(0, 10, unit=unit_id)
                if not response.isError():
                    results['coils'][unit_id] = response.bits
            except:
                pass
            
            # Read first 10 holding registers
            try:
                response = client.read_holding_registers(0, 10, unit=unit_id)
                if not response.isError():
                    results['holding_registers'][unit_id] = response.registers
            except:
                pass
                
    finally:
        client.close()
    
    return results

def main():
    safety_check()
    
    if len(sys.argv) != 2:
        print("Usage: python recon_safe.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    print(f"Starting safe reconnaissance of {target_ip}")
    print("This tool performs READ-ONLY operations only")
    
    results = modbus_recon(target_ip)
    
    print("\nReconnaissance Results:")
    print(json.dumps(results, indent=2))
    
    # Save results
    with open(f"recon_{target_ip.replace('.', '_')}.json", 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
