#!/usr/bin/env python3
"""
Safe Modbus scanner for lab environment
Read-only operations only
"""

import json
import sys
from pymodbus.client import ModbusTcpClient
import socket

def verify_lab_mode():
    """Ensure running in lab environment"""
    if not os.getenv('LAB_MODE') == '1':
        print("ERROR: Must run in lab mode with LAB_MODE=1")
        sys.exit(1)

class SafeModbusScanner:
    """Read-only Modbus scanner for lab use"""
    
    def __init__(self, target_ip, port=5020):
        self.target_ip = target_ip
        self.port = port
        self.client = None
        self.results = {
            'target': f"{target_ip}:{port}",
            'coils': [],
            'holding_registers': [],
            'unit_ids': []
        }
    
    def connect(self):
        """Establish connection to target"""
        try:
            self.client = ModbusTcpClient(self.target_ip, port=self.port)
            return self.client.connect()
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def safe_scan(self):
        """Perform read-only scan"""
        if not self.connect():
            return self.results
        
        try:
            # Scan unit IDs (safe)
            for unit_id in range(1, 10):
                try:
                    result = self.client.read_holding_registers(0, 1, unit=unit_id)
                    if not result.isError():
                        self.results['unit_ids'].append(unit_id)
                except:
                    pass
            
            # Read first 10 registers (safe)
            for unit_id in self.results['unit_ids']:
                # Holding registers
                result = self.client.read_holding_registers(0, 10, unit=unit_id)
                if not result.isError():
                    self.results['holding_registers'].extend(result.registers)
                
                # Coils
                result = self.client.read_coils(0, 10, unit=unit_id)
                if not result.isError():
                    self.results['coils'].extend(result.bits)
        
        finally:
            self.client.close()
        
        return self.results

def main():
    verify_lab_mode()
    
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    scanner = SafeModbusScanner(target_ip)
    results = scanner.safe_scan()
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
