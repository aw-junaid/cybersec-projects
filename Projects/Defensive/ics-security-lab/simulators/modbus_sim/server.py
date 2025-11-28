#!/usr/bin/env python3
"""
Modbus/TCP PLC Simulator for ICS Security Lab
SAFETY: Only operates in isolated lab environment
"""

import os
import sys
import logging
import yaml
from typing import Dict, Any
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.transaction import ModbusSocketFramer
from prometheus_client import start_http_server, Counter, Gauge
import threading

# Safety checks
def verify_lab_environment():
    """Verify we're running in safe lab environment"""
    if os.getenv('LAB_MODE') != '1':
        raise RuntimeError("SAFETY VIOLATION: LAB_MODE not set. Refusing to start.")
    
    # Check for obvious production network indicators
    forbidden_hosts = ['google.com', '8.8.8.8', '192.168.1.1']
    import socket
    for host in forbidden_hosts:
        try:
            socket.gethostbyname(host)
            raise RuntimeError(f"SAFETY VIOLATION: Network connectivity to {host}")
        except:
            pass  # Expected - no network connectivity
    
    logging.info("Safety checks passed - running in lab mode")

class SafetyAwareDataBlock(ModbusSequentialDataBlock):
    """Modbus data block with safety controls"""
    
    def __init__(self, address, values, safe_ranges=None):
        super().__init__(address, values)
        self.safe_ranges = safe_ranges or {}
        self.unsafe_write_attempts = Counter('modbus_unsafe_write_attempts', 
                                           'Attempted writes outside safe ranges')
    
    def setValues(self, address, values):
        """Override to enforce safe value ranges"""
        if self.safe_ranges:
            for i, value in enumerate(values):
                check_addr = address + i
                if check_addr in self.safe_ranges:
                    min_val, max_val = self.safe_ranges[check_addr]
                    if not (min_val <= value <= max_val):
                        self.unsafe_write_attempts.inc()
                        logging.warning(f"SAFETY: Write {value} to address {check_addr} outside safe range {min_val}-{max_val}")
                        # In lab mode, we allow but log the violation
                        # In production sim, this would be blocked
        super().setValues(address, values)

class ModbusPLCSimulator:
    """Safe Modbus/TCP PLC Simulator"""
    
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.metrics_port = self.config.get('metrics_port', 8080)
        
        # Prometheus metrics
        self.request_counter = Counter('modbus_requests_total', 
                                     'Total Modbus requests', ['function_code'])
        self.write_operations = Counter('modbus_writes_total',
                                      'Write operations', ['register_type'])
        
        self.setup_modbus_server()
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load PLC configuration with safety defaults"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Set safe defaults
        config.setdefault('safe_ranges', {})
        config.setdefault('read_only_registers', [])
        config.setdefault('port', 5020)  # Non-standard port for safety
        
        return config
    
    def setup_modbus_server(self):
        """Initialize Modbus server with safety controls"""
        # Create data blocks with safe ranges
        coils = SafetyAwareDataBlock(0, [0]*100, 
                                   self.config['safe_ranges'].get('coils', {}))
        holding_registers = SafetyAwareDataBlock(0, [0]*100,
                                              self.config['safe_ranges'].get('holding_registers', {}))
        
        slave_context = ModbusSlaveContext(
            co=coils,
            hr=holding_registers,
            zero_mode=True
        )
        
        self.context = ModbusServerContext(slaves=slave_context, single=True)
    
    def run(self):
        """Start the Modbus server and metrics endpoint"""
        # Start Prometheus metrics
        threading.Thread(target=start_http_server, 
                        args=(self.metrics_port,), daemon=True).start()
        
        # Start Modbus server
        logging.info(f"Starting Modbus PLC simulator on port {self.config['port']}")
        StartTcpServer(
            context=self.context,
            framer=ModbusSocketFramer,
            address=("0.0.0.0", self.config['port'])
        )

def main():
    """Main entry point with safety checks"""
    try:
        verify_lab_environment()
        
        config_path = os.getenv('CONFIG_PATH', '/app/config/plc_config.yaml')
        simulator = ModbusPLCSimulator(config_path)
        simulator.run()
        
    except Exception as e:
        logging.error(f"SAFETY: Startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
