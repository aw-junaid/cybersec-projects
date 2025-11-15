#!/usr/bin/env python3
"""
Bluetooth Protocol Tester - Security Assessment Tool
Purpose: Scan, enumerate, and test Bluetooth services for vulnerabilities
Use: Bluetooth security testing, penetration testing, device assessment
"""

import bluetooth
import socket
import struct
import time
import threading
import argparse
import json
from datetime import datetime
from collections import defaultdict

class BluetoothTester:
    def __init__(self, target_addr=None, scan_timeout=10):
        self.target_addr = target_addr
        self.scan_timeout = scan_timeout
        self.discovered_devices = []
        self.services_found = []
        self.vulnerabilities = []
        self.l2cap_socket = None
        
    def scan_devices(self):
        """
        Discover nearby Bluetooth devices
        """
        print("[SCAN] Discovering nearby Bluetooth devices...")
        print("This may take up to {} seconds...".format(self.scan_timeout))
        
        try:
            devices = bluetooth.discover_devices(
                duration=self.scan_timeout, 
                lookup_names=True, 
                flush_cache=True
            )
            
            self.discovered_devices = []
            for addr, name in devices:
                device_info = {
                    'address': addr,
                    'name': name if name else 'Unknown',
                    'timestamp': datetime.now().isoformat()
                }
                self.discovered_devices.append(device_info)
                print(f"  Found: {name} ({addr})")
            
            print(f"[SCAN] Found {len(self.discovered_devices)} devices")
            return self.discovered_devices
            
        except Exception as e:
            print(f"[ERROR] Device discovery failed: {e}")
            return []
    
    def scan_services(self, target_addr=None):
        """
        Discover services on target Bluetooth device
        """
        if target_addr is None:
            target_addr = self.target_addr
            
        if target_addr is None:
            print("[ERROR] No target address specified")
            return []
        
        print(f"[SERVICES] Scanning services on {target_addr}...")
        
        try:
            services = bluetooth.find_service(address=target_addr)
            self.services_found = []
            
            for service in services:
                service_info = {
                    'name': service.get('name', 'Unknown'),
                    'protocol': service.get('protocol', 'Unknown'),
                    'port': service.get('port', 'Unknown'),
                    'service-id': service.get('service-id', ''),
                    'service-classes': service.get('service-classes', []),
                    'profiles': service.get('profiles', []),
                    'provider': service.get('provider', ''),
                    'host': service.get('host', '')
                }
                self.services_found.append(service_info)
                
                print(f"  Service: {service_info['name']}")
                print(f"    Protocol: {service_info['protocol']}")
                print(f"    Port: {service_info['port']}")
                print(f"    Service ID: {service_info['service-id']}")
                print("    " + "-" * 30)
            
            print(f"[SERVICES] Found {len(self.services_found)} services")
            return self.services_found
            
        except Exception as e:
            print(f"[ERROR] Service discovery failed: {e}")
            return []
    
    def rfcomm_scan(self, target_addr, start_port=1, end_port=30):
        """
        Scan for open RFCOMM channels
        """
        print(f"[RFCOMM] Scanning RFCOMM ports {start_port}-{end_port} on {target_addr}...")
        
        open_ports = []
        for port in range(start_port, end_port + 1):
            try:
                sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                sock.settimeout(2)
                sock.connect((target_addr, port))
                open_ports.append(port)
                print(f"  RFCOMM Port {port}: OPEN")
                sock.close()
            except Exception as e:
                print(f"  RFCOMM Port {port}: CLOSED - {e}")
                continue
        
        return open_ports
    
    def l2cap_scan(self, target_addr, start_psm=1, end_psm=100):
        """
        Scan for open L2CAP PSM ports
        """
        print(f"[L2CAP] Scanning PSM {start_psm}-{end_psm} on {target_addr}...")
        
        open_psm = []
        for psm in range(start_psm, end_psm + 1):
            try:
                sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
                sock.settimeout(2)
                sock.connect((target_addr, psm))
                open_psm.append(psm)
                print(f"  L2CAP PSM {psm}: OPEN")
                sock.close()
            except Exception as e:
                # Don't print closed ports to reduce noise
                continue
        
        return open_psm
    
    def sdp_info_gathering(self, target_addr):
        """
        Gather detailed SDP information
        """
        print(f"[SDP] Gathering detailed service information from {target_addr}...")
        
        try:
            # This would use pybluez SDP functions for detailed info
            # Simplified implementation
            services = bluetooth.find_service(address=target_addr)
            
            sdp_info = {
                'target': target_addr,
                'services_count': len(services),
                'service_details': []
            }
            
            for service in services:
                sdp_info['service_details'].append({
                    'service_name': service.get('name', 'Unknown'),
                    'service_description': service.get('description', ''),
                    'service_protocol': service.get('protocol', ''),
                    'service_port': service.get('port', ''),
                    'service_classes': service.get('service-classes', []),
                    'profiles': service.get('profiles', [])
                })
            
            return sdp_info
            
        except Exception as e:
            print(f"[ERROR] SDP info gathering failed: {e}")
            return None
    
    def bluetooth_stack_fingerprinting(self, target_addr):
        """
        Attempt to fingerprint Bluetooth stack
        """
        print(f"[FINGERPRINT] Attempting Bluetooth stack fingerprinting on {target_addr}...")
        
        stack_info = {
            'target': target_addr,
            'likely_stacks': [],
            'supported_features': []
        }
        
        # Test common Bluetooth features
        feature_tests = [
            ('L2CAP', self.test_l2cap_support),
            ('RFCOMM', self.test_rfcomm_support),
            ('OBEX', self.test_obex_support),
            ('HID', self.test_hid_support),
        ]
        
        for feature, test_func in feature_tests:
            try:
                if test_func(target_addr):
                    stack_info['supported_features'].append(feature)
            except Exception as e:
                print(f"  {feature} test failed: {e}")
        
        # Determine likely stack based on features
        if 'L2CAP' in stack_info['supported_features'] and 'RFCOMM' in stack_info['supported_features']:
            stack_info['likely_stacks'].append('Linux BlueZ')
        if 'HID' in stack_info['supported_features']:
            stack_info['likely_stacks'].append('Windows/Microsoft')
        
        print(f"  Supported features: {', '.join(stack_info['supported_features'])}")
        print(f"  Likely stacks: {', '.join(stack_info['likely_stacks'])}")
        
        return stack_info
    
    def test_l2cap_support(self, target_addr):
        """Test L2CAP protocol support"""
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(2)
            sock.connect((target_addr, 1))  # Try PSM 1
            sock.close()
            return True
        except:
            return False
    
    def test_rfcomm_support(self, target_addr):
        """Test RFCOMM protocol support"""
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            sock.settimeout(2)
            sock.connect((target_addr, 1))  # Try channel 1
            sock.close()
            return True
        except:
            return False
    
    def test_obex_support(self, target_addr):
        """Test OBEX protocol support"""
        # Simplified OBEX test
        try:
            services = bluetooth.find_service(address=target_addr)
            for service in services:
                if 'obex' in str(service.get('protocol', '')).lower():
                    return True
            return False
        except:
            return False
    
    def test_hid_support(self, target_addr):
        """Test HID profile support"""
        try:
            services = bluetooth.find_service(address=target_addr)
            for service in services:
                if any('hid' in str(profile).lower() for profile in service.get('profiles', [])):
                    return True
            return False
        except:
            return False
    
    def blueborne_simulation(self, target_addr):
        """
        Simulate BlueBorne attack vectors (educational purposes only)
        """
        print(f"[BLUEBORNE] Testing BlueBorne attack vectors on {target_addr}...")
        
        blueborne_checks = {
            'L2CAP_Overflow': self.check_l2cap_overflow,
            'SDP_Information_Disclosure': self.check_sdp_info_disclosure,
            'PIN_Weakness': self.check_pin_weakness,
        }
        
        results = {}
        for check_name, check_func in blueborne_checks.items():
            try:
                result = check_func(target_addr)
                results[check_name] = result
                status = "VULNERABLE" if result else "SAFE"
                print(f"  {check_name}: {status}")
            except Exception as e:
                print(f"  {check_name}: ERROR - {e}")
                results[check_name] = False
        
        return results
    
    def check_l2cap_overflow(self, target_addr):
        """Check for potential L2CAP overflow vulnerabilities"""
        # This is a simulated check - real implementation would be more complex
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(2)
            sock.connect((target_addr, 1))
            
            # Send oversized packet (simulated)
            large_packet = b"A" * 10000
            try:
                sock.send(large_packet)
                time.sleep(1)
            except:
                # Device might have crashed or rejected
                return True
            
            sock.close()
            return False
        except:
            return False
    
    def check_sdp_info_disclosure(self, target_addr):
        """Check for SDP information disclosure"""
        try:
            services = bluetooth.find_service(address=target_addr)
            sensitive_info_found = False
            
            for service in services:
                # Check for potentially sensitive service information
                service_name = service.get('name', '').lower()
                if any(keyword in service_name for keyword in ['admin', 'config', 'debug', 'test']):
                    sensitive_info_found = True
            
            return sensitive_info_found
        except:
            return False
    
    def check_pin_weakness(self, target_addr):
        """Check for weak PIN/pairing vulnerabilities"""
        # This would normally test pairing mechanisms
        # Simplified check for common weak PINs
        common_pins = ['0000', '1234', '1111', '9999']
        
        # Note: Actual PIN testing requires pairing attempts
        # This is just a placeholder for the concept
        print("    Note: PIN testing requires active pairing attempts")
        return False
    
    def bluetooth_dos_test(self, target_addr, test_type="l2cap_flood"):
        """
        Test Bluetooth Denial of Service vectors (educational only)
        """
        print(f"[DoS] Testing {test_type} on {target_addr} (educational)...")
        
        if test_type == "l2cap_flood":
            return self.l2cap_flood_test(target_addr)
        elif test_type == "rfcomm_flood":
            return self.rfcomm_flood_test(target_addr)
        else:
            print("Unknown DoS test type")
            return False
    
    def l2cap_flood_test(self, target_addr):
        """Simulate L2CAP connection flood"""
        print("  Simulating L2CAP connection flood...")
        
        sockets = []
        max_connections = 10  # Limited for safety
        
        try:
            for i in range(max_connections):
                try:
                    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
                    sock.settimeout(2)
                    sock.connect((target_addr, 1))
                    sockets.append(sock)
                    print(f"    Connection {i+1} established")
                except Exception as e:
                    print(f"    Connection {i+1} failed: {e}")
                    break
            
            # Keep connections open for a short time
            time.sleep(3)
            
            # Cleanup
            for sock in sockets:
                sock.close()
            
            return len(sockets) > 0
            
        except Exception as e:
            print(f"  L2CAP flood test failed: {e}")
            return False
    
    def rfcomm_flood_test(self, target_addr):
        """Simulate RFCOMM connection flood"""
        print("  Simulating RFCOMM connection flood...")
        
        sockets = []
        max_connections = 5  # Limited for safety
        
        try:
            for i in range(max_connections):
                try:
                    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                    sock.settimeout(2)
                    sock.connect((target_addr, 1))
                    sockets.append(sock)
                    print(f"    Connection {i+1} established")
                except Exception as e:
                    print(f"    Connection {i+1} failed: {e}")
                    break
            
            time.sleep(2)
            
            for sock in sockets:
                sock.close()
            
            return len(sockets) > 0
            
        except Exception as e:
            print(f"  RFCOMM flood test failed: {e}")
            return False
    
    def generate_report(self, filename=None):
        """Generate comprehensive test report"""
        if filename is None:
            filename = f"bluetooth_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'target_device': self.target_addr,
            'discovered_devices': self.discovered_devices,
            'services_found': self.services_found,
            'vulnerabilities_found': self.vulnerabilities,
            'summary': {
                'total_devices': len(self.discovered_devices),
                'total_services': len(self.services_found),
                'vulnerabilities_count': len(self.vulnerabilities)
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[REPORT] Results saved to {filename}")
        return report

def main():
    parser = argparse.ArgumentParser(description='Bluetooth Protocol Tester')
    parser.add_argument('--scan', action='store_true', help='Scan for nearby devices')
    parser.add_argument('--target', help='Target Bluetooth address (XX:XX:XX:XX:XX:XX)')
    parser.add_argument('--services', action='store_true', help='Scan services on target')
    parser.add_argument('--rfcomm-scan', action='store_true', help='Scan RFCOMM ports')
    parser.add_argument('--l2cap-scan', action='store_true', help='Scan L2CAP PSM ports')
    parser.add_argument('--fingerprint', action='store_true', help='Fingerprint Bluetooth stack')
    parser.add_argument('--blueborne', action='store_true', help='Test BlueBorne vectors')
    parser.add_argument('--timeout', type=int, default=10, help='Scan timeout in seconds')
    parser.add_argument('--report', help='Generate report file')
    
    args = parser.parse_args()
    
    tester = BluetoothTester(args.target, args.timeout)
    
    try:
        if args.scan:
            tester.scan_devices()
        
        if args.target:
            if args.services:
                tester.scan_services(args.target)
            
            if args.rfcomm_scan:
                tester.rfcomm_scan(args.target)
            
            if args.l2cap_scan:
                tester.l2cap_scan(args.target)
            
            if args.fingerprint:
                tester.bluetooth_stack_fingerprinting(args.target)
            
            if args.blueborne:
                tester.blueborne_simulation(args.target)
        
        if args.report:
            tester.generate_report(args.report)
        
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
