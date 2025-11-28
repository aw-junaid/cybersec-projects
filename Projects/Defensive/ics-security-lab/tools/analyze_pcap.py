#!/usr/bin/env python3
"""
PCAP Analysis for ICS Lab
Extracts and analyzes Modbus traffic
"""

import pyshark
import json
from collections import Counter

def analyze_modbus_pcap(pcap_file):
    """Analyze Modbus traffic in PCAP file"""
    results = {
        'file': pcap_file,
        'total_packets': 0,
        'modbus_packets': 0,
        'function_codes': Counter(),
        'source_ips': Counter(),
        'write_operations': [],
        'alerts': []
    }
    
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter='modbus')
        
        for packet in cap:
            results['total_packets'] += 1
            
            if hasattr(packet, 'modbus'):
                results['modbus_packets'] += 1
                
                # Extract Modbus data
                src_ip = packet.ip.src
                results['source_ips'][src_ip] += 1
                
                if hasattr(packet.modbus, 'func_code'):
                    func_code = int(packet.modbus.func_code)
                    results['function_codes'][func_code] += 1
                    
                    # Detect write operations
                    if func_code in [5, 6, 15, 16]:
                        write_op = {
                            'source_ip': src_ip,
                            'function_code': func_code,
                            'timestamp': str(packet.sniff_time)
                        }
                        results['write_operations'].append(write_op)
                        
                        # Alert on writes to potentially critical registers
                        if hasattr(packet.modbus, 'address'):
                            address = int(packet.modbus.address)
                            if address >= 100:
                                results['alerts'].append({
                                    'type': 'write_to_protected_register',
                                    'source_ip': src_ip,
                                    'address': address,
                                    'timestamp': str(packet.sniff_time)
                                })
        
        cap.close()
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python analyze_pcap.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    print(f"Analyzing {pcap_file}...")
    
    results = analyze_modbus_pcap(pcap_file)
    
    print("\nAnalysis Results:")
    print(f"Total packets: {results['total_packets']}")
    print(f"Modbus packets: {results['modbus_packets']}")
    print(f"Function codes: {dict(results['function_codes'])}")
    print(f"Source IPs: {dict(results['source_ips'])}")
    print(f"Write operations: {len(results['write_operations'])}")
    print(f"Alerts: {len(results['alerts'])}")
    
    # Save detailed results
    with open(f"analysis_{pcap_file}.json", 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
