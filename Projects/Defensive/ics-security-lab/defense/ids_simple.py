#!/usr/bin/env python3
"""
Simple IDS for ICS Lab
Monitors for suspicious Modbus activity
"""

import json
import time
from collections import defaultdict, deque

class SimpleICSIDS:
    """Basic ICS intrusion detection system"""
    
    def __init__(self, rules_file="signatures.yaml"):
        self.rules = self.load_rules(rules_file)
        self.alert_queue = deque(maxlen=1000)
        self.event_history = defaultdict(lambda: deque(maxlen=100))
        
    def load_rules(self, rules_file):
        """Load detection rules"""
        # In full implementation, load from YAML
        return [
            {
                'id': 'ICS-001',
                'name': 'Write to Protected Register',
                'condition': lambda event: event.get('function_code') in [5, 6, 15, 16] 
                                         and event.get('start_address', 0) >= 100
            },
            {
                'id': 'ICS-002', 
                'name': 'Unusual Function Code',
                'condition': lambda event: event.get('function_code') not in [1, 2, 3, 4, 5, 6, 15, 16]
            }
        ]
    
    def process_event(self, event):
        """Process a Modbus event and check for alerts"""
        alerts = []
        
        # Update event history for rate-based detection
        source_ip = event.get('source_ip', 'unknown')
        self.event_history[source_ip].append((time.time(), event))
        
        # Check rules
        for rule in self.rules:
            if rule['condition'](event):
                alert = {
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'timestamp': time.time(),
                    'event': event,
                    'severity': 'medium'
                }
                alerts.append(alert)
                self.alert_queue.append(alert)
        
        return alerts
    
    def get_recent_alerts(self, count=10):
        """Get recent alerts"""
        return list(self.alert_queue)[-count:]

def main():
    """Demo the IDS"""
    ids = SimpleICSIDS()
    
    # Test with some events
    test_events = [
        {'source_ip': '172.20.0.100', 'function_code': 3, 'start_address': 0},  # Normal read
        {'source_ip': '172.20.0.100', 'function_code': 6, 'start_address': 150}, # Write to protected
        {'source_ip': '172.20.0.100', 'function_code': 99, 'start_address': 0},  # Unusual function
    ]
    
    for event in test_events:
        alerts = ids.process_event(event)
        for alert in alerts:
            print(f"ALERT: {alert['rule_name']} - {event}")
    
    print(f"Total alerts generated: {len(ids.get_recent_alerts())}")

if __name__ == "__main__":
    main()
