#!/usr/bin/env python3
"""
DNS Spoofing Simulator - Educational tool for DNS security
Purpose: Simulate DNS spoofing attacks and practice detection methods
Use: Security training, penetration testing practice, IDS testing
"""

import socket
import threading
import time
import json
import argparse
from datetime import datetime
from collections import defaultdict, deque

class DNSSpoofingSimulator:
    def __init__(self, dns_server='8.8.8.8', port=53, spoof_db_file='spoof_db.json'):
        self.dns_server = dns_server
        self.port = port
        self.spoof_db_file = spoof_db_file
        self.spoof_records = self.load_spoof_records()
        self.detection_log = []
        self.packet_log = deque(maxlen=1000)
        self.is_running = False
        self.suspicious_activity = defaultdict(int)
        
    def load_spoof_records(self):
        """Load spoofing records from JSON file"""
        try:
            with open(self.spoof_db_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Default spoofing records for common sites
            default_records = {
                "example.com": "192.168.1.100",
                "google.com": "192.168.1.101", 
                "facebook.com": "192.168.1.102",
                "bankofamerica.com": "192.168.1.103",
                "paypal.com": "192.168.1.104"
            }
            self.save_spoof_records(default_records)
            return default_records
    
    def save_spoof_records(self, records):
        """Save spoofing records to JSON file"""
        with open(self.spoof_db_file, 'w') as f:
            json.dump(records, f, indent=4)
    
    def add_spoof_record(self, domain, fake_ip):
        """Add a new spoofing record"""
        self.spoof_records[domain] = fake_ip
        self.save_spoof_records(self.spoof_records)
        print(f"Added spoof record: {domain} -> {fake_ip}")
    
    def dns_query_simulation(self, domain, query_type='A'):
        """
        Simulate a legitimate DNS query (for baseline comparison)
        """
        print(f"[LEGIT] Querying {domain} from {self.dns_server}")
        
        # Simulate DNS query/response time
        time.sleep(0.1)
        
        # In real implementation, this would use dnspython or similar
        # For simulation, we return a mock legitimate response
        legit_responses = {
            "example.com": "93.184.216.34",
            "google.com": "142.250.190.78",
            "facebook.com": "157.240.229.35"
        }
        
        return legit_responses.get(domain, "8.8.8.8")
    
    def spoof_dns_response(self, domain, client_ip):
        """
        Generate a spoofed DNS response
        """
        if domain in self.spoof_records:
            spoofed_ip = self.spoof_records[domain]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            log_entry = {
                'timestamp': timestamp,
                'type': 'SPOOFED_RESPONSE',
                'domain': domain,
                'original_ip': 'N/A',
                'spoofed_ip': spoofed_ip,
                'client_ip': client_ip
            }
            
            self.detection_log.append(log_entry)
            self.packet_log.append(log_entry)
            
            print(f"[SPOOF] {domain} -> {spoofed_ip} for client {client_ip}")
            return spoofed_ip
        
        return None
    
    def detect_dns_spoofing(self, query_domain, response_ip, client_ip):
        """
        Detect potential DNS spoofing attempts
        """
        detection_flags = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Check if response matches known spoofed IPs
        if query_domain in self.spoof_records:
            if response_ip == self.spoof_records[query_domain]:
                detection_flags.append("KNOWN_SPOOFED_IP")
                self.suspicious_activity[client_ip] += 1
        
        # Check for rapid successive queries (potential attack)
        recent_queries = [log for log in self.packet_log 
                         if log.get('client_ip') == client_ip 
                         and time.time() - datetime.strptime(log.get('timestamp', timestamp), 
                                                           "%Y-%m-%d %H:%M:%S").timestamp() < 10]
        
        if len(recent_queries) > 20:  # More than 20 queries in 10 seconds
            detection_flags.append("RAPID_QUERIES")
        
        # Check for unusual TTL patterns (simplified)
        if response_ip.startswith('192.168.') or response_ip.startswith('10.'):
            detection_flags.append("PRIVATE_IP_RESPONSE")
        
        if detection_flags:
            detection_entry = {
                'timestamp': timestamp,
                'type': 'DETECTION_ALERT',
                'domain': query_domain,
                'response_ip': response_ip,
                'client_ip': client_ip,
                'flags': detection_flags,
                'confidence': len(detection_flags) * 25
            }
            
            self.detection_log.append(detection_entry)
            self.packet_log.append(detection_entry)
            
            print(f"[ALERT] Potential DNS spoofing detected!")
            print(f"        Domain: {query_domain}")
            print(f"        Response IP: {response_ip}")
            print(f"        Flags: {', '.join(detection_flags)}")
            print(f"        Confidence: {detection_entry['confidence']}%")
            
            return True
        
        return False
    
    def start_spoofing_simulation(self, target_domains=None, duration=60):
        """
        Start DNS spoofing simulation
        """
        if target_domains is None:
            target_domains = list(self.spoof_records.keys())[:3]
        
        self.is_running = True
        start_time = time.time()
        
        print(f"[SIM] Starting DNS spoofing simulation for {duration} seconds")
        print(f"[SIM] Target domains: {', '.join(target_domains)}")
        
        def simulation_worker():
            while self.is_running and (time.time() - start_time) < duration:
                # Simulate both legitimate and spoofed queries
                client_ip = f"192.168.1.{threading.current_thread().ident % 255}"
                
                # Legitimate query
                domain = "example.com"
                legit_ip = self.dns_query_simulation(domain)
                self.detect_dns_spoofing(domain, legit_ip, client_ip)
                
                # Spoofed query
                spoof_domain = target_domains[int(time.time()) % len(target_domains)]
                spoofed_ip = self.spoof_dns_response(spoof_domain, client_ip)
                if spoofed_ip:
                    self.detect_dns_spoofing(spoof_domain, spoofed_ip, client_ip)
                
                time.sleep(1)  # Simulate query interval
        
        # Start multiple client threads
        threads = []
        for i in range(3):  # 3 simulated clients
            thread = threading.Thread(target=simulation_worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Run for specified duration
        time.sleep(duration)
        self.is_running = False
        
        for thread in threads:
            thread.join()
        
        self.generate_report()
    
    def generate_report(self):
        """Generate simulation report"""
        print("\n" + "="*60)
        print("DNS SPOOFING SIMULATION REPORT")
        print("="*60)
        
        total_queries = len([log for log in self.detection_log if 'SPOOFED' in log.get('type', '') or 'DETECTION' in log.get('type', '')])
        spoofed_attempts = len([log for log in self.detection_log if 'SPOOFED' in log.get('type', '')])
        detections = len([log for log in self.detection_log if 'DETECTION' in log.get('type', '')])
        
        print(f"Total queries simulated: {total_queries}")
        print(f"Spoofing attempts: {spoofed_attempts}")
        print(f"Detection alerts: {detections}")
        
        if self.suspicious_activity:
            print("\nSuspicious clients:")
            for client, count in self.suspicious_activity.items():
                print(f"  {client}: {count} suspicious activities")
        
        print("\nDetection log (last 10 entries):")
        for entry in self.detection_log[-10:]:
            print(f"  [{entry['timestamp']}] {entry['type']}: {entry.get('domain', 'N/A')}")

class AdvancedDNSSpoofDetector:
    """
    Advanced DNS spoofing detection using multiple techniques
    """
    
    def __init__(self):
        self.known_legit_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
        self.domain_reputation = {}
        self.ttl_analysis = {}
    
    def analyze_dns_traffic(self, packet_data):
        """
        Analyze DNS traffic patterns for spoofing indicators
        """
        indicators = []
        
        # TTL Analysis - spoofed responses often have unusual TTLs
        if packet_data.get('ttl', 0) < 30:
            indicators.append("UNUSUALLY_LOW_TTL")
        
        # DNS Server Analysis - responses from unexpected servers
        if packet_data.get('dns_server') not in self.known_legit_dns:
            indicators.append("UNTRUSTED_DNS_SERVER")
        
        # Query/Response Mismatch
        if packet_data.get('query_count', 0) > packet_data.get('response_count', 0) * 2:
            indicators.append("QUERY_RESPONSE_MISMATCH")
        
        return indicators
    
    def behavioral_analysis(self, client_ip, query_pattern):
        """
        Behavioral analysis of DNS query patterns
        """
        suspicious_behaviors = []
        
        # Rapid domain generation algorithms (DGA) detection
        unique_domains = len(set(query_pattern))
        if unique_domains > 50:  # More than 50 unique domains in short time
            suspicious_behaviors.append("POSSIBLE_DGA_ACTIVITY")
        
        # Unusual query times
        nighttime_queries = sum(1 for time in query_pattern if 0 <= time.hour <= 5)
        if nighttime_queries > len(query_pattern) * 0.7:  # 70% queries at night
            suspicious_behaviors.append("UNUSUAL_QUERY_TIMES")
        
        return suspicious_behaviors

def main():
    parser = argparse.ArgumentParser(description='DNS Spoofing Simulator')
    parser.add_argument('--mode', choices=['simulate', 'detect', 'add-spoof'], 
                       default='simulate', help='Operation mode')
    parser.add_argument('--domain', help='Domain for spoofing record')
    parser.add_argument('--ip', help='Fake IP for spoofing record')
    parser.add_argument('--duration', type=int, default=60, 
                       help='Simulation duration in seconds')
    
    args = parser.parse_args()
    
    simulator = DNSSpoofingSimulator()
    
    if args.mode == 'simulate':
        print("Starting DNS Spoofing Simulation...")
        simulator.start_spoofing_simulation(duration=args.duration)
    
    elif args.mode == 'add-spoof':
        if not args.domain or not args.ip:
            print("Error: --domain and --ip required for add-spoof mode")
            return
        simulator.add_spoof_record(args.domain, args.ip)
    
    elif args.mode == 'detect':
        print("Starting DNS Spoofing Detection Analysis...")
        # This would integrate with actual network monitoring
        detector = AdvancedDNSSpoofDetector()
        print("Advanced detection engine initialized")

if __name__ == "__main__":
    main()
