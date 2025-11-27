#!/usr/bin/env python3
"""
Rootkit Detection & Removal Toolkit
Advanced heuristics and scanning for rootkit detection
"""

import os
import sys
import hashlib
import psutil
import platform
import subprocess
import json
import time
import threading
from pathlib import Path
from datetime import datetime
import logging
import re
import winreg
import struct
from collections import defaultdict

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rootkit_scanner.log'),
        logging.StreamHandler()
    ]
)

class RootkitScanner:
    def __init__(self):
        self.system = platform.system().lower()
        self.suspicious_items = []
        self.known_rootkit_signatures = self.load_signatures()
        self.scan_results = {
            'hidden_processes': [],
            'hidden_files': [],
            'suspicious_drivers': [],
            'api_hooks': [],
            'integrity_violations': [],
            'behavioral_anomalies': []
        }
        
    def load_signatures(self):
        """Load known rootkit signatures and patterns"""
        signatures = {
            'files': [
                'adore', 'adore-ng', 'beastkit', 'diamon', 'fu', 'kbeast',
                'knark', 'mood-nt', 'phide', 'sebek', 'suckit', 'w32.spybot'
            ],
            'processes': [
                'adore', 'beast', 'diamon', 'fu', 'kbeast', 'knark', 'phide'
            ],
            'registry_keys': [
                r'\\System\\CurrentControlSet\\Services\\.*rootkit',
                r'\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.*suspicious'
            ],
            'network_patterns': [
                r'hidden_port_\d+', r'stealth_tcp'
            ]
        }
        return signatures

    def cross_view_analysis(self):
        """Compare different views of system resources"""
        logging.info("Performing cross-view analysis...")
        
        # Compare process lists from different methods
        api_processes = self.get_processes_via_api()
        dir_processes = self.get_processes_via_procfs()
        
        # Find hidden processes
        hidden = set(dir_processes) - set(api_processes)
        for pid in hidden:
            self.scan_results['hidden_processes'].append({
                'pid': pid,
                'method': 'cross_view',
                'confidence': 'high'
            })
        
        # Compare file system views
        self.cross_view_filesystem()

    def get_processes_via_api(self):
        """Get process list using high-level API"""
        processes = []
        for proc in psutil.process_iter(['pid']):
            processes.append(proc.info['pid'])
        return processes

    def get_processes_via_procfs(self):
        """Get process list by reading /proc directory (Linux)"""
        processes = []
        if self.system == 'linux':
            try:
                for entry in os.listdir('/proc'):
                    if entry.isdigit():
                        processes.append(int(entry))
            except Exception as e:
                logging.error(f"Error reading /proc: {e}")
        return processes

    def cross_view_filesystem(self):
        """Compare file system views"""
        if self.system == 'linux':
            # Compare ls output with readdir
            suspicious_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/tmp']
            
            for directory in suspicious_dirs:
                if os.path.exists(directory):
                    try:
                        # High-level view
                        api_files = set(os.listdir(directory))
                        
                        # Low-level view (simplified)
                        low_level_files = set()
                        with os.scandir(directory) as entries:
                            for entry in entries:
                                low_level_files.add(entry.name)
                        
                        # Find hidden files
                        hidden_files = low_level_files - api_files
                        for file in hidden_files:
                            self.scan_results['hidden_files'].append({
                                'path': os.path.join(directory, file),
                                'method': 'cross_view_fs',
                                'confidence': 'high'
                            })
                    except Exception as e:
                        logging.error(f"Error scanning {directory}: {e}")

    def signature_scanning(self):
        """Scan for known rootkit signatures"""
        logging.info("Performing signature scanning...")
        
        # Scan running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                
                # Check against known rootkit process names
                for signature in self.known_rootkit_signatures['processes']:
                    if signature in proc_name:
                        self.scan_results['suspicious_drivers'].append({
                            'type': 'process',
                            'name': proc_name,
                            'pid': proc_info['pid'],
                            'signature': signature,
                            'confidence': 'medium'
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Scan system directories for suspicious files
        system_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/tmp', '/var/tmp']
        for directory in system_dirs:
            if os.path.exists(directory):
                self.scan_directory_for_signatures(directory)

    def scan_directory_for_signatures(self, directory):
        """Scan directory for rootkit signatures"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Check filename against signatures
                    for signature in self.known_rootkit_signatures['files']:
                        if signature in file_lower:
                            self.scan_results['suspicious_drivers'].append({
                                'type': 'file',
                                'path': file_path,
                                'signature': signature,
                                'confidence': 'medium'
                            })
                    
                    # Check file content for suspicious patterns
                    self.scan_file_content(file_path)
        except Exception as e:
            logging.debug(f"Could not scan {directory}: {e}")

    def scan_file_content(self, file_path):
        """Scan file content for suspicious patterns"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB
                
                # Look for common rootkit patterns
                patterns = [
                    b'rootkit',
                    b'hidden',
                    b'stealth',
                    b'hook_',
                    b'sys_call'
                ]
                
                for pattern in patterns:
                    if pattern in content:
                        self.scan_results['suspicious_drivers'].append({
                            'type': 'file_content',
                            'path': file_path,
                            'pattern': pattern.decode('utf-8', errors='ignore'),
                            'confidence': 'low'
                        })
        except Exception:
            pass

    def integrity_checking(self):
        """Check system file integrity"""
        logging.info("Performing integrity checks...")
        
        if self.system == 'linux':
            self.check_linux_integrity()
        elif self.system == 'windows':
            self.check_windows_integrity()

    def check_linux_integrity(self):
        """Check Linux system file integrity"""
        critical_files = {
            '/bin/ls': '54e07d4f4e8f0b7a5c86c4b4e3a0c9e1',  # Example hash
            '/bin/ps': 'a1b2c3d4e5f6789012345678901234567',
            '/bin/netstat': 'f1e2d3c4b5a6978098765432109876543'
        }
        
        for file_path, expected_hash in critical_files.items():
            if os.path.exists(file_path):
                actual_hash = self.calculate_file_hash(file_path)
                if actual_hash != expected_hash:
                    self.scan_results['integrity_violations'].append({
                        'file': file_path,
                        'expected_hash': expected_hash,
                        'actual_hash': actual_hash,
                        'confidence': 'high'
                    })

    def check_windows_integrity(self):
        """Check Windows system file integrity"""
        try:
            # Check critical system files
            system_files = [
                'C:\\Windows\\System32\\ntoskrnl.exe',
                'C:\\Windows\\System32\\winlogon.exe',
                'C:\\Windows\\System32\\lsass.exe'
            ]
            
            for file_path in system_files:
                if os.path.exists(file_path):
                    # Check file size and basic properties
                    stat = os.stat(file_path)
                    if stat.st_size < 1024 or stat.st_size > 100 * 1024 * 1024:  # Suspicious size
                        self.scan_results['integrity_violations'].append({
                            'file': file_path,
                            'issue': 'suspicious_size',
                            'size': stat.st_size,
                            'confidence': 'medium'
                        })
        except Exception as e:
            logging.error(f"Windows integrity check failed: {e}")

    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of file"""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "unknown"

    def behavioral_analysis(self):
        """Perform behavioral analysis for rootkit detection"""
        logging.info("Performing behavioral analysis...")
        
        # Monitor for suspicious process behavior
        self.analyze_process_behavior()
        
        # Check for network anomalies
        self.analyze_network_behavior()
        
        # Check for system call anomalies
        self.analyze_system_calls()

    def analyze_process_behavior(self):
        """Analyze process behavior for anomalies"""
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_times']):
            try:
                proc_info = proc.info
                
                # Check for processes with no parent (possible rootkit)
                parent = proc.parent()
                if parent is None and proc_info['pid'] > 100:  # PID > 100 should have parent
                    self.scan_results['behavioral_anomalies'].append({
                        'type': 'orphan_process',
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'confidence': 'medium'
                    })
                
                # Check for processes hiding in normal directories
                if hasattr(proc, 'exe') and proc.exe():
                    exe_path = proc.exe().lower()
                    suspicious_locations = ['/tmp/', '/var/tmp/', '/dev/shm/']
                    if any(loc in exe_path for loc in suspicious_locations):
                        self.scan_results['behavioral_anomalies'].append({
                            'type': 'suspicious_location',
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'path': exe_path,
                            'confidence': 'medium'
                        })
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def analyze_network_behavior(self):
        """Analyze network behavior for anomalies"""
        try:
            connections = psutil.net_connections()
            hidden_ports = set()
            
            for conn in connections:
                if conn.status == 'LISTEN' and conn.laddr:
                    port = conn.laddr.port
                    # Check for ports that shouldn't be open
                    if port > 10000 and port < 60000:
                        # Look for processes hiding network activity
                        try:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                            if any(sig in proc_name.lower() for sig in self.known_rootkit_signatures['processes']):
                                hidden_ports.add(port)
                        except psutil.NoSuchProcess:
                            hidden_ports.add(port)
            
            if hidden_ports:
                self.scan_results['behavioral_anomalies'].append({
                    'type': 'hidden_ports',
                    'ports': list(hidden_ports),
                    'confidence': 'high'
                })
                    
        except Exception as e:
            logging.error(f"Network analysis failed: {e}")

    def analyze_system_calls(self):
        """Analyze system call patterns"""
        # This would typically use more advanced techniques
        # For demo purposes, we'll check for suspicious loaded modules
        if self.system == 'linux':
            try:
                with open('/proc/modules', 'r') as f:
                    modules = f.read()
                    
                suspicious_modules = ['adore', 'knark', 'phide', 'suckit']
                for module in suspicious_modules:
                    if module in modules.lower():
                        self.scan_results['behavioral_anomalies'].append({
                            'type': 'suspicious_module',
                            'module': module,
                            'confidence': 'high'
                        })
            except Exception as e:
                logging.error(f"Module analysis failed: {e}")

    def hook_detection(self):
        """Detect API hooks and system call hooks"""
        logging.info("Performing hook detection...")
        
        if self.system == 'windows':
            self.detect_windows_hooks()
        elif self.system == 'linux':
            self.detect_linux_hooks()

    def detect_windows_hooks(self):
        """Detect Windows API hooks"""
        try:
            # Check for IAT hooks in common processes
            common_processes = ['explorer.exe', 'svchost.exe', 'winlogon.exe']
            
            for proc_name in common_processes:
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'].lower() == proc_name.lower():
                        # Simplified hook detection - in real implementation,
                        # this would parse PE files and check IAT/EAT
                        self.scan_results['api_hooks'].append({
                            'type': 'potential_iat_hook',
                            'process': proc_name,
                            'confidence': 'low'
                        })
        except Exception as e:
            logging.error(f"Windows hook detection failed: {e}")

    def detect_linux_hooks(self):
        """Detect Linux system call hooks"""
        try:
            # Check syscall table integrity
            if os.path.exists('/proc/kallsyms'):
                with open('/proc/kallsyms', 'r') as f:
                    symbols = f.read()
                
                # Look for suspicious symbols
                suspicious_symbols = ['sys_call_table', 'interrupt_descriptor_table']
                for symbol in suspicious_symbols:
                    if symbol in symbols:
                        lines = [line for line in symbols.split('\n') if symbol in line]
                        for line in lines:
                            self.scan_results['api_hooks'].append({
                                'type': 'kernel_symbol',
                                'symbol': symbol,
                                'address': line.split()[0],
                                'confidence': 'medium'
                            })
        except Exception as e:
            logging.error(f"Linux hook detection failed: {e}")

    def memory_analysis(self):
        """Analyze system memory for rootkit patterns"""
        logging.info("Performing memory analysis...")
        
        # Scan process memory for suspicious patterns
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['pid'] < 100:  # Skip system processes for demo
                    continue
                    
                # Look for common rootkit strings in process memory
                # This is simplified - real implementation would use memory reading APIs
                proc_name = proc.info['name'].lower()
                suspicious_strings = ['rootkit', 'hidden', 'stealth', 'hook_']
                
                for string in suspicious_strings:
                    if string in proc_name:
                        self.scan_results['behavioral_anomalies'].append({
                            'type': 'suspicious_process_name',
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'pattern': string,
                            'confidence': 'low'
                        })
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def comprehensive_scan(self):
        """Perform comprehensive rootkit scan"""
        logging.info("Starting comprehensive rootkit scan...")
        
        scan_methods = [
            self.cross_view_analysis,
            self.signature_scanning,
            self.integrity_checking,
            self.behavioral_analysis,
            self.hook_detection,
            self.memory_analysis
        ]
        
        for method in scan_methods:
            try:
                method()
            except Exception as e:
                logging.error(f"Scan method {method.__name__} failed: {e}")
        
        return self.generate_report()

    def generate_report(self):
        """Generate comprehensive scan report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system': self.system,
            'scan_results': self.scan_results,
            'summary': self.generate_summary()
        }
        
        # Save report to file
        with open('rootkit_scan_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

    def generate_summary(self):
        """Generate scan summary"""
        total_findings = sum(len(items) for items in self.scan_results.values())
        
        summary = {
            'total_findings': total_findings,
            'risk_level': 'LOW',
            'recommendations': []
        }
        
        # Calculate risk level
        high_confidence = 0
        for category, items in self.scan_results.items():
            for item in items:
                if item.get('confidence') == 'high':
                    high_confidence += 1
        
        if high_confidence > 0:
            summary['risk_level'] = 'HIGH'
        elif total_findings > 5:
            summary['risk_level'] = 'MEDIUM'
        
        # Generate recommendations
        if self.scan_results['hidden_processes']:
            summary['recommendations'].append(
                "Investigate hidden processes - possible rootkit activity"
            )
        
        if self.scan_results['integrity_violations']:
            summary['recommendations'].append(
                "System file integrity compromised - consider reinstalling critical system files"
            )
        
        if not summary['recommendations'] and total_findings == 0:
            summary['recommendations'].append("No rootkit activity detected")
        
        return summary

    def remove_detected_threats(self):
        """Attempt to remove detected rootkits"""
        logging.warning("Attempting to remove detected threats...")
        
        removal_actions = []
        
        # Remove suspicious files
        for item in self.scan_results['suspicious_drivers']:
            if item['type'] == 'file':
                try:
                    os.remove(item['path'])
                    removal_actions.append(f"Removed file: {item['path']}")
                except Exception as e:
                    removal_actions.append(f"Failed to remove {item['path']}: {e}")
        
        # Terminate suspicious processes
        for item in self.scan_results['hidden_processes'] + self.scan_results['behavioral_anomalies']:
            if 'pid' in item:
                try:
                    proc = psutil.Process(item['pid'])
                    proc.terminate()
                    removal_actions.append(f"Terminated process: {item['pid']}")
                except Exception as e:
                    removal_actions.append(f"Failed to terminate process {item['pid']}: {e}")
        
        return removal_actions

class RealTimeMonitor:
    """Real-time rootkit monitoring"""
    
    def __init__(self):
        self.scanner = RootkitScanner()
        self.monitoring = False
        
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.monitoring = True
        logging.info("Starting real-time rootkit monitoring...")
        
        while self.monitoring:
            try:
                # Perform quick scans periodically
                self.scanner.behavioral_analysis()
                self.scanner.cross_view_analysis()
                
                # Check for critical findings
                critical_findings = []
                for category, items in self.scanner.scan_results.items():
                    for item in items:
                        if item.get('confidence') == 'high':
                            critical_findings.append(item)
                
                if critical_findings:
                    logging.critical(f"Critical findings detected: {critical_findings}")
                
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                logging.error(f"Monitoring error: {e}")
                time.sleep(60)

    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False

def main():
    """Main function"""
    print("Rootkit Detection & Removal Toolkit")
    print("===================================")
    print("WARNING: Run with appropriate privileges")
    print("This tool should be used in authorized environments only\n")
    
    scanner = RootkitScanner()
    
    while True:
        print("\nOptions:")
        print("1. Quick Scan")
        print("2. Comprehensive Scan")
        print("3. Real-time Monitoring")
        print("4. Remove Detected Threats")
        print("5. View Scan Report")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            print("Performing quick scan...")
            scanner.behavioral_analysis()
            scanner.cross_view_analysis()
            report = scanner.generate_report()
            print(f"Quick scan completed. Findings: {report['summary']['total_findings']}")
            
        elif choice == '2':
            print("Performing comprehensive scan...")
            report = scanner.comprehensive_scan()
            print(f"Comprehensive scan completed.")
            print(f"Risk Level: {report['summary']['risk_level']}")
            print(f"Total Findings: {report['summary']['total_findings']}")
            
        elif choice == '3':
            print("Starting real-time monitoring...")
            monitor = RealTimeMonitor()
            try:
                monitor.start_monitoring()
            except KeyboardInterrupt:
                monitor.stop_monitoring()
                print("Monitoring stopped.")
                
        elif choice == '4':
            print("Attempting to remove detected threats...")
            actions = scanner.remove_detected_threats()
            for action in actions:
                print(f"  {action}")
                
        elif choice == '5':
            try:
                with open('rootkit_scan_report.json', 'r') as f:
                    report = json.load(f)
                print(f"Last Scan: {report['timestamp']}")
                print(f"Risk Level: {report['summary']['risk_level']}")
                print(f"Findings: {report['summary']['total_findings']}")
                print("Recommendations:")
                for rec in report['summary']['recommendations']:
                    print(f"  - {rec}")
            except FileNotFoundError:
                print("No scan report found. Please run a scan first.")
                
        elif choice == '6':
            print("Exiting...")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
