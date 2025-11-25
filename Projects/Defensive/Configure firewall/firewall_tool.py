#!/usr/bin/env python3
"""
Firewall Rule Automation Toolkit - Python Implementation
Multi-platform firewall configuration generator and tester
"""

import os
import sys
import json
import yaml
import argparse
import subprocess
import ipaddress
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import re

class FirewallRule:
    """Represents a firewall rule with validation"""
    
    def __init__(self, name: str, action: str, protocol: str, src: str, dst: str, 
                 sport: str = None, dport: str = None, description: str = ""):
        self.name = name
        self.action = action  # allow, deny, drop, reject
        self.protocol = protocol.lower()  # tcp, udp, icmp, any
        self.src = src  # IP, CIDR, or any
        self.dst = dst  # IP, CIDR, or any
        self.sport = sport  # Source port
        self.dport = dport  # Destination port
        self.description = description
        self.enabled = True
        
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate rule parameters"""
        errors = []
        
        # Validate action
        valid_actions = ['allow', 'deny', 'drop', 'reject']
        if self.action.lower() not in valid_actions:
            errors.append(f"Invalid action: {self.action}. Must be one of {valid_actions}")
        
        # Validate protocol
        valid_protocols = ['tcp', 'udp', 'icmp', 'any', 'ip', 'all']
        if self.protocol.lower() not in valid_protocols:
            errors.append(f"Invalid protocol: {self.protocol}. Must be one of {valid_protocols}")
        
        # Validate IP addresses/CIDR
        for field, value in [('source', self.src), ('destination', self.dst)]:
            if value.lower() != 'any':
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    errors.append(f"Invalid {field} IP/CIDR: {value}")
        
        # Validate ports
        if self.sport and self.sport != 'any':
            if not self._validate_port(self.sport):
                errors.append(f"Invalid source port: {self.sport}")
        
        if self.dport and self.dport != 'any':
            if not self._validate_port(self.dport):
                errors.append(f"Invalid destination port: {self.dport}")
        
        # Protocol-port consistency
        if self.protocol in ['tcp', 'udp'] and not self.dport:
            errors.append(f"Port required for protocol: {self.protocol}")
        
        return len(errors) == 0, errors
    
    def _validate_port(self, port: str) -> bool:
        """Validate port specification"""
        # Single port
        if port.isdigit():
            return 1 <= int(port) <= 65535
        
        # Port range
        if ':' in port:
            parts = port.split(':')
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                return 1 <= int(parts[0]) <= 65535 and 1 <= int(parts[1]) <= 65535
        
        # Multiple ports
        if ',' in port:
            return all(self._validate_port(p.strip()) for p in port.split(','))
        
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary"""
        return {
            'name': self.name,
            'action': self.action,
            'protocol': self.protocol,
            'src': self.src,
            'dst': self.dst,
            'sport': self.sport,
            'dport': self.dport,
            'description': self.description,
            'enabled': self.enabled
        }

class FirewallTemplate:
    """Firewall configuration templates for different platforms"""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, Any]:
        """Load platform-specific templates"""
        return {
            'iptables': {
                'chain_template': "{action} {protocol} -s {src} -d {dst} {sport} {dport} -j {target}",
                'comment_template': "# {description}",
                'target_map': {
                    'allow': 'ACCEPT',
                    'deny': 'DROP', 
                    'drop': 'DROP',
                    'reject': 'REJECT'
                }
            },
            'nftables': {
                'rule_template': "{action} {protocol} {src} {dst} {sport} {dport} # {description}",
                'target_map': {
                    'allow': 'accept',
                    'deny': 'drop',
                    'drop': 'drop',
                    'reject': 'reject'
                }
            },
            'windows': {
                'rule_template': 'New-NetFirewallRule -DisplayName "{name}" -Direction Inbound -Protocol {protocol} -Action {action} {src} {dst} {sport} {dport} -Description "{description}"',
                'action_map': {
                    'allow': 'Allow',
                    'deny': 'Block',
                    'drop': 'Block',
                    'reject': 'Block'
                }
            },
            'aws': {
                'rule_template': {
                    'IpProtocol': '{protocol}',
                    'FromPort': '{from_port}',
                    'ToPort': '{to_port}',
                    'IpRanges': [{'CidrIp': '{src}', 'Description': '{description}'}]
                }
            },
            'azure': {
                'rule_template': {
                    'name': '{name}',
                    'properties': {
                        'protocol': '{protocol}',
                        'sourceAddressPrefix': '{src}',
                        'destinationAddressPrefix': '{dst}',
                        'sourcePortRange': '{sport}',
                        'destinationPortRange': '{dport}',
                        'access': '{action}',
                        'priority': 100,
                        'direction': 'Inbound'
                    }
                }
            }
        }
    
    def generate_iptables_config(self, rules: List[FirewallRule], chain: str = "INPUT") -> str:
        """Generate iptables configuration"""
        config = f"# iptables configuration\n# Generated: {datetime.now().isoformat()}\n\n"
        
        # Filter rules by enabled status
        enabled_rules = [r for r in rules if r.enabled]
        
        for rule in enabled_rules:
            # Add comment
            if rule.description:
                config += f"# {rule.description}\n"
            
            # Build rule components
            target = self.templates['iptables']['target_map'][rule.action]
            
            sport = f"--sport {rule.sport}" if rule.sport and rule.sport != 'any' else ""
            dport = f"--dport {rule.dport}" if rule.dport and rule.dport != 'any' else ""
            
            protocol = rule.protocol.upper() if rule.protocol != 'any' else 'all'
            
            config += f"iptables -A {chain} -p {protocol} -s {rule.src} -d {rule.dst} {sport} {dport} -j {target}\n"
        
        config += "\n# Default policies\n"
        config += "iptables -P INPUT DROP\n"
        config += "iptables -P FORWARD DROP\n"
        config += "iptables -P OUTPUT ACCEPT\n"
        
        return config
    
    def generate_nftables_config(self, rules: List[FirewallRule]) -> str:
        """Generate nftables configuration"""
        config = f"# nftables configuration\n# Generated: {datetime.now().isoformat()}\n\n"
        
        config += "table inet filter {\n"
        config += "  chain input {\n"
        config += "    type filter hook input priority 0; policy drop;\n"
        
        enabled_rules = [r for r in rules if r.enabled]
        for rule in enabled_rules:
            target = self.templates['nftables']['target_map'][rule.action]
            
            sport = f"sport {rule.sport}" if rule.sport and rule.sport != 'any' else ""
            dport = f"dport {rule.dport}" if rule.dport and rule.dport != 'any' else ""
            
            protocol = rule.protocol if rule.protocol != 'any' else 'ip'
            
            rule_line = f"    {protocol} saddr {rule.src} daddr {rule.dst} {sport} {dport} {target}"
            if rule.description:
                rule_line += f" comment \"{rule.description}\""
            
            config += rule_line + "\n"
        
        config += "  }\n"
        config += "  chain forward {\n"
        config += "    type filter hook forward priority 0; policy drop;\n"
        config += "  }\n"
        config += "  chain output {\n"
        config += "    type filter hook output priority 0; policy accept;\n"
        config += "  }\n"
        config += "}\n"
        
        return config
    
    def generate_windows_firewall_config(self, rules: List[FirewallRule]) -> str:
        """Generate Windows Firewall PowerShell script"""
        config = f"# Windows Firewall Configuration\n# Generated: {datetime.now().isoformat()}\n\n"
        
        config += "# Remove existing rules\n"
        config += "Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'AutoGen-*'} | Remove-NetFirewallRule\n\n"
        
        enabled_rules = [r for r in rules if r.enabled]
        for rule in enabled_rules:
            action = self.templates['windows']['action_map'][rule.action]
            
            # Build parameters
            src_param = f"-RemoteAddress {rule.src}" if rule.src != 'any' else ""
            dst_param = f"-LocalAddress {rule.dst}" if rule.dst != 'any' else ""
            
            sport_param = f"-RemotePort {rule.sport}" if rule.sport and rule.sport != 'any' else ""
            dport_param = f"-LocalPort {rule.dport}" if rule.dport and rule.dport != 'any' else ""
            
            protocol = rule.protocol.upper() if rule.protocol != 'any' else 'Any'
            
            config += f"# {rule.description}\n" if rule.description else ""
            config += f'New-NetFirewallRule -DisplayName "AutoGen-{rule.name}" -Direction Inbound ' \
                     f'-Protocol {protocol} -Action {action} {src_param} {dst_param} {sport_param} {dport_param} ' \
                     f'-Description "{rule.description}"\n\n'
        
        return config
    
    def generate_aws_security_group(self, rules: List[FirewallRule], group_name: str) -> Dict[str, Any]:
        """Generate AWS Security Group configuration"""
        security_group = {
            'GroupName': group_name,
            'Description': f'Auto-generated security group - {datetime.now().isoformat()}',
            'IpPermissions': [],
            'IpPermissionsEgress': [
                {
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        }
        
        enabled_rules = [r for r in rules if r.enabled and r.action == 'allow']
        for rule in enabled_rules:
            permission = {
                'IpProtocol': rule.protocol if rule.protocol != 'any' else '-1'
            }
            
            # Handle ports
            if rule.dport and rule.dport != 'any' and rule.protocol in ['tcp', 'udp']:
                if ':' in rule.dport:
                    from_port, to_port = rule.dport.split(':')
                    permission['FromPort'] = int(from_port)
                    permission['ToPort'] = int(to_port)
                else:
                    port = int(rule.dport)
                    permission['FromPort'] = port
                    permission['ToPort'] = port
            
            # Handle IP ranges
            ip_ranges = []
            if rule.src != 'any':
                ip_ranges.append({
                    'CidrIp': rule.src,
                    'Description': rule.description or rule.name
                })
            else:
                ip_ranges.append({'CidrIp': '0.0.0.0/0'})
            
            permission['IpRanges'] = ip_ranges
            security_group['IpPermissions'].append(permission)
        
        return security_group
    
    def generate_azure_nsg(self, rules: List[FirewallRule], nsg_name: str) -> Dict[str, Any]:
        """Generate Azure Network Security Group configuration"""
        nsg = {
            'name': nsg_name,
            'properties': {
                'securityRules': []
            }
        }
        
        enabled_rules = [r for r in rules if r.enabled]
        priority = 100
        
        for rule in enabled_rules:
            security_rule = {
                'name': f"AutoGen-{rule.name}",
                'properties': {
                    'protocol': rule.protocol.upper() if rule.protocol != 'any' else '*',
                    'sourceAddressPrefix': rule.src if rule.src != 'any' else '*',
                    'destinationAddressPrefix': rule.dst if rule.dst != 'any' else '*',
                    'access': rule.action.upper(),
                    'priority': priority,
                    'direction': 'Inbound'
                }
            }
            
            # Port handling
            if rule.sport and rule.sport != 'any':
                security_rule['properties']['sourcePortRange'] = rule.sport
            else:
                security_rule['properties']['sourcePortRange'] = '*'
            
            if rule.dport and rule.dport != 'any':
                security_rule['properties']['destinationPortRange'] = rule.dport
            else:
                security_rule['properties']['destinationPortRange'] = '*'
            
            if rule.description:
                security_rule['properties']['description'] = rule.description
            
            nsg['properties']['securityRules'].append(security_rule)
            priority += 1
        
        return nsg

class FirewallRuleManager:
    """Manage firewall rules with validation and testing"""
    
    def __init__(self, rule_file: str = None):
        self.rules = []
        self.rule_file = rule_file
        if rule_file and os.path.exists(rule_file):
            self.load_rules(rule_file)
    
    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a rule with validation"""
        is_valid, errors = rule.validate()
        if not is_valid:
            print(f"Rule validation failed: {errors}")
            return False
        
        # Check for duplicates
        for existing_rule in self.rules:
            if self._rules_equal(existing_rule, rule):
                print(f"Duplicate rule detected: {rule.name}")
                return False
        
        self.rules.append(rule)
        return True
    
    def _rules_equal(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if two rules are effectively the same"""
        return (rule1.protocol == rule2.protocol and
                rule1.src == rule2.src and
                rule1.dst == rule2.dst and
                rule1.sport == rule2.sport and
                rule1.dport == rule2.dport and
                rule1.action == rule2.action)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove rule by name"""
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                del self.rules[i]
                return True
        return False
    
    def enable_rule(self, rule_name: str) -> bool:
        """Enable a rule"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True
                return True
        return False
    
    def disable_rule(self, rule_name: str) -> bool:
        """Disable a rule"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False
                return True
        return False
    
    def load_rules(self, file_path: str) -> bool:
        """Load rules from JSON or YAML file"""
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith('.json'):
                    data = json.load(f)
                elif file_path.endswith(('.yaml', '.yml')):
                    data = yaml.safe_load(f)
                else:
                    print("Unsupported file format")
                    return False
            
            self.rules = []
            for rule_data in data.get('rules', []):
                rule = FirewallRule(
                    name=rule_data['name'],
                    action=rule_data['action'],
                    protocol=rule_data['protocol'],
                    src=rule_data['src'],
                    dst=rule_data['dst'],
                    sport=rule_data.get('sport'),
                    dport=rule_data.get('dport'),
                    description=rule_data.get('description', '')
                )
                rule.enabled = rule_data.get('enabled', True)
                self.add_rule(rule)
            
            print(f"Loaded {len(self.rules)} rules from {file_path}")
            return True
            
        except Exception as e:
            print(f"Error loading rules: {e}")
            return False
    
    def save_rules(self, file_path: str) -> bool:
        """Save rules to JSON or YAML file"""
        try:
            data = {
                'metadata': {
                    'generated': datetime.now().isoformat(),
                    'rule_count': len(self.rules),
                    'enabled_count': len([r for r in self.rules if r.enabled])
                },
                'rules': [rule.to_dict() for rule in self.rules]
            }
            
            with open(file_path, 'w') as f:
                if file_path.endswith('.json'):
                    json.dump(data, f, indent=2)
                elif file_path.endswith(('.yaml', '.yml')):
                    yaml.dump(data, f, default_flow_style=False)
                else:
                    print("Unsupported file format")
                    return False
            
            print(f"Saved {len(self.rules)} rules to {file_path}")
            return True
            
        except Exception as e:
            print(f"Error saving rules: {e}")
            return False
    
    def validate_all_rules(self) -> Tuple[bool, List[str]]:
        """Validate all rules"""
        all_errors = []
        for rule in self.rules:
            is_valid, errors = rule.validate()
            if not is_valid:
                all_errors.append(f"Rule '{rule.name}': {', '.join(errors)}")
        
        return len(all_errors) == 0, all_errors
    
    def analyze_rules(self) -> Dict[str, Any]:
        """Analyze rule set for common issues"""
        analysis = {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules if r.enabled]),
            'disabled_rules': len([r for r in self.rules if not r.enabled]),
            'by_protocol': {},
            'by_action': {},
            'issues': []
        }
        
        # Count by protocol and action
        for rule in self.rules:
            if rule.enabled:
                analysis['by_protocol'][rule.protocol] = analysis['by_protocol'].get(rule.protocol, 0) + 1
                analysis['by_action'][rule.action] = analysis['by_action'].get(rule.action, 0) + 1
        
        # Check for common issues
        for rule in self.rules:
            if rule.enabled:
                # Check for overly permissive rules
                if rule.src == 'any' and rule.action == 'allow':
                    analysis['issues'].append(f"Overly permissive rule: {rule.name} allows from any source")
                
                # Check for wide port ranges
                if rule.dport and ':' in rule.dport:
                    from_port, to_port = map(int, rule.dport.split(':'))
                    if to_port - from_port > 1000:
                        analysis['issues'].append(f"Wide port range in rule: {rule.name} ({rule.dport})")
        
        return analysis

class FirewallTester:
    """Test firewall rules and configurations"""
    
    def __init__(self):
        self.test_cases = self._load_test_cases()
    
    def _load_test_cases(self) -> Dict[str, Any]:
        """Load standard test cases"""
        return {
            'ssh_access': {
                'description': 'SSH access test',
                'protocol': 'tcp',
                'port': 22,
                'expected': 'allow'
            },
            'web_access': {
                'description': 'HTTP/HTTPS access test',
                'protocol': 'tcp',
                'ports': [80, 443],
                'expected': 'allow'
            },
            'dns_access': {
                'description': 'DNS access test',
                'protocol': 'udp',
                'port': 53,
                'expected': 'allow'
            },
            'icmp_test': {
                'description': 'ICMP ping test',
                'protocol': 'icmp',
                'expected': 'allow'
            },
            'rdp_block': {
                'description': 'RDP should be blocked',
                'protocol': 'tcp',
                'port': 3389,
                'expected': 'deny'
            }
        }
    
    def test_rule_coverage(self, rules: List[FirewallRule]) -> Dict[str, Any]:
        """Test if rules provide expected coverage"""
        coverage = {
            'passed': [],
            'failed': [],
            'warnings': []
        }
        
        for test_name, test_case in self.test_cases.items():
            # Find matching rules
            matching_rules = []
            for rule in rules:
                if rule.enabled and self._rule_matches_test(rule, test_case):
                    matching_rules.append(rule)
            
            # Check if expected action is present
            expected_action_present = any(
                rule.action == test_case['expected'] for rule in matching_rules
            )
            
            if expected_action_present:
                coverage['passed'].append({
                    'test': test_name,
                    'description': test_case['description'],
                    'status': 'PASS'
                })
            else:
                coverage['failed'].append({
                    'test': test_name,
                    'description': test_case['description'],
                    'status': 'FAIL',
                    'expected': test_case['expected']
                })
        
        return coverage
    
    def _rule_matches_test(self, rule: FirewallRule, test_case: Dict[str, Any]) -> bool:
        """Check if a rule matches a test case"""
        # Protocol match
        if rule.protocol != test_case['protocol'] and rule.protocol != 'any':
            return False
        
        # Port match
        if 'port' in test_case and rule.dport:
            test_port = str(test_case['port'])
            if rule.dport != test_port and test_port not in rule.dport.split(','):
                return False
        
        # Port range match
        if 'ports' in test_case and rule.dport:
            test_ports = [str(p) for p in test_case['ports']]
            rule_ports = rule.dport.split(',')
            if not any(tp in rule_ports for tp in test_ports):
                return False
        
        return True
    
    def simulate_traffic(self, rules: List[FirewallRule], traffic: Dict[str, Any]) -> str:
        """Simulate traffic against rules to determine action"""
        src_ip = traffic.get('src_ip', 'any')
        dst_ip = traffic.get('dst_ip', 'any')
        protocol = traffic.get('protocol', 'any')
        dport = traffic.get('dport')
        
        # Find matching rules
        matching_rules = []
        for rule in rules:
            if not rule.enabled:
                continue
            
            # Check protocol
            if rule.protocol != 'any' and rule.protocol != protocol:
                continue
            
            # Check source IP
            if rule.src != 'any':
                try:
                    if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(rule.src):
                        continue
                except ValueError:
                    continue
            
            # Check destination IP
            if rule.dst != 'any':
                try:
                    if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(rule.dst):
                        continue
                except ValueError:
                    continue
            
            # Check destination port
            if rule.dport and rule.dport != 'any' and dport:
                if ':' in rule.dport:
                    # Port range
                    from_port, to_port = map(int, rule.dport.split(':'))
                    if not (from_port <= dport <= to_port):
                        continue
                elif ',' in rule.dport:
                    # Multiple ports
                    ports = [int(p.strip()) for p in rule.dport.split(',')]
                    if dport not in ports:
                        continue
                else:
                    # Single port
                    if int(rule.dport) != dport:
                        continue
            
            matching_rules.append(rule)
        
        # Return action from first matching rule, or default deny
        if matching_rules:
            return matching_rules[0].action
        else:
            return 'deny'  # Default deny
    
    def generate_test_report(self, coverage: Dict[str, Any]) -> str:
        """Generate test report"""
        report = f"""
Firewall Rule Test Report
Generated: {datetime.now().isoformat()}
{'='*50}

Summary:
- Total Tests: {len(coverage['passed']) + len(coverage['failed'])}
- Passed: {len(coverage['passed'])}
- Failed: {len(coverage['failed'])}

Passed Tests:
"""
        for test in coverage['passed']:
            report += f"  ✅ {test['test']}: {test['description']}\n"
        
        if coverage['failed']:
            report += "\nFailed Tests:\n"
            for test in coverage['failed']:
                report += f"  ❌ {test['test']}: {test['description']} (expected: {test['expected']})\n"
        
        if coverage['warnings']:
            report += "\nWarnings:\n"
            for warning in coverage['warnings']:
                report += f"  ⚠️  {warning}\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Firewall Rule Automation Toolkit')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Rule management commands
    rule_parser = subparsers.add_parser('rules', help='Manage firewall rules')
    rule_parser.add_argument('--add', action='store_true', help='Add a new rule')
    rule_parser.add_argument('--list', action='store_true', help='List all rules')
    rule_parser.add_argument('--validate', action='store_true', help='Validate all rules')
    rule_parser.add_argument('--analyze', action='store_true', help='Analyze rule set')
    rule_parser.add_argument('--file', required=True, help='Rule file path')
    
    # Configuration generation commands
    config_parser = subparsers.add_parser('generate', help='Generate firewall configurations')
    config_parser.add_argument('--platform', choices=['iptables', 'nftables', 'windows', 'aws', 'azure'], 
                              required=True, help='Target platform')
    config_parser.add_argument('--input', required=True, help='Input rule file')
    config_parser.add_argument('--output', help='Output file path')
    config_parser.add_argument('--name', help='Resource name (for cloud platforms)')
    
    # Testing commands
    test_parser = subparsers.add_parser('test', help='Test firewall rules')
    test_parser.add_argument('--file', required=True, help='Rule file to test')
    test_parser.add_argument('--coverage', action='store_true', help='Test rule coverage')
    test_parser.add_argument('--simulate', help='Simulate traffic (format: src_ip,dst_ip,protocol,dport)')
    test_parser.add_argument('--report', action='store_true', help='Generate test report')
    
    args = parser.parse_args()
    
    if args.command == 'rules':
        manager = FirewallRuleManager(args.file)
        
        if args.add:
            # Interactive rule addition
            print("Adding new firewall rule:")
            name = input("Rule name: ")
            action = input("Action (allow/deny/drop/reject): ")
            protocol = input("Protocol (tcp/udp/icmp/any): ")
            src = input("Source IP/CIDR (any for any): ")
            dst = input("Destination IP/CIDR (any for any): ")
            sport = input("Source port (any for any): ") or None
            dport = input("Destination port (any for any): ") or None
            description = input("Description: ")
            
            rule = FirewallRule(name, action, protocol, src, dst, sport, dport, description)
            if manager.add_rule(rule):
                manager.save_rules(args.file)
        
        if args.list:
            print(f"\nFirewall Rules ({len(manager.rules)} total):")
            for rule in manager.rules:
                status = "ENABLED" if rule.enabled else "DISABLED"
                print(f"{status}: {rule.name} - {rule.action} {rule.protocol} from {rule.src} to {rule.dst}:{rule.dport or 'any'}")
        
        if args.validate:
            is_valid, errors = manager.validate_all_rules()
            if is_valid:
                print("✅ All rules are valid")
            else:
                print("❌ Rule validation errors:")
                for error in errors:
                    print(f"  - {error}")
        
        if args.analyze:
            analysis = manager.analyze_rules()
            print(json.dumps(analysis, indent=2))
    
    elif args.command == 'generate':
        manager = FirewallRuleManager(args.input)
        template = FirewallTemplate()
        
        if args.platform == 'iptables':
            config = template.generate_iptables_config(manager.rules)
        elif args.platform == 'nftables':
            config = template.generate_nftables_config(manager.rules)
        elif args.platform == 'windows':
            config = template.generate_windows_firewall_config(manager.rules)
        elif args.platform == 'aws':
            config = template.generate_aws_security_group(manager.rules, args.name or 'auto-generated-sg')
            config = json.dumps(config, indent=2)
        elif args.platform == 'azure':
            config = template.generate_azure_nsg(manager.rules, args.name or 'auto-generated-nsg')
            config = json.dumps(config, indent=2)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(config)
            print(f"[+] Configuration saved to: {args.output}")
        else:
            print(config)
    
    elif args.command == 'test':
        manager = FirewallRuleManager(args.file)
        tester = FirewallTester()
        
        if args.coverage:
            coverage = tester.test_rule_coverage(manager.rules)
            if args.report:
                report = tester.generate_test_report(coverage)
                print(report)
            else:
                print(json.dumps(coverage, indent=2))
        
        if args.simulate:
            parts = args.simulate.split(',')
            if len(parts) == 4:
                traffic = {
                    'src_ip': parts[0],
                    'dst_ip': parts[1],
                    'protocol': parts[2],
                    'dport': int(parts[3])
                }
                action = tester.simulate_traffic(manager.rules, traffic)
                print(f"Traffic action: {action}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
