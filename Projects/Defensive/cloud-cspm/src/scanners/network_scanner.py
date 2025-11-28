"""
Network Security Scanner
Detects insecure network configurations
"""

import logging
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class NetworkScanner(BaseScanner):
    """Network Security Misconfiguration Scanner"""
    
    def __init__(self, connectors: Dict[str, Any]):
        super().__init__(connectors)
        self.scanner_name = "Network Security Scanner"
        self.logger = logging.getLogger(__name__)
        
    def scan(self) -> List[Dict[str, Any]]:
        """Perform network security scan"""
        findings = []
        
        # AWS Network scanning
        if 'aws' in self.connectors:
            findings.extend(self.scan_aws_network())
            
        # Azure Network scanning
        if 'azure' in self.connectors:
            findings.extend(self.scan_azure_network())
            
        # GCP Network scanning
        if 'gcp' in self.connectors:
            findings.extend(self.scan_gcp_network())
            
        return findings
    
    def scan_aws_network(self) -> List[Dict[str, Any]]:
        """Scan AWS network resources for misconfigurations"""
        findings = []
        aws_connector = self.connectors['aws']
        
        try:
            security_groups = aws_connector.list_security_groups()
            for sg in security_groups:
                findings.extend(self.analyze_security_group(sg))
                
        except Exception as e:
            self.logger.error(f"AWS network scan failed: {str(e)}")
            
        return findings
    
    def analyze_security_group(self, sg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security group for security issues"""
        findings = []
        
        # Check ingress rules
        for rule in sg.get('ip_permissions', []):
            findings.extend(self.analyze_security_group_rule(sg, rule, 'ingress'))
            
        # Check egress rules
        for rule in sg.get('ip_permissions_egress', []):
            findings.extend(self.analyze_security_group_rule(sg, rule, 'egress'))
            
        return findings
    
    def analyze_security_group_rule(self, sg: Dict[str, Any], rule: Dict[str, Any], 
                                  direction: str) -> List[Dict[str, Any]]:
        """Analyze individual security group rule"""
        findings = []
        
        # Check for open CIDR ranges
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            if cidr == '0.0.0.0/0':
                # Check if this is a dangerous port
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if self.is_dangerous_port(from_port, to_port):
                    findings.append({
                        'provider': 'aws',
                        'resource_type': 'Security_Group',
                        'resource_id': sg['group_id'],
                        'resource_arn': f"arn:aws:ec2:{sg.get('region', 'us-east-1')}:{sg.get('account_id', '')}:security-group/{sg['group_id']}",
                        'finding_type': 'OPEN_SECURITY_GROUP',
                        'title': f'Open Security Group Rule ({direction})',
                        'description': f"Security group {sg['group_name']} ({sg['group_id']}) has open {direction} rule on port {from_port}-{to_port}",
                        'severity': 'HIGH' if self.is_critical_port(from_port, to_port) else 'MEDIUM',
                        'category': 'Network',
                        'details': {
                            'security_group_id': sg['group_id'],
                            'security_group_name': sg['group_name'],
                            'direction': direction,
                            'from_port': from_port,
                            'to_port': to_port,
                            'protocol': rule.get('IpProtocol'),
                            'cidr_ip': cidr,
                            'description': sg.get('description', '')
                        }
                    })
                    
        return findings
    
    def is_dangerous_port(self, from_port: int, to_port: int) -> bool:
        """Check if port range is considered dangerous when open to internet"""
        dangerous_ports = [22, 3389, 1433, 3306, 5432, 1521, 27017]  # SSH, RDP, DB ports
        
        if from_port is None or to_port is None:
            return True  # All ports
            
        for port in dangerous_ports:
            if from_port <= port <= to_port:
                return True
                
        return False
    
    def is_critical_port(self, from_port: int, to_port: int) -> bool:
        """Check if port range includes critical services"""
        critical_ports = [22, 3389]  # SSH, RDP
        
        if from_port is None or to_port is None:
            return True  # All ports
            
        for port in critical_ports:
            if from_port <= port <= to_port:
                return True
                
        return False
    
    def scan_azure_network(self) -> List[Dict[str, Any]]:
        """Scan Azure network (placeholder implementation)"""
        return []
    
    def scan_gcp_network(self) -> List[Dict[str, Any]]:
        """Scan GCP network (placeholder implementation)"""
        return []
