"""
IAM Security Scanner
Detects IAM misconfigurations and risky permissions
"""

import json
import logging
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class IAMScanner(BaseScanner):
    """IAM Security Misconfiguration Scanner"""
    
    def __init__(self, connectors: Dict[str, Any]):
        super().__init__(connectors)
        self.scanner_name = "IAM Security Scanner"
        self.logger = logging.getLogger(__name__)
        
    def scan(self) -> List[Dict[str, Any]]:
        """Perform IAM security scan"""
        findings = []
        
        # AWS IAM scanning
        if 'aws' in self.connectors:
            findings.extend(self.scan_aws_iam())
            
        # Azure IAM scanning
        if 'azure' in self.connectors:
            findings.extend(self.scan_azure_iam())
            
        # GCP IAM scanning
        if 'gcp' in self.connectors:
            findings.extend(self.scan_gcp_iam())
            
        return findings
    
    def scan_aws_iam(self) -> List[Dict[str, Any]]:
        """Scan AWS IAM for misconfigurations"""
        findings = []
        aws_connector = self.connectors['aws']
        
        try:
            # Scan IAM users
            users = aws_connector.list_iam_users()
            for user in users:
                findings.extend(self.analyze_iam_user(user))
                
            # Scan IAM roles
            roles = aws_connector.list_iam_roles()
            for role in roles:
                findings.extend(self.analyze_iam_role(role))
                
        except Exception as e:
            self.logger.error(f"AWS IAM scan failed: {str(e)}")
            
        return findings
    
    def analyze_iam_user(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze IAM user for security issues"""
        findings = []
        
        # Check for users with no MFA (simplified check)
        if not self.has_mfa(user):
            findings.append({
                'provider': 'aws',
                'resource_type': 'IAM_User',
                'resource_id': user['user_name'],
                'resource_arn': user['arn'],
                'finding_type': 'NO_MFA',
                'title': 'IAM User without Multi-Factor Authentication',
                'description': f"IAM user {user['user_name']} does not have MFA enabled",
                'severity': 'HIGH',
                'category': 'IAM',
                'details': {
                    'user_name': user['user_name'],
                    'create_date': str(user['create_date']),
                    'policies': user['policies']
                }
            })
        
        # Check for access keys older than 90 days
        for access_key in user.get('access_keys', []):
            if self.is_access_key_old(access_key):
                findings.append({
                    'provider': 'aws',
                    'resource_type': 'IAM_AccessKey',
                    'resource_id': access_key['access_key_id'],
                    'resource_arn': user['arn'],
                    'finding_type': 'OLD_ACCESS_KEY',
                    'title': 'Old IAM Access Key',
                    'description': f"Access key {access_key['access_key_id']} for user {user['user_name']} is older than 90 days",
                    'severity': 'MEDIUM',
                    'category': 'IAM',
                    'details': {
                        'user_name': user['user_name'],
                        'access_key_id': access_key['access_key_id'],
                        'create_date': str(access_key['create_date']),
                        'status': access_key['status']
                    }
                })
        
        # Check for inline policies (considered risky)
        if user['policies']['inline_policies']:
            findings.append({
                'provider': 'aws',
                'resource_type': 'IAM_User',
                'resource_id': user['user_name'],
                'resource_arn': user['arn'],
                'finding_type': 'INLINE_POLICY',
                'title': 'IAM User with Inline Policies',
                'description': f"IAM user {user['user_name']} has inline policies which are harder to manage",
                'severity': 'LOW',
                'category': 'IAM',
                'details': {
                    'user_name': user['user_name'],
                    'inline_policies': user['policies']['inline_policies']
                }
            })
            
        return findings
    
    def analyze_iam_role(self, role: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze IAM role for security issues"""
        findings = []
        
        # Check for wildcard permissions in trust policy
        trust_policy = role.get('assume_role_policy_document', {})
        if self.has_wildcard_principal(trust_policy):
            findings.append({
                'provider': 'aws',
                'resource_type': 'IAM_Role',
                'resource_id': role['role_name'],
                'resource_arn': role['arn'],
                'finding_type': 'WILDCARD_TRUST_POLICY',
                'title': 'IAM Role with Wildcard in Trust Policy',
                'description': f"IAM role {role['role_name']} has wildcard principal in trust policy",
                'severity': 'HIGH',
                'category': 'IAM',
                'details': {
                    'role_name': role['role_name'],
                    'trust_policy': trust_policy
                }
            })
        
        # Check for admin privileges
        if self.has_admin_privileges(role):
            findings.append({
                'provider': 'aws',
                'resource_type': 'IAM_Role',
                'resource_id': role['role_name'],
                'resource_arn': role['arn'],
                'finding_type': 'ADMIN_PRIVILEGES',
                'title': 'IAM Role with Administrator Privileges',
                'description': f"IAM role {role['role_name']} has administrator privileges",
                'severity': 'HIGH',
                'category': 'IAM',
                'details': {
                    'role_name': role['role_name'],
                    'policies': role['policies']
                }
            })
            
        return findings
    
    def has_mfa(self, user: Dict[str, Any]) -> bool:
        """Check if user has MFA enabled (simplified)"""
        # In real implementation, you would call iam.list_mfa_devices
        return False  # Simplified for example
    
    def is_access_key_old(self, access_key: Dict[str, Any]) -> bool:
        """Check if access key is older than 90 days"""
        from datetime import datetime, timedelta
        create_date = access_key['create_date']
        if isinstance(create_date, str):
            # Parse string date if needed
            pass
        ninety_days_ago = datetime.now() - timedelta(days=90)
        return create_date.replace(tzinfo=None) < ninety_days_ago
    
    def has_wildcard_principal(self, trust_policy: Dict[str, Any]) -> bool:
        """Check if trust policy contains wildcard principal"""
        try:
            statements = trust_policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
                
            for statement in statements:
                principal = statement.get('Principal', {})
                if isinstance(principal, dict):
                    for service in principal.values():
                        if service == '*' or (isinstance(service, str) and '*' in service):
                            return True
                elif principal == '*':
                    return True
                    
        except Exception as e:
            self.logger.error(f"Error parsing trust policy: {str(e)}")
            
        return False
    
    def has_admin_privileges(self, role: Dict[str, Any]) -> bool:
        """Check if role has admin privileges"""
        admin_policy_arns = [
            'arn:aws:iam::aws:policy/AdministratorAccess',
            'arn:aws:iam::aws:policy/IAMFullAccess'
        ]
        
        # Check attached policies
        for attached_policy in role['policies']['attached_policies']:
            if attached_policy['policy_arn'] in admin_policy_arns:
                return True
                
        # Check for admin in policy names (simplified)
        for inline_policy in role['policies']['inline_policies']:
            if 'admin' in inline_policy.lower() or 'full' in inline_policy.lower():
                return True
                
        return False
    
    def scan_azure_iam(self) -> List[Dict[str, Any]]:
        """Scan Azure IAM (placeholder implementation)"""
        # Azure IAM scanning logic would go here
        return []
    
    def scan_gcp_iam(self) -> List[Dict[str, Any]]:
        """Scan GCP IAM (placeholder implementation)"""
        # GCP IAM scanning logic would go here
        return []
