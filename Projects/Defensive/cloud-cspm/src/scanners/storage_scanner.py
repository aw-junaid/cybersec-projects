"""
Storage Security Scanner
Detects misconfigured storage resources
"""

import json
import logging
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class StorageScanner(BaseScanner):
    """Storage Security Misconfiguration Scanner"""
    
    def __init__(self, connectors: Dict[str, Any]):
        super().__init__(connectors)
        self.scanner_name = "Storage Security Scanner"
        self.logger = logging.getLogger(__name__)
        
    def scan(self) -> List[Dict[str, Any]]:
        """Perform storage security scan"""
        findings = []
        
        # AWS S3 scanning
        if 'aws' in self.connectors:
            findings.extend(self.scan_aws_s3())
            
        # Azure Storage scanning
        if 'azure' in self.connectors:
            findings.extend(self.scan_azure_storage())
            
        # GCP Cloud Storage scanning
        if 'gcp' in self.connectors:
            findings.extend(self.scan_gcp_storage())
            
        return findings
    
    def scan_aws_s3(self) -> List[Dict[str, Any]]:
        """Scan AWS S3 buckets for misconfigurations"""
        findings = []
        aws_connector = self.connectors['aws']
        
        try:
            buckets = aws_connector.list_s3_buckets()
            for bucket in buckets:
                findings.extend(self.analyze_s3_bucket(bucket))
                
        except Exception as e:
            self.logger.error(f"AWS S3 scan failed: {str(e)}")
            
        return findings
    
    def analyze_s3_bucket(self, bucket: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze S3 bucket for security issues"""
        findings = []
        
        # Check for public access
        if self.is_bucket_public(bucket):
            findings.append({
                'provider': 'aws',
                'resource_type': 'S3_Bucket',
                'resource_id': bucket['name'],
                'resource_arn': f"arn:aws:s3:::{bucket['name']}",
                'finding_type': 'PUBLIC_BUCKET',
                'title': 'Public S3 Bucket',
                'description': f"S3 bucket {bucket['name']} is publicly accessible",
                'severity': 'HIGH',
                'category': 'Storage',
                'details': {
                    'bucket_name': bucket['name'],
                    'region': bucket['region'],
                    'policy': bucket.get('policy'),
                    'acl': bucket.get('acl')
                }
            })
        
        # Check for missing encryption
        if not self.has_encryption(bucket):
            findings.append({
                'provider': 'aws',
                'resource_type': 'S3_Bucket',
                'resource_id': bucket['name'],
                'resource_arn': f"arn:aws:s3:::{bucket['name']}",
                'finding_type': 'UNENCRYPTED_BUCKET',
                'title': 'Unencrypted S3 Bucket',
                'description': f"S3 bucket {bucket['name']} does not have default encryption enabled",
                'severity': 'MEDIUM',
                'category': 'Storage',
                'details': {
                    'bucket_name': bucket['name'],
                    'region': bucket['region']
                }
            })
        
        # Check for weak bucket policies
        weak_policy_findings = self.check_bucket_policy(bucket)
        findings.extend(weak_policy_findings)
            
        return findings
    
    def is_bucket_public(self, bucket: Dict[str, Any]) -> bool:
        """Check if S3 bucket is publicly accessible"""
        # Check bucket policy for public access
        policy = bucket.get('policy', {})
        if policy:
            statements = policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
                
            for statement in statements:
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Check for wildcard principal
                if principal == '*' or (isinstance(principal, dict) and any(p == '*' for p in principal.values())):
                    if effect == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        # Check for dangerous actions
                        dangerous_actions = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 's3:*']
                        if any(action in dangerous_actions for action in actions):
                            return True
        
        # Check bucket ACL for public access
        acl = bucket.get('acl', {})
        if acl:
            grants = acl.get('Grants', [])
            for grant in grants:
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        return True
                        
        return False
    
    def has_encryption(self, bucket: Dict[str, Any]) -> bool:
        """Check if bucket has default encryption enabled"""
        # In real implementation, you would call s3.get_bucket_encryption
        # For this example, we'll assume no encryption
        return False
    
    def check_bucket_policy(self, bucket: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for weak bucket policies"""
        findings = []
        policy = bucket.get('policy', {})
        
        if not policy:
            return findings
            
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
            
        for statement in statements:
            # Check for overly permissive actions
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
                
            if 's3:*' in actions:
                findings.append({
                    'provider': 'aws',
                    'resource_type': 'S3_Bucket',
                    'resource_id': bucket['name'],
                    'resource_arn': f"arn:aws:s3:::{bucket['name']}",
                    'finding_type': 'OVERLY_PERMISSIVE_BUCKET_POLICY',
                    'title': 'Overly Permissive S3 Bucket Policy',
                    'description': f"S3 bucket {bucket['name']} has policy allowing s3:* actions",
                    'severity': 'HIGH',
                    'category': 'Storage',
                    'details': {
                        'bucket_name': bucket['name'],
                        'statement': statement
                    }
                })
                
        return findings
    
    def scan_azure_storage(self) -> List[Dict[str, Any]]:
        """Scan Azure Storage (placeholder implementation)"""
        return []
    
    def scan_gcp_storage(self) -> List[Dict[str, Any]]:
        """Scan GCP Cloud Storage (placeholder implementation)"""
        return []
