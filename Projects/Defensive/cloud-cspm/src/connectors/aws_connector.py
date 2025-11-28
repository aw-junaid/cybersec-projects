"""
AWS Cloud Connector
Handles authentication and API calls to AWS
"""

import boto3
import json
import logging
from typing import Dict, List, Any
from botocore.exceptions import ClientError, BotoCoreError


class AWSConnector:
    """AWS Cloud Provider Connector"""
    
    def __init__(self, profile_name: str = None, region: str = 'us-east-1'):
        self.profile_name = profile_name
        self.region = region
        self.session = None
        self.clients = {}
        self.logger = logging.getLogger(__name__)
        self.initialize_session()
        
    def initialize_session(self):
        """Initialize AWS session and clients"""
        try:
            session_args = {}
            if self.profile_name:
                session_args['profile_name'] = self.profile_name
                
            self.session = boto3.Session(**session_args)
            
            # Initialize clients for various services
            self.clients = {
                'iam': self.session.client('iam'),
                's3': self.session.client('s3'),
                'ec2': self.session.client('ec2', region_name=self.region),
                'rds': self.session.client('rds', region_name=self.region),
                'cloudtrail': self.session.client('cloudtrail', region_name=self.region),
                'config': self.session.client('config', region_name=self.region),
                'securityhub': self.session.client('securityhub', region_name=self.region)
            }
            
            # Test connection
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.logger.info(f"AWS connected successfully. Account: {identity['Account']}, User: {identity['Arn']}")
            
        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"AWS connection failed: {str(e)}")
            raise
            
    def get_client(self, service: str):
        """Get AWS service client"""
        if service not in self.clients:
            self.clients[service] = self.session.client(service, region_name=self.region)
        return self.clients[service]
    
    def list_s3_buckets(self) -> List[Dict[str, Any]]:
        """List all S3 buckets with their properties"""
        try:
            s3 = self.get_client('s3')
            response = s3.list_buckets()
            
            buckets = []
            for bucket in response['Buckets']:
                bucket_info = {
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'],
                    'region': self.get_bucket_region(bucket['Name'])
                }
                
                # Get bucket policies and ACLs
                try:
                    bucket_info['policy'] = self.get_bucket_policy(bucket['Name'])
                except ClientError:
                    bucket_info['policy'] = None
                    
                try:
                    bucket_info['acl'] = s3.get_bucket_acl(Bucket=bucket['Name'])
                except ClientError:
                    bucket_info['acl'] = None
                    
                buckets.append(bucket_info)
                
            return buckets
            
        except ClientError as e:
            self.logger.error(f"Failed to list S3 buckets: {str(e)}")
            return []
    
    def get_bucket_region(self, bucket_name: str) -> str:
        """Get S3 bucket region"""
        try:
            s3 = self.get_client('s3')
            response = s3.get_bucket_location(Bucket=bucket_name)
            return response.get('LocationConstraint', 'us-east-1')
        except ClientError:
            return 'us-east-1'
    
    def get_bucket_policy(self, bucket_name: str) -> Dict[str, Any]:
        """Get S3 bucket policy"""
        try:
            s3 = self.get_client('s3')
            response = s3.get_bucket_policy(Bucket=bucket_name)
            return json.loads(response['Policy'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return {}
            raise
    
    def list_iam_users(self) -> List[Dict[str, Any]]:
        """List all IAM users with their policies"""
        try:
            iam = self.get_client('iam')
            users = []
            
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_info = {
                        'user_name': user['UserName'],
                        'user_id': user['UserId'],
                        'arn': user['Arn'],
                        'create_date': user['CreateDate'],
                        'policies': self.get_user_policies(user['UserName']),
                        'access_keys': self.get_user_access_keys(user['UserName'])
                    }
                    users.append(user_info)
                    
            return users
            
        except ClientError as e:
            self.logger.error(f"Failed to list IAM users: {str(e)}")
            return []
    
    def get_user_policies(self, user_name: str) -> Dict[str, Any]:
        """Get IAM user policies"""
        try:
            iam = self.get_client('iam')
            policies = {
                'inline_policies': [],
                'attached_policies': []
            }
            
            # Get inline policies
            inline_paginator = iam.get_paginator('list_user_policies')
            for page in inline_paginator.paginate(UserName=user_name):
                policies['inline_policies'].extend(page['PolicyNames'])
            
            # Get attached policies
            attached_paginator = iam.get_paginator('list_attached_user_policies')
            for page in attached_paginator.paginate(UserName=user_name):
                for policy in page['AttachedPolicies']:
                    policies['attached_policies'].append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn']
                    })
                    
            return policies
            
        except ClientError as e:
            self.logger.error(f"Failed to get policies for user {user_name}: {str(e)}")
            return {'inline_policies': [], 'attached_policies': []}
    
    def get_user_access_keys(self, user_name: str) -> List[Dict[str, Any]]:
        """Get IAM user access keys"""
        try:
            iam = self.get_client('iam')
            access_keys = []
            
            response = iam.list_access_keys(UserName=user_name)
            for key in response['AccessKeyMetadata']:
                access_keys.append({
                    'access_key_id': key['AccessKeyId'],
                    'status': key['Status'],
                    'create_date': key['CreateDate']
                })
                
            return access_keys
            
        except ClientError as e:
            self.logger.error(f"Failed to get access keys for user {user_name}: {str(e)}")
            return []
    
    def list_security_groups(self) -> List[Dict[str, Any]]:
        """List all security groups with rules"""
        try:
            ec2 = self.get_client('ec2')
            security_groups = []
            
            response = ec2.describe_security_groups()
            for sg in response['SecurityGroups']:
                sg_info = {
                    'group_id': sg['GroupId'],
                    'group_name': sg['GroupName'],
                    'description': sg.get('Description', ''),
                    'vpc_id': sg['VpcId'],
                    'ip_permissions': sg['IpPermissions'],
                    'ip_permissions_egress': sg['IpPermissionsEgress'],
                    'tags': sg.get('Tags', [])
                }
                security_groups.append(sg_info)
                
            return security_groups
            
        except ClientError as e:
            self.logger.error(f"Failed to list security groups: {str(e)}")
            return []
    
    def list_iam_roles(self) -> List[Dict[str, Any]]:
        """List all IAM roles with their trust policies"""
        try:
            iam = self.get_client('iam')
            roles = []
            
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_info = {
                        'role_name': role['RoleName'],
                        'role_id': role['RoleId'],
                        'arn': role['Arn'],
                        'create_date': role['CreateDate'],
                        'assume_role_policy_document': role.get('AssumeRolePolicyDocument', {}),
                        'description': role.get('Description', ''),
                        'policies': self.get_role_policies(role['RoleName'])
                    }
                    roles.append(role_info)
                    
            return roles
            
        except ClientError as e:
            self.logger.error(f"Failed to list IAM roles: {str(e)}")
            return []
    
    def get_role_policies(self, role_name: str) -> Dict[str, Any]:
        """Get IAM role policies"""
        try:
            iam = self.get_client('iam')
            policies = {
                'inline_policies': [],
                'attached_policies': []
            }
            
            # Get inline policies
            inline_paginator = iam.get_paginator('list_role_policies')
            for page in inline_paginator.paginate(RoleName=role_name):
                policies['inline_policies'].extend(page['PolicyNames'])
            
            # Get attached policies
            attached_paginator = iam.get_paginator('list_attached_role_policies')
            for page in attached_paginator.paginate(RoleName=role_name):
                for policy in page['AttachedPolicies']:
                    policies['attached_policies'].append({
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn']
                    })
                    
            return policies
            
        except ClientError as e:
            self.logger.error(f"Failed to get policies for role {role_name}: {str(e)}")
            return {'inline_policies': [], 'attached_policies': []}
