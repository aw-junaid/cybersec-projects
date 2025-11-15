#!/usr/bin/env python3
"""
Social Engineering Toolkit - Educational Tool
Purpose: Simulate social engineering attacks for security awareness training
Use: Security training, phishing simulation, employee awareness testing
"""

import smtplib
import json
import random
import threading
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from datetime import datetime, timedelta
from pathlib import Path
import argparse
import logging
from typing import Dict, List, Optional
import sqlite3
import hashlib
import time
import re
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackType(Enum):
    PHISHING_EMAIL = "phishing_email"
    SMISHING_SMS = "smishing_sms"
    VOICE_PHISHING = "voice_phishing"
    QUID_PRO_QUO = "quid_pro_quo"
    BAITING = "baiting"

@dataclass
class CampaignResult:
    campaign_id: str
    target_count: int
    responses: int
    clicks: int
    credentials_submitted: int
    start_time: datetime
    end_time: datetime

class SocialEngineeringToolkit:
    def __init__(self, config_file="se_config.json"):
        self.config = self.load_config(config_file)
        self.templates = self.load_templates()
        self.campaigns = {}
        self.setup_database()
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "smtp": {
                "server": "smtp.gmail.com",
                "port": 587,
                "username": "",
                "password": "",
                "use_tls": True
            },
            "sms": {
                "provider": "twilio",
                "account_sid": "",
                "auth_token": "",
                "from_number": ""
            },
            "tracking": {
                "track_clicks": True,
                "track_opens": True,
                "track_responses": True
            },
            "security": {
                "require_authorization": True,
                "max_emails_per_hour": 100,
                "allowed_domains": ["example.com"]
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
    
    def load_templates(self) -> Dict:
        """Load social engineering templates"""
        templates = {
            "phishing_email": {
                "urgent_password_reset": {
                    "name": "Urgent Password Reset",
                    "subject": "Urgent: Your Password Reset Required",
                    "body": """
Dear {name},

Our security system has detected unusual activity on your account. 
To protect your information, we need you to reset your password immediately.

Click here to reset your password: {tracking_url}

If you don't reset your password within 24 hours, your account will be temporarily suspended.

Best regards,
IT Security Team
{company_name}
                    """,
                    "variables": ["name", "tracking_url", "company_name"],
                    "difficulty": "beginner"
                },
                "package_delivery": {
                    "name": "Package Delivery Notification",
                    "subject": "Package Delivery Failed - Action Required",
                    "body": """
Hello {name},

We attempted to deliver your package today but were unable to complete the delivery.

Tracking Number: {tracking_number}
Delivery Address: {address}

Please confirm your delivery details here: {tracking_url}

You must confirm within 2 hours or the package will be returned to sender.

Thank you,
Delivery Services
                    """,
                    "variables": ["name", "tracking_number", "address", "tracking_url"],
                    "difficulty": "intermediate"
                },
                "ceo_fraud": {
                    "name": "CEO Fraud / Business Email Compromise",
                    "subject": "URGENT: Payment Request",
                    "body": """
Hello {name},

I need you to process an urgent payment for me. I'm in meetings all day and can't handle this personally.

Please transfer ${amount} to the following account:

Bank: {bank_name}
Account: {account_number}
Routing: {routing_number}

This is time-sensitive for an important business acquisition. Please complete this today and email me confirmation.

Thanks,
{ceo_name}
CEO
                    """,
                    "variables": ["name", "amount", "bank_name", "account_number", "routing_number", "ceo_name"],
                    "difficulty": "advanced"
                }
            },
            "smishing_sms": {
                "bank_alert": {
                    "name": "Bank Fraud Alert",
                    "body": """
{bank_name} Alert: Suspicious activity detected on your account. 
Reply YES to confirm recent transactions or call {phone_number}.
Msg&Data rates may apply.
                    """,
                    "variables": ["bank_name", "phone_number"],
                    "difficulty": "beginner"
                },
                "package_sms": {
                    "name": "Package Delivery SMS",
                    "body": """
UPS: Your package delivery failed. Confirm address: {tracking_url}
Expected delivery: {delivery_date}
                    """,
                    "variables": ["tracking_url", "delivery_date"],
                    "difficulty": "intermediate"
                }
            }
        }
        return templates
    
    def setup_database(self):
        """Setup SQLite database for tracking campaigns"""
        self.db_path = Path('se_campaigns.db')
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT UNIQUE,
                name TEXT,
                attack_type TEXT,
                target_count INTEGER,
                start_time DATETIME,
                end_time DATETIME,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT,
                email TEXT,
                phone TEXT,
                name TEXT,
                department TEXT,
                sent_time DATETIME,
                opened BOOLEAN DEFAULT 0,
                clicked BOOLEAN DEFAULT 0,
                responded BOOLEAN DEFAULT 0,
                credentials_submitted BOOLEAN DEFAULT 0,
                FOREIGN KEY (campaign_id) REFERENCES campaigns (campaign_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT,
                target_id INTEGER,
                event_type TEXT,
                event_time DATETIME,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns (campaign_id),
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database setup completed")
    
    def create_campaign(self, name: str, attack_type: AttackType, template_name: str, 
                       targets: List[Dict], **template_vars) -> str:
        """Create a new social engineering campaign"""
        campaign_id = hashlib.md5(f"{name}{datetime.now()}".encode()).hexdigest()[:8]
        
        # Validate template
        if attack_type.value not in self.templates:
            raise ValueError(f"Unsupported attack type: {attack_type}")
        
        if template_name not in self.templates[attack_type.value]:
            raise ValueError(f"Template not found: {template_name}")
        
        template = self.templates[attack_type.value][template_name]
        
        # Store campaign in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO campaigns (campaign_id, name, attack_type, target_count, start_time, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (campaign_id, name, attack_type.value, len(targets), datetime.now(), 'created'))
        
        # Add targets
        for target in targets:
            cursor.execute('''
                INSERT INTO targets (campaign_id, email, phone, name, department)
                VALUES (?, ?, ?, ?, ?)
            ''', (campaign_id, target.get('email'), target.get('phone'), 
                  target.get('name'), target.get('department')))
        
        conn.commit()
        conn.close()
        
        self.campaigns[campaign_id] = {
            'name': name,
            'attack_type': attack_type,
            'template': template,
            'template_vars': template_vars,
            'targets': targets,
            'start_time': datetime.now(),
            'status': 'created'
        }
        
        logger.info(f"Created campaign {campaign_id} with {len(targets)} targets")
        return campaign_id
    
    def send_phishing_email(self, campaign_id: str, target: Dict, tracking_url: str = None):
        """Send a phishing email to a target"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id}")
        
        template = campaign['template']
        template_vars = campaign['template_vars'].copy()
        
        # Add target-specific variables
        template_vars.update({
            'name': target.get('name', 'Valued Customer'),
            'email': target.get('email'),
            'tracking_url': tracking_url or "https://example.com/secure-login"
        })
        
        # Render template
        subject = self.render_template(template['subject'], template_vars)
        body = self.render_template(template['body'], template_vars)
        
        # Create email
        msg = MimeMultipart()
        msg['From'] = self.config['smtp']['username']
        msg['To'] = target['email']
        msg['Subject'] = subject
        
        # Add tracking pixel if enabled
        if self.config['tracking']['track_opens']:
            tracking_pixel = f'<img src="http://tracker.example.com/open/{campaign_id}/{target["email"]}" width="1" height="1">'
            body = body.replace('</body>', f'{tracking_pixel}</body>')
        
        msg.attach(MimeText(body, 'html' if '<html>' in body else 'plain'))
        
        try:
            # Send email
            if self.config['smtp']['server']:
                self.send_email_via_smtp(msg)
            else:
                logger.info(f"SIMULATION: Would send email to {target['email']}")
                logger.info(f"Subject: {subject}")
                logger.info(f"Body preview: {body[:200]}...")
            
            # Update database
            self.mark_email_sent(campaign_id, target['email'])
            
        except Exception as e:
            logger.error(f"Failed to send email to {target['email']}: {e}")
    
    def send_smishing_sms(self, campaign_id: str, target: Dict, tracking_url: str = None):
        """Send a smishing SMS to a target"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id}")
        
        template = campaign['template']
        template_vars = campaign['template_vars'].copy()
        
        # Add target-specific variables
        template_vars.update({
            'name': target.get('name', 'Customer'),
            'tracking_url': tracking_url or "https://example.com/verify"
        })
        
        # Render template
        body = self.render_template(template['body'], template_vars)
        
        try:
            # Send SMS
            if self.config['sms']['provider'] == 'twilio' and self.config['sms']['account_sid']:
                self.send_sms_via_twilio(target['phone'], body)
            else:
                logger.info(f"SIMULATION: Would send SMS to {target['phone']}")
                logger.info(f"Message: {body}")
            
            # Update database
            self.mark_sms_sent(campaign_id, target['phone'])
            
        except Exception as e:
            logger.error(f"Failed to send SMS to {target['phone']}: {e}")
    
    def render_template(self, template: str, variables: Dict) -> str:
        """Render template with variables"""
        for key, value in variables.items():
            placeholder = '{' + key + '}'
            template = template.replace(placeholder, str(value))
        return template
    
    def send_email_via_smtp(self, msg):
        """Send email via SMTP server"""
        try:
            server = smtplib.SMTP(self.config['smtp']['server'], self.config['smtp']['port'])
            
            if self.config['smtp']['use_tls']:
                server.starttls()
            
            if self.config['smtp']['username']:
                server.login(self.config['smtp']['username'], self.config['smtp']['password'])
            
            server.send_message(msg)
            server.quit()
            logger.info("Email sent successfully via SMTP")
            
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            raise
    
    def send_sms_via_twilio(self, to_number: str, body: str):
        """Send SMS via Twilio"""
        try:
            from twilio.rest import Client
            
            client = Client(self.config['sms']['account_sid'], self.config['sms']['auth_token'])
            
            message = client.messages.create(
                body=body,
                from_=self.config['sms']['from_number'],
                to=to_number
            )
            
            logger.info(f"SMS sent via Twilio: {message.sid}")
            
        except ImportError:
            logger.warning("Twilio library not installed. Install with: pip install twilio")
            raise
        except Exception as e:
            logger.error(f"Twilio error: {e}")
            raise
    
    def mark_email_sent(self, campaign_id: str, email: str):
        """Mark email as sent in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE targets 
            SET sent_time = ?
            WHERE campaign_id = ? AND email = ?
        ''', (datetime.now(), campaign_id, email))
        
        conn.commit()
        conn.close()
    
    def mark_sms_sent(self, campaign_id: str, phone: str):
        """Mark SMS as sent in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE targets 
            SET sent_time = ?
            WHERE campaign_id = ? AND phone = ?
        ''', (datetime.now(), campaign_id, phone))
        
        conn.commit()
        conn.close()
    
    def execute_campaign(self, campaign_id: str, delay: int = 0):
        """Execute a social engineering campaign"""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id}")
        
        logger.info(f"Executing campaign: {campaign['name']}")
        
        # Update campaign status
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE campaigns SET status = 'running' WHERE campaign_id = ?
        ''', (campaign_id,))
        conn.commit()
        conn.close()
        
        # Execute based on attack type
        if campaign['attack_type'] == AttackType.PHISHING_EMAIL:
            self.execute_email_campaign(campaign_id, delay)
        elif campaign['attack_type'] == AttackType.SMISHING_SMS:
            self.execute_sms_campaign(campaign_id, delay)
        
        # Mark campaign as completed
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE campaigns SET status = 'completed', end_time = ? WHERE campaign_id = ?
        ''', (datetime.now(), campaign_id))
        conn.commit()
        conn.close()
        
        logger.info(f"Campaign {campaign_id} completed")
    
    def execute_email_campaign(self, campaign_id: str, delay: int):
        """Execute email campaign with threading"""
        campaign = self.campaigns[campaign_id]
        
        def send_to_target(target):
            time.sleep(delay * random.uniform(0.5, 1.5))  # Random delay
            tracking_url = f"https://track.example.com/{campaign_id}/{hashlib.md5(target['email'].encode()).hexdigest()[:8]}"
            self.send_phishing_email(campaign_id, target, tracking_url)
        
        threads = []
        for target in campaign['targets']:
            if target.get('email'):
                thread = threading.Thread(target=send_to_target, args=(target,))
                thread.start()
                threads.append(thread)
        
        for thread in threads:
            thread.join()
    
    def execute_sms_campaign(self, campaign_id: str, delay: int):
        """Execute SMS campaign with threading"""
        campaign = self.campaigns[campaign_id]
        
        def send_to_target(target):
            time.sleep(delay * random.uniform(0.5, 1.5))  # Random delay
            tracking_url = f"https://track.example.com/sms/{campaign_id}/{hashlib.md5(target['phone'].encode()).hexdigest()[:8]}"
            self.send_smishing_sms(campaign_id, target, tracking_url)
        
        threads = []
        for target in campaign['targets']:
            if target.get('phone'):
                thread = threading.Thread(target=send_to_target, args=(target,))
                thread.start()
                threads.append(thread)
        
        for thread in threads:
            thread.join()
    
    def generate_report(self, campaign_id: str) -> Dict:
        """Generate campaign report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get campaign details
        cursor.execute('''
            SELECT name, attack_type, target_count, start_time, end_time, status
            FROM campaigns WHERE campaign_id = ?
        ''', (campaign_id,))
        
        campaign_row = cursor.fetchone()
        if not campaign_row:
            raise ValueError(f"Campaign not found: {campaign_id}")
        
        name, attack_type, target_count, start_time, end_time, status = campaign_row
        
        # Get target statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(opened) as opened,
                SUM(clicked) as clicked,
                SUM(responded) as responded,
                SUM(credentials_submitted) as credentials_submitted
            FROM targets 
            WHERE campaign_id = ?
        ''', (campaign_id,))
        
        stats_row = cursor.fetchone()
        total, opened, clicked, responded, credentials = stats_row
        
        # Calculate percentages
        opened_pct = (opened / total * 100) if total > 0 else 0
        clicked_pct = (clicked / total * 100) if total > 0 else 0
        responded_pct = (responded / total * 100) if total > 0 else 0
        credentials_pct = (credentials / total * 100) if total > 0 else 0
        
        # Risk assessment
        risk_score = min(100, (opened_pct * 0.2 + clicked_pct * 0.3 + responded_pct * 0.5) * 2)
        
        risk_level = "Low"
        if risk_score >= 70:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 30:
            risk_level = "Medium"
        
        report = {
            'campaign_id': campaign_id,
            'name': name,
            'attack_type': attack_type,
            'status': status,
            'timeline': {
                'start_time': start_time,
                'end_time': end_time,
                'duration': str((end_time or datetime.now()) - start_time) if start_time else None
            },
            'statistics': {
                'targets_sent': total,
                'emails_opened': opened,
                'emails_opened_percentage': round(opened_pct, 2),
                'links_clicked': clicked,
                'links_clicked_percentage': round(clicked_pct, 2),
                'responses_received': responded,
                'responses_percentage': round(responded_pct, 2),
                'credentials_submitted': credentials,
                'credentials_percentage': round(credentials_pct, 2)
            },
            'risk_assessment': {
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'vulnerability_level': risk_level
            },
            'recommendations': self.generate_recommendations(risk_score, attack_type)
        }
        
        conn.close()
        return report
    
    def generate_recommendations(self, risk_score: float, attack_type: str) -> List[str]:
        """Generate security recommendations based on results"""
        recommendations = []
        
        if risk_score >= 70:
            recommendations.extend([
                "Immediate security awareness training required",
                "Implement multi-factor authentication",
                "Conduct phishing simulation exercises monthly",
                "Review and update email security policies"
            ])
        elif risk_score >= 50:
            recommendations.extend([
                "Schedule security awareness training within 30 days",
                "Consider implementing email filtering solutions",
                "Conduct quarterly phishing simulations",
                "Review incident response procedures"
            ])
        else:
            recommendations.extend([
                "Continue regular security awareness training",
                "Maintain current security controls",
                "Conduct annual phishing simulations"
            ])
        
        if attack_type == "phishing_email":
            recommendations.extend([
                "Train employees to identify suspicious emails",
                "Implement email authentication (SPF, DKIM, DMARC)",
                "Use advanced threat protection for email"
            ])
        elif attack_type == "smishing_sms":
            recommendations.extend([
                "Educate employees about SMS-based attacks",
                "Implement mobile device management",
                "Establish procedures for verifying suspicious messages"
            ])
        
        return recommendations
    
    def list_templates(self, attack_type: AttackType = None) -> Dict:
        """List available templates"""
        if attack_type:
            return self.templates.get(attack_type.value, {})
        return self.templates
    
    def create_target_list(self, departments: List[str], count_per_dept: int = 5) -> List[Dict]:
        """Generate sample target list for testing"""
        first_names = ["John", "Jane", "Robert", "Lisa", "Michael", "Sarah", "David", "Emily"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
        domains = ["company.com", "example.org", "test-inc.net"]
        
        targets = []
        for dept in departments:
            for i in range(count_per_dept):
                first = random.choice(first_names)
                last = random.choice(last_names)
                domain = random.choice(domains)
                
                target = {
                    'name': f"{first} {last}",
                    'email': f"{first.lower()}.{last.lower()}@{domain}",
                    'phone': f"+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}",
                    'department': dept
                }
                targets.append(target)
        
        return targets

class EducationalContent:
    """Educational content about social engineering"""
    
    @staticmethod
    def get_red_flags(attack_type: AttackType) -> List[str]:
        """Get red flags for different social engineering attacks"""
        red_flags = {
            AttackType.PHISHING_EMAIL: [
                "Urgent language and deadlines",
                "Requests for sensitive information",
                "Suspicious sender addresses",
                "Generic greetings ('Dear Customer')",
                "Poor grammar and spelling",
                "Mismatched URLs",
                "Unexpected attachments"
            ],
            AttackType.SMISHING_SMS: [
                "Unsolicited messages",
                "Requests to click links",
                "Urgent action required",
                "Unknown sender numbers",
                "Requests for personal information"
            ],
            AttackType.CEO_FRAUD: [
                "Requests from executives you don't normally communicate with",
                "Urgent financial transactions",
                "Requests to bypass normal procedures",
                "Pressure to act quickly",
                "Unusual payment methods or accounts"
            ]
        }
        return red_flags.get(attack_type, [])
    
    @staticmethod
    def get_prevention_tips() -> Dict[str, List[str]]:
        """Get prevention tips for social engineering"""
        return {
            "email_security": [
                "Verify sender email addresses carefully",
                "Hover over links before clicking",
                "Don't open unexpected attachments",
                "Use multi-factor authentication",
                "Report suspicious emails to IT"
            ],
            "sms_security": [
                "Don't respond to unknown numbers",
                "Verify SMS messages through other channels",
                "Don't click links in suspicious texts",
                "Use official company apps for communications"
            ],
            "general": [
                "Verify unusual requests through secondary channels",
                "Follow company security procedures",
                "Participate in security awareness training",
                "Keep software and systems updated",
                "Use strong, unique passwords"
            ]
        }

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Social Engineering Toolkit - Educational Tool')
    parser.add_argument('--create-campaign', action='store_true', help='Create a new campaign')
    parser.add_argument('--list-templates', action='store_true', help='List available templates')
    parser.add_argument('--execute-campaign', help='Execute campaign by ID')
    parser.add_argument('--generate-report', help='Generate report for campaign')
    parser.add_argument('--attack-type', choices=['phishing_email', 'smishing_sms'], 
                       help='Type of attack for campaign')
    parser.add_argument('--template', help='Template name to use')
    parser.add_argument('--config', default='se_config.json', help='Configuration file')
    
    args = parser.parse_args()
    
    toolkit = SocialEngineeringToolkit(args.config)
    
    if args.list_templates:
        templates = toolkit.list_templates()
        print("Available Templates:")
        for attack_type, type_templates in templates.items():
            print(f"\n{attack_type.upper()}:")
            for name, template in type_templates.items():
                print(f"  {name}: {template['name']} ({template['difficulty']})")
    
    elif args.create_campaign and args.attack_type and args.template:
        # Create sample campaign
        departments = ['IT', 'HR', 'Finance', 'Marketing']
        targets = toolkit.create_target_list(departments, 3)
        
        template_vars = {
            'company_name': 'Example Corporation',
            'ceo_name': 'John Smith',
            'amount': '15,000',
            'bank_name': 'Global Bank',
            'account_number': 'XXXX-XXXX-XXXX-1234',
            'routing_number': '021000021'
        }
        
        campaign_id = toolkit.create_campaign(
            name=f"Test Campaign - {args.template}",
            attack_type=AttackType(args.attack_type),
            template_name=args.template,
            targets=targets,
            **template_vars
        )
        
        print(f"Created campaign: {campaign_id}")
        print(f"Targets: {len(targets)}")
    
    elif args.execute_campaign:
        toolkit.execute_campaign(args.execute_campaign, delay=1)
        print(f"Executed campaign: {args.execute_campaign}")
    
    elif args.generate_report:
        report = toolkit.generate_report(args.generate_report)
        print("Campaign Report:")
        print(json.dumps(report, indent=2, default=str))
    
    else:
        print("Social Engineering Toolkit - Educational Purpose Only")
        print("Use --help for available commands")

if __name__ == "__main__":
    main()
