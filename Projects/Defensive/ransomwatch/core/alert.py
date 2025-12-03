"""
Alert Management System
Handle logging, notifications, and alert aggregation
"""

import json
import logging
import smtplib
import requests
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from collections import defaultdict

class AlertManager:
    def __init__(self, webhook_url=None, log_file='alerts.json'):
        self.webhook_url = webhook_url
        self.log_file = log_file
        self.logger = logging.getLogger("AlertManager")
        self.alert_counts = defaultdict(int)
        self.setup_alert_logging()
    
    def setup_alert_logging(self):
        """Setup JSON alert logging"""
        self.alert_handler = logging.FileHandler(self.log_file)
        self.alert_handler.setFormatter(logging.Formatter('%(message)s'))
        
        self.alert_logger = logging.getLogger("Alerts")
        self.alert_logger.setLevel(logging.INFO)
        self.alert_logger.addHandler(self.alert_handler)
        self.alert_logger.propagate = False
    
    def alert(self, severity, message, details=None):
        """Generate an alert"""
        alert_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'severity': severity,
            'message': message,
            'details': details or {},
            'alert_id': self._generate_alert_id(severity, message)
        }
        
        # Log to JSON file
        self.alert_logger.info(json.dumps(alert_data))
        
        # Console logging
        self.logger.warning(f"[{severity}] {message}")
        
        # Update alert counts
        self.alert_counts[severity] += 1
        
        # Send notifications
        self._send_notifications(alert_data)
        
        # Check for prevention actions
        if severity in ['CRITICAL', 'HIGH']:
            self._evaluate_prevention_actions(alert_data)
    
    def _generate_alert_id(self, severity, message):
        """Generate unique alert ID"""
        import hashlib
        content = f"{severity}:{message}:{datetime.utcnow().timestamp()}"
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    def _send_notifications(self, alert_data):
        """Send notifications via various channels"""
        # Slack webhook
        if self.webhook_url and 'slack' in self.webhook_url:
            self._send_slack_alert(alert_data)
        
        # Email for critical alerts
        if alert_data['severity'] in ['CRITICAL', 'HIGH']:
            self._send_email_alert(alert_data)
    
    def _send_slack_alert(self, alert_data):
        """Send alert to Slack"""
        try:
            slack_message = {
                'text': f"🚨 RansomWatch Alert",
                'blocks': [
                    {
                        'type': 'header',
                        'text': {
                            'type': 'plain_text',
                            'text': f'🚨 RansomWatch {alert_data["severity"]} Alert'
                        }
                    },
                    {
                        'type': 'section',
                        'fields': [
                            {
                                'type': 'mrkdwn',
                                'text': f'*Message:* {alert_data["message"]}'
                            },
                            {
                                'type': 'mrkdwn',
                                'text': f'*Time:* {alert_data["timestamp"]}'
                            }
                        ]
                    }
                ]
            }
            
            if alert_data['details']:
                details_text = '\n'.join([f'{k}: {v}' for k, v in alert_data['details'].items()])
                slack_message['blocks'].append({
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f'*Details:*\n```{details_text}```'
                    }
                })
            
            Thread(target=self._send_slack_async, args=(slack_message,)).start()
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
    
    def _send_slack_async(self, message):
        """Send Slack message asynchronously"""
        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10
            )
            if response.status_code != 200:
                self.logger.error(f"Slack webhook error: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Slack request failed: {e}")
    
    def _send_email_alert(self, alert_data):
        """Send email alert for critical events"""
        # This would be implemented based on SMTP configuration
        pass
    
    def _evaluate_prevention_actions(self, alert_data):
        """Evaluate if prevention actions should be taken"""
        if os.environ.get('SAFE_MODE') != 'true':
            return
        
        details = alert_data.get('details', {})
        
        # Kill process for critical process-based alerts
        if alert_data['severity'] == 'CRITICAL' and 'pid' in details:
            pid = details['pid']
            self.logger.info(f"Safe mode: Attempting to kill process {pid}")
            
            # Import here to avoid circular imports
            from core.process_watch import ProcessWatcher
            watcher = ProcessWatcher(None, None)
            watcher.kill_suspicious_process(pid)
        
        # Quarantine suspicious files
        if 'file_path' in details and os.path.exists(details['file_path']):
            self._quarantine_file(details['file_path'])
    
    def _quarantine_file(self, file_path):
        """Move suspicious file to quarantine"""
        try:
            quarantine_dir = '/tmp/ransomwatch_quarantine'
            os.makedirs(quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"{int(time.time())}_{filename}")
            
            os.rename(file_path, quarantine_path)
            self.logger.info(f"Quarantined file: {file_path} -> {quarantine_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}")
    
    def get_alert_summary(self):
        """Get alert statistics"""
        return dict(self.alert_counts)
