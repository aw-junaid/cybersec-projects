import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class RulesEngine:
    """Security rules engine for detecting threats"""
    
    def __init__(self, storage_handler):
        self.storage_handler = storage_handler
        self.rules = storage_handler.settings.SECURITY_RULES
    
    def evaluate_rules(self, event):
        """Evaluate all rules against an event"""
        alerts = []
        
        for rule in self.rules:
            try:
                if self._evaluate_rule(rule, event):
                    alert = self._create_alert_from_rule(rule, event)
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule['id']}: {e}")
        
        return alerts
    
    def _evaluate_rule(self, rule, event):
        """Evaluate a single rule against an event"""
        rule_type = rule.get("type", "single_event")
        
        if rule_type == "single_event":
            return self._evaluate_single_event_rule(rule, event)
        elif rule_type == "aggregation":
            return self._evaluate_aggregation_rule(rule, event)
        
        return False
    
    def _evaluate_single_event_rule(self, rule, event):
        """Evaluate single event rule"""
        condition = rule.get("condition", "")
        
        # Simple condition evaluation (in production, use a proper expression evaluator)
        try:
            if "failed_login" in condition and event.get("event_type") == "auth_failed":
                return True
            elif "port_scan" in condition and event.get("tags", {}).get("destination_port"):
                return True
            elif "data_exfiltration" in condition:
                size = event.get("tags", {}).get("response_size", 0)
                return size > 100000000  # 100MB
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
        
        return False
    
    def _evaluate_aggregation_rule(self, rule, event):
        """Evaluate aggregation rule (stub for complex rules)"""
        # This would involve querying the database for events matching patterns
        # over time windows
        return False
    
    def _create_alert_from_rule(self, rule, event):
        """Create alert from rule match"""
        alert_data = {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "description": rule["description"],
            "events": [event.get("id")],
            "source_ips": [event.get("source_ip")] if event.get("source_ip") else [],
            "destination_ips": [event.get("destination_ip")] if event.get("destination_ip") else [],
            "timestamp": datetime.utcnow()
        }
        
        return self.create_alert(alert_data)
    
    def create_alert(self, alert_data):
        """Create a new alert"""
        try:
            alert_id = self.storage_handler.create_alert(alert_data)
            logger.warning(f"Security alert created: {alert_data['rule_name']}")
            
            # Here you would add notification logic (email, Slack, etc.)
            self._notify_alert(alert_data)
            
            return alert_id
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    def _notify_alert(self, alert_data):
        """Notify about security alert (stub implementation)"""
        # Implement notifications via:
        # - Email
        # - Slack webhook
        # - PagerDuty
        # - SMS
        
        print(f"SECURITY ALERT: {alert_data['severity'].upper()} - {alert_data['rule_name']}")
        print(f"Description: {alert_data['description']}")
        print(f"Source IPs: {alert_data.get('source_ips', [])}")
        
        # Example Slack notification
        # if self.slack_webhook:
        #     self._send_slack_alert(alert_data)
    
    def get_active_alerts(self, hours=24):
        """Get active alerts from last N hours"""
        try:
            return self.storage_handler.get_recent_alerts(hours)
        except Exception as e:
            logger.error(f"Error getting active alerts: {e}")
            return []
