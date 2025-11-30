import logging
import json
from datetime import datetime

class DlpLogger:
    """Structured logging for DLP events"""
    
    def __init__(self, name="dlp-engine"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Console handler with JSON formatting
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(name)s", "message": "%(message)s"}',
            datefmt='%Y-%m-%dT%H:%M:%SZ'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_event(self, event_type, data):
        """Log structured event"""
        event = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "event_type": event_type,
            "data": data
        }
        self.logger.info(json.dumps(event))
    
    def log_alert(self, alert_data):
        """Log DLP alert"""
        self.log_event("dlp_alert", alert_data)
