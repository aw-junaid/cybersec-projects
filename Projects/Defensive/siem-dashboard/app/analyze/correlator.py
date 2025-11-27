import threading
import time
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
import redis

logger = logging.getLogger(__name__)

class EventCorrelator:
    """Correlate events to detect security incidents"""
    
    def __init__(self, storage_handler, rules_engine):
        self.storage_handler = storage_handler
        self.rules_engine = rules_engine
        self.running = False
        self.redis_client = redis.Redis.from_url(
            storage_handler.settings.REDIS_URL,
            decode_responses=True
        )
        
        # Time windows for correlation (in seconds)
        self.time_windows = {
            "failed_logins": 300,  # 5 minutes
            "port_scans": 60,      # 1 minute
            "data_exfiltration": 600  # 10 minutes
        }
        
        # In-memory buffers for real-time correlation
        self.event_buffers = {
            "failed_logins": defaultdict(deque),
            "port_scans": defaultdict(deque),
            "http_errors": defaultdict(deque)
        }
    
    def start_correlation(self):
        """Start the correlation engine"""
        self.running = True
        self.correlation_thread = threading.Thread(target=self._correlation_loop)
        self.correlation_thread.daemon = True
        self.correlation_thread.start()
        logger.info("Event correlation engine started")
    
    def stop_correlation(self):
        """Stop the correlation engine"""
        self.running = False
        logger.info("Event correlation engine stopped")
    
    def _correlation_loop(self):
        """Main correlation loop"""
        while self.running:
            try:
                # Process real-time correlation rules
                self._correlate_failed_logins()
                self._correlate_port_scans()
                self._correlate_http_errors()
                
                # Clean old events from buffers
                self._clean_old_events()
                
                time.sleep(5)  # Run every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in correlation loop: {e}")
                time.sleep(10)
    
    def process_event(self, event):
        """Process a single event for real-time correlation"""
        try:
            # Add to appropriate buffers based on event type
            if event.get("event_type") == "auth_failed":
                source_ip = event.get("source_ip")
                if source_ip:
                    self.event_buffers["failed_logins"][source_ip].append({
                        "timestamp": event.get("timestamp", datetime.utcnow()),
                        "event_id": event.get("id")
                    })
            
            elif event.get("event_type") == "firewall":
                source_ip = event.get("source_ip")
                dest_port = event.get("tags", {}).get("destination_port")
                if source_ip and dest_port:
                    self.event_buffers["port_scans"][source_ip].append({
                        "timestamp": event.get("timestamp", datetime.utcnow()),
                        "destination_port": dest_port,
                        "event_id": event.get("id")
                    })
            
            elif event.get("event_type") == "http_request":
                status = event.get("tags", {}).get("http_status")
                if status and status >= 400:
                    source_ip = event.get("source_ip")
                    if source_ip:
                        self.event_buffers["http_errors"][source_ip].append({
                            "timestamp": event.get("timestamp", datetime.utcnow()),
                            "status": status,
                            "event_id": event.get("id")
                        })
                        
        except Exception as e:
            logger.error(f"Error processing event for correlation: {e}")
    
    def _correlate_failed_logins(self):
        """Correlate failed login attempts"""
        current_time = datetime.utcnow()
        threshold = 5  # Number of failed attempts to trigger alert
        
        for source_ip, events in self.event_buffers["failed_logins"].items():
            # Remove events outside time window
            window_start = current_time - timedelta(seconds=self.time_windows["failed_logins"])
            recent_events = [
                e for e in events 
                if e["timestamp"] > window_start
            ]
            
            if len(recent_events) >= threshold:
                # Create alert
                alert_data = {
                    "rule_id": "multiple_failed_logins",
                    "rule_name": "Multiple Failed Login Attempts",
                    "severity": "high",
                    "description": f"Multiple failed login attempts from {source_ip}",
                    "events": [e["event_id"] for e in recent_events],
                    "source_ips": [source_ip],
                    "timestamp": current_time
                }
                
                self.rules_engine.create_alert(alert_data)
                logger.warning(f"Alert: Multiple failed logins from {source_ip}")
    
    def _correlate_port_scans(self):
        """Correlate port scanning activity"""
        current_time = datetime.utcnow()
        port_threshold = 10  # Number of unique ports to trigger alert
        
        for source_ip, events in self.event_buffers["port_scans"].items():
            # Remove events outside time window
            window_start = current_time - timedelta(seconds=self.time_windows["port_scans"])
            recent_events = [
                e for e in events 
                if e["timestamp"] > window_start
            ]
            
            # Count unique destination ports
            unique_ports = set(e["destination_port"] for e in recent_events)
            
            if len(unique_ports) >= port_threshold:
                # Create alert
                alert_data = {
                    "rule_id": "port_scan_detected",
                    "rule_name": "Port Scanning Activity",
                    "severity": "medium",
                    "description": f"Port scanning detected from {source_ip} ({len(unique_ports)} unique ports)",
                    "events": [e["event_id"] for e in recent_events],
                    "source_ips": [source_ip],
                    "timestamp": current_time
                }
                
                self.rules_engine.create_alert(alert_data)
                logger.warning(f"Alert: Port scanning from {source_ip}")
    
    def _correlate_http_errors(self):
        """Correlate HTTP error patterns"""
        current_time = datetime.utcnow()
        error_threshold = 20  # Number of errors to trigger alert
        
        for source_ip, events in self.event_buffers["http_errors"].items():
            # Remove events outside time window (1 minute for HTTP errors)
            window_start = current_time - timedelta(seconds=60)
            recent_events = [
                e for e in events 
                if e["timestamp"] > window_start
            ]
            
            if len(recent_events) >= error_threshold:
                # Create alert
                alert_data = {
                    "rule_id": "http_error_storm",
                    "rule_name": "HTTP Error Storm",
                    "severity": "medium",
                    "description": f"Excessive HTTP errors from {source_ip}",
                    "events": [e["event_id"] for e in recent_events],
                    "source_ips": [source_ip],
                    "timestamp": current_time
                }
                
                self.rules_engine.create_alert(alert_data)
                logger.warning(f"Alert: HTTP error storm from {source_ip}")
    
    def _clean_old_events(self):
        """Clean old events from buffers"""
        current_time = datetime.utcnow()
        
        for buffer_name in self.event_buffers:
            for key in list(self.event_buffers[buffer_name].keys()):
                # Get appropriate time window
                window_seconds = self.time_windows.get(buffer_name, 300)
                window_start = current_time - timedelta(seconds=window_seconds)
                
                # Remove old events
                self.event_buffers[buffer_name][key] = deque(
                    e for e in self.event_buffers[buffer_name][key] 
                    if e["timestamp"] > window_start
                )
                
                # Remove empty buffers
                if not self.event_buffers[buffer_name][key]:
                    del self.event_buffers[buffer_name][key]
