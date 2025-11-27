from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import json

Base = declarative_base()

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    event_type = Column(String(100), index=True)
    severity = Column(String(20), index=True)  # low, medium, high, critical
    source = Column(String(100))  # firewall, web_server, auth, etc.
    message = Column(Text)
    raw_log = Column(Text)
    tags = Column(JSON)  # Additional metadata
    processed = Column(Boolean, default=False)
    alert_triggered = Column(Boolean, default=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "tags": self.tags or {},
            "processed": self.processed,
            "alert_triggered": self.alert_triggered
        }

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    rule_id = Column(String(50), index=True)
    rule_name = Column(String(200))
    severity = Column(String(20), index=True)
    description = Column(Text)
    events = Column(JSON)  # List of event IDs that triggered the alert
    source_ips = Column(JSON)
    destination_ips = Column(JSON)
    acknowledged = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "events": self.events or [],
            "source_ips": self.source_ips or [],
            "destination_ips": self.destination_ips or [],
            "acknowledged": self.acknowledged,
            "resolved": self.resolved
        }

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(200), index=True)  # IP, domain, hash
    indicator_type = Column(String(50))  # ipv4, domain, md5, sha256
    threat_type = Column(String(100))  # malware, botnet, phishing
    severity = Column(String(20))
    source = Column(String(100))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    description = Column(Text)
    tags = Column(JSON)

class DashboardMetric(Base):
    __tablename__ = "dashboard_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    metric_name = Column(String(100), index=True)
    metric_value = Column(Float)
    tags = Column(JSON)
