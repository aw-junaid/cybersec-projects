import os
from typing import List, Dict, Any
from datetime import timedelta

class Settings:
    # Application
    APP_NAME = "SIEM Dashboard"
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    SECRET_KEY = os.getenv("SECRET_KEY", "siem-secure-key-change-in-production")
    
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./siem.db")
    
    # Elasticsearch
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    ELASTICSEARCH_INDEX = "siem-logs"
    
    # Redis
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Log Sources
    LOG_SOURCES = [
        {
            "name": "firewall",
            "type": "syslog",
            "port": 514,
            "protocol": "udp"
        },
        {
            "name": "web_server",
            "type": "file",
            "path": "/var/log/nginx/access.log"
        },
        {
            "name": "auth_server",
            "type": "syslog", 
            "port": 1514,
            "protocol": "tcp"
        }
    ]
    
    # Security Rules
    SECURITY_RULES = [
        {
            "id": "rule_001",
            "name": "Multiple Failed Logins",
            "description": "Detect multiple failed login attempts from same IP",
            "condition": "count > 5",
            "time_window": "5 minutes",
            "severity": "high"
        },
        {
            "id": "rule_002", 
            "name": "Port Scanning",
            "description": "Detect port scanning activity",
            "condition": "unique_ports > 10",
            "time_window": "1 minute",
            "severity": "medium"
        },
        {
            "id": "rule_003",
            "name": "Data Exfiltration",
            "description": "Large outbound data transfer",
            "condition": "outbound_bytes > 100000000",  # 100MB
            "time_window": "10 minutes",
            "severity": "critical"
        }
    ]
    
    # Dashboard Settings
    DASHBOARD_REFRESH_INTERVAL = 30000  # milliseconds
    MAX_EVENTS_DISPLAY = 1000

settings = Settings()
