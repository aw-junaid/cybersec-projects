import os
from typing import List, Dict, Any
from pathlib import Path

class Settings:
    # Application
    APP_NAME = "Log Aggregator"
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    # Data directories
    DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
    LOGS_DIR = DATA_DIR / "logs"
    CONFIG_DIR = Path("./config")
    
    # Collection settings
    COLLECTORS = {
        "file": {
            "enabled": True,
            "poll_interval": 1,  # seconds
            "max_file_size": 100 * 1024 * 1024,  # 100MB
        },
        "syslog": {
            "enabled": True,
            "udp_port": 514,
            "tcp_port": 1514,
            "max_message_size": 8192,
        },
        "http": {
            "enabled": True,
            "port": 8080,
            "max_content_length": 10 * 1024 * 1024,  # 10MB
        }
    }
    
    # Parser configurations
    PARSERS = {
        "apache": {
            "patterns": [
                r'^(?P<client_ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+)',
                r'^(?P<client_ip>\S+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ],
            "timestamp_format": "%d/%b/%Y:%H:%M:%S %z"
        },
        "nginx": {
            "patterns": [
                r'^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"',
                r'^(?P<remote_addr>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+)'
            ],
            "timestamp_format": "%d/%b/%Y:%H:%M:%S %z"
        },
        "syslog": {
            "patterns": [
                r'^<(?P<pri>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<hostname>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?P<message>.*)',
                r'^<(?P<pri>\d+)>(?P<timestamp>\S+\s+\S+) (?P<hostname>\S+) (?P<app>\S+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'
            ],
            "timestamp_format": "%Y-%m-%dT%H:%M:%S.%fZ"
        },
        "json": {
            "patterns": [],  # JSON doesn't need regex patterns
            "enabled": True
        }
    }
    
    # Normalization rules
    NORMALIZATION = {
        "field_mappings": {
            "client_ip": "source_ip",
            "remote_addr": "source_ip",
            "host": "source_ip",
            "msg": "message",
            "log": "message",
            "content": "message"
        },
        "timestamp_fields": ["timestamp", "@timestamp", "time", "datetime"],
        "default_timestamp_format": "iso8601"
    }
    
    # Storage settings
    STORAGE = {
        "elasticsearch": {
            "enabled": True,
            "hosts": os.getenv("ELASTICSEARCH_HOSTS", "http://localhost:9200").split(","),
            "index_prefix": "logs-",
            "bulk_size": 1000,
            "timeout": 30
        },
        "database": {
            "enabled": False,
            "url": os.getenv("DATABASE_URL", "sqlite:///./logs.db"),
            "table_name": "log_events"
        },
        "file": {
            "enabled": True,
            "directory": "./data/storage",
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "rotation_count": 10
        }
    }
    
    # Search settings
    SEARCH = {
        "default_limit": 100,
        "max_limit": 10000,
        "time_range_default": "1h",
        "highlight_fields": ["message", "path", "user_agent"]
    }
    
    # API settings
    API = {
        "host": "0.0.0.0",
        "port": 8000,
        "cors_origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
        "rate_limit": "1000/hour"
    }

settings = Settings()
