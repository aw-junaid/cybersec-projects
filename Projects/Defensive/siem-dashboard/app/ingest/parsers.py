import re
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class LogParser:
    """Parse various log formats into standardized events"""
    
    @staticmethod
    def parse_common_log_format(line, source="web_server"):
        """Parse Common Log Format (Apache/Nginx)"""
        try:
            # Common Log Format: IP - - [timestamp] "method url protocol" status size
            pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
            match = re.match(pattern, line)
            
            if match:
                ip, timestamp, method, url, protocol, status, size = match.groups()
                
                event = {
                    "timestamp": LogParser._parse_timestamp(timestamp),
                    "source_ip": ip,
                    "destination_ip": None,  # Will be set by correlation
                    "event_type": "http_request",
                    "severity": LogParser._get_http_severity(int(status)),
                    "source": source,
                    "message": f"{method} {url} - {status}",
                    "raw_log": line,
                    "tags": {
                        "http_method": method,
                        "http_url": url,
                        "http_status": int(status),
                        "response_size": int(size),
                        "user_agent": "unknown"  # Would extract from combined format
                    }
                }
                return event
        except Exception as e:
            logger.error(f"Error parsing common log format: {e}")
        
        return None
    
    @staticmethod
    def parse_json_log(line, source="application"):
        """Parse JSON formatted logs"""
        try:
            data = json.loads(line)
            
            event = {
                "timestamp": datetime.utcnow(),
                "source_ip": data.get('ip', data.get('source_ip')),
                "destination_ip": data.get('dest_ip', data.get('destination_ip')),
                "event_type": data.get('event_type', 'application'),
                "severity": data.get('severity', 'info'),
                "source": source,
                "message": data.get('message', line),
                "raw_log": line,
                "tags": data
            }
            
            # Ensure timestamp is properly parsed
            if 'timestamp' in data:
                try:
                    if isinstance(data['timestamp'], (int, float)):
                        event["timestamp"] = datetime.fromtimestamp(data['timestamp'])
                    else:
                        event["timestamp"] = datetime.fromisoformat(
                            data['timestamp'].replace('Z', '+00:00')
                        )
                except:
                    pass
            
            return event
        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.error(f"Error parsing JSON log: {e}")
            return None
    
    @staticmethod
    def parse_firewall_log(line, source="firewall"):
        """Parse firewall logs (basic pattern)"""
        try:
            # Basic firewall log pattern
            patterns = [
                # iptables format
                r'(\S+) (\S+) (\S+) .* SRC=(\S+) DST=(\S+) .* PROTO=(\S+) .* SPT=(\d+) DPT=(\d+)',
                # Cisco ASA format
                r'%ASA-(\d)-(\d+): .* (\S+) to (\S+)'
            ]
            
            for pattern in patterns:
                match = re.match(pattern, line)
                if match:
                    event = {
                        "timestamp": datetime.utcnow(),
                        "source_ip": match.group(4) if 'SRC' in pattern else match.group(3),
                        "destination_ip": match.group(5) if 'DST' in pattern else match.group(4),
                        "event_type": "firewall",
                        "severity": "info",
                        "source": source,
                        "message": line,
                        "raw_log": line,
                        "tags": {
                            "protocol": match.group(6) if 'PROTO' in pattern else 'unknown',
                            "source_port": match.group(7) if 'SPT' in pattern else 'unknown',
                            "destination_port": match.group(8) if 'DPT' in pattern else 'unknown'
                        }
                    }
                    return event
        except Exception as e:
            logger.error(f"Error parsing firewall log: {e}")
        
        return None
    
    @staticmethod
    def _parse_timestamp(timestamp_str):
        """Parse various timestamp formats"""
        try:
            # Common log format: 10/Oct/2000:13:55:36 -0700
            formats = [
                '%d/%b/%Y:%H:%M:%S %z',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            # If no format matches, return current time
            return datetime.utcnow()
        except:
            return datetime.utcnow()
    
    @staticmethod
    def _get_http_severity(status_code):
        """Determine severity based on HTTP status code"""
        if status_code >= 500:
            return "error"
        elif status_code >= 400:
            return "warning"
        elif status_code >= 300:
            return "info"
        else:
            return "info"
