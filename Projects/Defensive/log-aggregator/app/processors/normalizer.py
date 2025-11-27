import logging
import re
from typing import Dict, Any, List
from datetime import datetime
import ipaddress

logger = logging.getLogger(__name__)

class LogNormalizer:
    """Normalize log entries to consistent format"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.field_mappings = config.get("field_mappings", {})
        self.timestamp_fields = config.get("timestamp_fields", ["timestamp"])
    
    def normalize(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a log entry to consistent format"""
        try:
            normalized = log_entry.copy()
            
            # Apply field mappings
            normalized = self._apply_field_mappings(normalized)
            
            # Normalize timestamp
            normalized = self._normalize_timestamp(normalized)
            
            # Normalize IP addresses
            normalized = self._normalize_ip_addresses(normalized)
            
            # Normalize severity levels
            normalized = self._normalize_severity(normalized)
            
            # Add metadata
            normalized = self._add_metadata(normalized)
            
            # Clean up fields
            normalized = self._cleanup_fields(normalized)
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing log entry: {e}")
            return log_entry
    
    def _apply_field_mappings(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Apply field name mappings to standardize field names"""
        mapped_entry = log_entry.copy()
        
        for old_field, new_field in self.field_mappings.items():
            if old_field in mapped_entry and new_field not in mapped_entry:
                mapped_entry[new_field] = mapped_entry[old_field]
                # Don't remove old field to preserve original data
        
        return mapped_entry
    
    def _normalize_timestamp(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize timestamp to ISO format and UNIX timestamp"""
        normalized = log_entry.copy()
        
        # Find timestamp field
        timestamp_value = None
        timestamp_field = None
        
        for field in self.timestamp_fields:
            if field in normalized and normalized[field]:
                timestamp_value = normalized[field]
                timestamp_field = field
                break
        
        if timestamp_value:
            try:
                # Handle different timestamp formats
                if isinstance(timestamp_value, (int, float)):
                    # UNIX timestamp
                    unix_ts = float(timestamp_value)
                    iso_ts = datetime.fromtimestamp(unix_ts).isoformat()
                
                elif isinstance(timestamp_value, str):
                    # Try to parse string timestamp
                    unix_ts = self._parse_timestamp_string(timestamp_value)
                    if unix_ts:
                        iso_ts = datetime.fromtimestamp(unix_ts).isoformat()
                    else:
                        # Use current time if parsing fails
                        unix_ts = datetime.now().timestamp()
                        iso_ts = datetime.now().isoformat()
                
                else:
                    # Use current time
                    unix_ts = datetime.now().timestamp()
                    iso_ts = datetime.now().isoformat()
                
                # Add normalized timestamp fields
                normalized['@timestamp'] = iso_ts
                normalized['timestamp_unix'] = unix_ts
                
            except Exception as e:
                logger.warning(f"Error normalizing timestamp: {e}")
                # Fallback to current time
                normalized['@timestamp'] = datetime.now().isoformat()
                normalized['timestamp_unix'] = datetime.now().timestamp()
        
        else:
            # No timestamp found, use current time
            normalized['@timestamp'] = datetime.now().isoformat()
            normalized['timestamp_unix'] = datetime.now().timestamp()
        
        return normalized
    
    def _parse_timestamp_string(self, timestamp_str: str) -> float:
        """Parse timestamp string to UNIX timestamp"""
        try:
            # Try common formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ", 
                "%Y-%m-%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z",
                "%b %d %H:%M:%S",
                "%Y-%m-%d"
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    return dt.timestamp()
                except ValueError:
                    continue
            
            # Try parsing as UNIX timestamp string
            try:
                return float(timestamp_str)
            except ValueError:
                pass
            
            return None
            
        except Exception:
            return None
    
    def _normalize_ip_addresses(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize and validate IP addresses"""
        normalized = log_entry.copy()
        ip_fields = ['source_ip', 'client_ip', 'remote_addr', 'dst_ip', 'src_ip']
        
        for field in ip_fields:
            if field in normalized and normalized[field]:
                try:
                    ip_str = str(normalized[field])
                    
                    # Validate IP address
                    ip = ipaddress.ip_address(ip_str)
                    
                    # Add IP metadata
                    normalized[f'{field}_type'] = 'IPv4' if ip.version == 4 else 'IPv6'
                    normalized[f'{field}_is_private'] = ip.is_private
                    normalized[f'{field}_is_global'] = ip.is_global
                    
                    # For IPv4, add network information
                    if ip.version == 4:
                        # Extract first two octets for network grouping
                        octets = ip_str.split('.')
                        if len(octets) >= 2:
                            normalized[f'{field}_network'] = f"{octets[0]}.{octets[1]}.0.0/16"
                    
                except ValueError:
                    # Invalid IP address
                    normalized[f'{field}_valid'] = False
                except Exception as e:
                    logger.debug(f"Error processing IP address {field}: {e}")
        
        return normalized
    
    def _normalize_severity(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize severity levels to consistent format"""
        normalized = log_entry.copy()
        
        severity_fields = ['severity', 'level', 'log_level', 'pri']
        
        for field in severity_fields:
            if field in normalized and normalized[field]:
                severity = str(normalized[field]).lower()
                
                # Map to standard levels
                severity_map = {
                    '0': 'emergency', 'emerg': 'emergency',
                    '1': 'alert',
                    '2': 'critical', 'crit': 'critical', 'fatal': 'critical',
                    '3': 'error', 'err': 'error',
                    '4': 'warning', 'warn': 'warning',
                    '5': 'notice', 
                    '6': 'info', 'information': 'info',
                    '7': 'debug',
                    'panic': 'emergency',
                    'error': 'error',
                    'warning': 'warning',
                    'info': 'info',
                    'debug': 'debug'
                }
                
                normalized_severity = severity_map.get(severity, severity)
                normalized['severity_normalized'] = normalized_severity
                
                # Add numeric severity for sorting
                numeric_severity = {
                    'emergency': 0,
                    'alert': 1,
                    'critical': 2, 
                    'error': 3,
                    'warning': 4,
                    'notice': 5,
                    'info': 6,
                    'debug': 7
                }.get(normalized_severity, 6)  # Default to info
                
                normalized['severity_numeric'] = numeric_severity
                break
        
        return normalized
    
    def _add_metadata(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Add metadata to log entry"""
        normalized = log_entry.copy()
        
        # Add processing metadata
        normalized['_normalized'] = True
        normalized['_normalized_at'] = datetime.now().isoformat()
        
        # Add message hash for deduplication
        message = normalized.get('message', normalized.get('raw_message', ''))
        if message:
            import hashlib
            message_hash = hashlib.md5(message.encode()).hexdigest()
            normalized['_message_hash'] = message_hash
        
        # Add source metadata
        if 'source_ip' in normalized:
            normalized['_source'] = normalized['source_ip']
        elif 'hostname' in normalized:
            normalized['_source'] = normalized['hostname']
        elif 'file_path' in normalized:
            normalized['_source'] = normalized['file_path']
        
        return normalized
    
    def _cleanup_fields(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up and remove unnecessary fields"""
        normalized = log_entry.copy()
        
        # Fields to keep (whitelist approach)
        important_fields = {
            '@timestamp', 'timestamp_unix', 'message', 'raw_message',
            'source_ip', 'destination_ip', 'hostname', 'app', 'pid',
            'severity', 'severity_normalized', 'severity_numeric',
            'method', 'path', 'status', 'protocol', 'user_agent', 'referrer',
            'file_path', 'source_type', '_source', '_message_hash',
            '_normalized', '_normalized_at', '_parser', '_structured'
        }
        
        # Add all fields that start with config prefixes
        for field in list(normalized.keys()):
            if (field not in important_fields and 
                not field.startswith('_') and
                field not in self.field_mappings.values()):
                # Keep the field but mark it as additional
                pass
        
        return normalized
