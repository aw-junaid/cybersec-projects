import re
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class BaseParser(ABC):
    """Base class for all log parsers"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.patterns = self._compile_patterns()
    
    @abstractmethod
    def _compile_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for this parser"""
        pass
    
    def parse(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a log entry and return structured data"""
        try:
            raw_message = log_entry.get("raw_message", "")
            
            # Try each pattern until one matches
            for pattern in self.patterns:
                match = pattern.match(raw_message)
                if match:
                    parsed_data = match.groupdict()
                    parsed_data = self._post_process(parsed_data, log_entry)
                    return self._create_structured_entry(parsed_data, log_entry)
            
            # If no pattern matches, return basic structure
            return self._create_fallback_entry(log_entry)
            
        except Exception as e:
            logger.error(f"Error parsing log with {self.name}: {e}")
            return self._create_error_entry(log_entry, str(e))
    
    def _post_process(self, parsed_data: Dict[str, Any], original_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process parsed data (timestamp conversion, type casting, etc.)"""
        # Convert timestamp if present
        if 'timestamp' in parsed_data:
            parsed_data['timestamp'] = self._parse_timestamp(parsed_data['timestamp'])
        
        # Convert numeric fields
        for field in ['status', 'size', 'body_bytes_sent', 'pid']:
            if field in parsed_data and parsed_data[field]:
                try:
                    parsed_data[field] = int(parsed_data[field])
                except (ValueError, TypeError):
                    pass
        
        # Add parser metadata
        parsed_data['_parser'] = self.name
        parsed_data['_parse_success'] = True
        
        return parsed_data
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[float]:
        """Parse timestamp string to UNIX timestamp"""
        try:
            timestamp_format = self.config.get("timestamp_format")
            
            if timestamp_format:
                dt = datetime.strptime(timestamp_str, timestamp_format)
            else:
                # Try common formats
                formats = [
                    "%d/%b/%Y:%H:%M:%S %z",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%b %d %H:%M:%S"
                ]
                
                for fmt in formats:
                    try:
                        dt = datetime.strptime(timestamp_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    # If no format matches, use current time
                    return datetime.now().timestamp()
            
            return dt.timestamp()
            
        except Exception as e:
            logger.warning(f"Could not parse timestamp '{timestamp_str}': {e}")
            return datetime.now().timestamp()
    
    def _create_structured_entry(self, parsed_data: Dict[str, Any], original_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Create structured log entry from parsed data"""
        structured_entry = original_entry.copy()
        structured_entry.update(parsed_data)
        structured_entry['_structured'] = True
        return structured_entry
    
    def _create_fallback_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Create fallback entry when parsing fails"""
        fallback_entry = log_entry.copy()
        fallback_entry.update({
            'message': log_entry.get('raw_message', ''),
            '_structured': False,
            '_parser': self.name,
            '_parse_success': False
        })
        return fallback_entry
    
    def _create_error_entry(self, log_entry: Dict[str, Any], error: str) -> Dict[str, Any]:
        """Create error entry for parsing failures"""
        error_entry = log_entry.copy()
        error_entry.update({
            'message': log_entry.get('raw_message', ''),
            '_structured': False,
            '_parser': self.name,
            '_parse_success': False,
            '_parse_error': error
        })
        return error_entry

class ApacheParser(BaseParser):
    """Parser for Apache HTTP server logs"""
    
    def _compile_patterns(self) -> List[re.Pattern]:
        patterns = [
            # Common Log Format
            re.compile(r'^(?P<client_ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+)'),
            # Combined Log Format
            re.compile(r'^(?P<client_ip>\S+) - (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'),
            # With virtual host
            re.compile(r'^(?P<vhost>\S+) (?P<client_ip>\S+) - (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"')
        ]
        return patterns

class NginxParser(BaseParser):
    """Parser for Nginx HTTP server logs"""
    
    def _compile_patterns(self) -> List[re.Pattern]:
        patterns = [
            # Combined format
            re.compile(r'^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" "(?P<http_x_forwarded_for>[^"]*)"'),
            # Main format
            re.compile(r'^(?P<remote_addr>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+)'),
            # With request time
            re.compile(r'^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" (?P<request_time>\S+)')
        ]
        return patterns

class SyslogParser(BaseParser):
    """Parser for syslog messages"""
    
    def _compile_patterns(self) -> List[re.Pattern]:
        patterns = [
            # RFC 5424 format
            re.compile(r'^<(?P<pri>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<hostname>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?P<message>.*)'),
            # RFC 3164 format
            re.compile(r'^<(?P<pri>\d+)>(?P<timestamp>\S+\s+\S+) (?P<hostname>\S+) (?P<app>\S+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'),
            # Simple format
            re.compile(r'^<(?P<pri>\d+)>(?P<timestamp>\S+\s+\S+) (?P<hostname>\S+) (?P<message>.*)')
        ]
        return patterns
    
    def _post_process(self, parsed_data: Dict[str, Any], original_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process syslog-specific fields"""
        parsed_data = super()._post_process(parsed_data, original_entry)
        
        # Parse priority field
        if 'pri' in parsed_data:
            try:
                pri = int(parsed_data['pri'])
                facility = pri // 8
                severity = pri % 8
                
                parsed_data['facility'] = facility
                parsed_data['severity'] = severity
                parsed_data['severity_name'] = self._get_severity_name(severity)
            except (ValueError, TypeError):
                pass
        
        return parsed_data
    
    def _get_severity_name(self, severity: int) -> str:
        """Get severity name from numeric code"""
        severity_names = {
            0: "emergency",
            1: "alert", 
            2: "critical",
            3: "error",
            4: "warning",
            5: "notice",
            6: "info",
            7: "debug"
        }
        return severity_names.get(severity, "unknown")

class JSONParser(BaseParser):
    """Parser for JSON-formatted logs"""
    
    def _compile_patterns(self) -> List[re.Pattern]:
        # JSON parser doesn't use regex patterns
        return []
    
    def parse(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse JSON log entry"""
        try:
            raw_message = log_entry.get("raw_message", "").strip()
            
            # Try to parse as JSON
            json_data = json.loads(raw_message)
            
            if isinstance(json_data, dict):
                # Add parser metadata
                json_data.update({
                    '_parser': self.name,
                    '_structured': True,
                    '_parse_success': True
                })
                
                # Merge with original entry
                structured_entry = log_entry.copy()
                structured_entry.update(json_data)
                return structured_entry
            else:
                return self._create_fallback_entry(log_entry)
                
        except json.JSONDecodeError:
            # Not valid JSON, return as fallback
            return self._create_fallback_entry(log_entry)
        except Exception as e:
            logger.error(f"Error parsing JSON log: {e}")
            return self._create_error_entry(log_entry, str(e))

class ParserManager:
    """Manage multiple log parsers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.parsers = self._initialize_parsers()
    
    def _initialize_parsers(self) -> Dict[str, BaseParser]:
        """Initialize all configured parsers"""
        parsers = {}
        parser_configs = self.config.get("parsers", {})
        
        for parser_name, parser_config in parser_configs.items():
            try:
                if parser_name == "apache":
                    parsers[parser_name] = ApacheParser(parser_name, parser_config)
                elif parser_name == "nginx":
                    parsers[parser_name] = NginxParser(parser_name, parser_config)
                elif parser_name == "syslog":
                    parsers[parser_name] = SyslogParser(parser_name, parser_config)
                elif parser_name == "json":
                    parsers[parser_name] = JSONParser(parser_name, parser_config)
                else:
                    logger.warning(f"Unknown parser type: {parser_name}")
            except Exception as e:
                logger.error(f"Error initializing parser {parser_name}: {e}")
        
        logger.info(f"Initialized {len(parsers)} parsers")
        return parsers
    
    def parse(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse log entry using appropriate parser"""
        # Determine which parser to use
        parser_name = self._select_parser(log_entry)
        
        if parser_name in self.parsers:
            return self.parsers[parser_name].parse(log_entry)
        else:
            # Use fallback parser (JSON or raw)
            if "json" in self.parsers:
                return self.parsers["json"].parse(log_entry)
            else:
                # Create basic structured entry
                basic_entry = log_entry.copy()
                basic_entry.update({
                    'message': log_entry.get('raw_message', ''),
                    '_structured': False,
                    '_parser': 'fallback',
                    '_parse_success': True
                })
                return basic_entry
    
    def _select_parser(self, log_entry: Dict[str, Any]) -> str:
        """Select appropriate parser for log entry"""
        source_type = log_entry.get('source_type', '')
        file_path = log_entry.get('file_path', '')
        raw_message = log_entry.get('raw_message', '')
        
        # Check source type hints
        if 'apache' in source_type.lower() or 'apache' in file_path.lower():
            return 'apache'
        elif 'nginx' in source_type.lower() or 'nginx' in file_path.lower():
            return 'nginx'
        elif 'syslog' in source_type.lower():
            return 'syslog'
        
        # Check message content
        if raw_message.strip().startswith('{') or raw_message.strip().startswith('['):
            return 'json'
        elif ' - - [' in raw_message and '] "' in raw_message:
            return 'apache'
        elif ' "' in raw_message and ' HTTP/' in raw_message:
            return 'nginx'
        elif raw_message.startswith('<') and '>' in raw_message:
            return 'syslog'
        
        # Default to JSON parser for unknown formats
        return 'json'
