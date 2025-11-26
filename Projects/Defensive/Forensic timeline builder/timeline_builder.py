#!/usr/bin/env python3
"""
Forensic Timeline Builder - Python Implementation
Correlates artifacts from multiple sources into unified timelines
"""

import os
import sys
import json
import sqlite3
import argparse
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import csv
import re
from dataclasses import dataclass
from collections import defaultdict
import psutil

@dataclass
class TimelineEvent:
    """Represents a single timeline event"""
    timestamp: datetime
    source: str
    event_type: str
    description: str
    artifact: str
    user: str = ""
    host: str = ""
    hash: str = ""
    size: int = 0
    confidence: float = 1.0
    tags: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'description': self.description,
            'artifact': self.artifact,
            'user': self.user,
            'host': self.host,
            'hash': self.hash,
            'size': self.size,
            'confidence': self.confidence,
            'tags': self.tags or []
        }

class TimelineBuilder:
    """Builds forensic timelines from multiple artifact sources"""
    
    def __init__(self, case_name: str = "forensic_case"):
        self.case_name = case_name
        self.events = []
        self.sources = {}
        self.init_database()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('timeline_builder.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize timeline database"""
        self.db_path = f"{self.case_name}_timeline.db"
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                artifact TEXT,
                user TEXT,
                host TEXT,
                file_hash TEXT,
                file_size INTEGER,
                confidence REAL DEFAULT 1.0,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS artifact_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                source_path TEXT NOT NULL,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON timeline_events(timestamp);
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_event_type ON timeline_events(event_type);
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_source ON timeline_events(source);
        ''')
        
        self.conn.commit()
    
    def add_event(self, event: TimelineEvent) -> bool:
        """Add an event to the timeline"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO timeline_events 
                (timestamp, source, event_type, description, artifact, user, host, file_hash, file_size, confidence, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.timestamp.isoformat(),
                event.source,
                event.event_type,
                event.description,
                event.artifact,
                event.user,
                event.host,
                event.hash,
                event.size,
                event.confidence,
                json.dumps(event.tags) if event.tags else '[]'
            ))
            
            self.conn.commit()
            self.events.append(event)
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding event: {e}")
            return False
    
    def process_filesystem_timestamps(self, directory: str, recursive: bool = True) -> int:
        """Process filesystem MACB timestamps (Modified, Accessed, Changed, Birth)"""
        self.logger.info(f"Processing filesystem timestamps from: {directory}")
        
        event_count = 0
        directory_path = Path(directory)
        
        if not directory_path.exists():
            self.logger.error(f"Directory does not exist: {directory}")
            return 0
        
        # Record source
        source_id = self._record_source('filesystem', directory)
        
        files_to_process = []
        if recursive:
            files_to_process = list(directory_path.rglob('*'))
        else:
            files_to_process = list(directory_path.iterdir())
        
        for file_path in files_to_process:
            if file_path.is_file():
                try:
                    stat = file_path.stat()
                    
                    # Create events for each timestamp type
                    timestamps = [
                        (datetime.fromtimestamp(stat.st_mtime), 'filesystem', 'file_modified', f'File modified: {file_path}'),
                        (datetime.fromtimestamp(stat.st_atime), 'filesystem', 'file_accessed', f'File accessed: {file_path}'),
                        (datetime.fromtimestamp(stat.st_ctime), 'filesystem', 'metadata_changed', f'File metadata changed: {file_path}'),
                    ]
                    
                    # Birth time (if available)
                    try:
                        if hasattr(stat, 'st_birthtime'):
                            timestamps.append((datetime.fromtimestamp(stat.st_birthtime), 'filesystem', 'file_created', f'File created: {file_path}'))
                    except AttributeError:
                        pass
                    
                    for timestamp, source, event_type, description in timestamps:
                        event = TimelineEvent(
                            timestamp=timestamp,
                            source=source,
                            event_type=event_type,
                            description=description,
                            artifact=str(file_path),
                            size=stat.st_size
                        )
                        
                        if self.add_event(event):
                            event_count += 1
                    
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Could not process {file_path}: {e}")
        
        self._update_source_count(source_id, event_count)
        self.logger.info(f"Processed {event_count} filesystem events from {directory}")
        return event_count
    
    def parse_windows_event_logs(self, evtx_file: str) -> int:
        """Parse Windows Event Logs (EVTX files)"""
        self.logger.info(f"Processing Windows Event Log: {evtx_file}")
        
        # This would use python-evtx or similar library in production
        # For demo purposes, we'll simulate event parsing
        
        simulated_events = [
            (datetime(2024, 1, 15, 10, 30, 0), 'windows_event', 'user_logon', 'User jdoe logged on', 'Security', 'jdoe'),
            (datetime(2024, 1, 15, 10, 31, 15), 'windows_event', 'process_creation', 'Process started: cmd.exe', 'Security', 'jdoe'),
            (datetime(2024, 1, 15, 10, 32, 30), 'windows_event', 'network_connection', 'Outbound connection to 192.168.1.100', 'Security', 'SYSTEM'),
        ]
        
        source_id = self._record_source('windows_event_log', evtx_file)
        event_count = 0
        
        for timestamp, source, event_type, description, log_name, user in simulated_events:
            event = TimelineEvent(
                timestamp=timestamp,
                source=source,
                event_type=event_type,
                description=description,
                artifact=log_name,
                user=user
            )
            
            if self.add_event(event):
                event_count += 1
        
        self._update_source_count(source_id, event_count)
        self.logger.info(f"Processed {event_count} Windows Event Log events")
        return event_count
    
    def parse_bash_history(self, history_file: str, username: str = "unknown") -> int:
        """Parse bash history files"""
        self.logger.info(f"Processing bash history: {history_file}")
        
        if not os.path.exists(history_file):
            self.logger.error(f"History file not found: {history_file}")
            return 0
        
        source_id = self._record_source('bash_history', history_file)
        event_count = 0
        
        try:
            with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Parse timestamp if available (bash history with timestamps)
                timestamp = None
                command = line
                
                # Check for timestamp format: #1610647200
                if line.startswith('#') and line[1:].isdigit():
                    timestamp_str = line[1:]
                    if len(timestamp_str) == 10:  # Unix timestamp
                        timestamp = datetime.fromtimestamp(int(timestamp_str))
                        # Next line should be the command
                        if line_num < len(lines):
                            command = lines[line_num].strip()
                    else:
                        continue
                else:
                    # No timestamp, use file modification time as approximation
                    stat = os.stat(history_file)
                    timestamp = datetime.fromtimestamp(stat.st_mtime - (len(lines) - line_num) * 60)  # Approximate
                
                event = TimelineEvent(
                    timestamp=timestamp,
                    source='bash_history',
                    event_type='command_executed',
                    description=f'Command executed: {command}',
                    artifact=history_file,
                    user=username
                )
                
                if self.add_event(event):
                    event_count += 1
        
        except Exception as e:
            self.logger.error(f"Error parsing bash history: {e}")
        
        self._update_source_count(source_id, event_count)
        self.logger.info(f"Processed {event_count} bash history events")
        return event_count
    
    def parse_apache_logs(self, log_file: str) -> int:
        """Parse Apache access logs"""
        self.logger.info(f"Processing Apache logs: {log_file}")
        
        if not os.path.exists(log_file):
            self.logger.error(f"Log file not found: {log_file}")
            return 0
        
        source_id = self._record_source('apache_logs', log_file)
        event_count = 0
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse Apache common log format
                    # 127.0.0.1 - jdoe [15/Jan/2024:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234
                    log_pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'
                    match = re.match(log_pattern, line)
                    
                    if match:
                        ip, ident, user, timestamp_str, request, status, size = match.groups()
                        
                        # Parse Apache timestamp
                        try:
                            timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
                        except ValueError:
                            continue
                        
                        event_type = 'web_access'
                        if status.startswith('4') or status.startswith('5'):
                            event_type = 'web_error'
                        if 'admin' in request.lower() or 'login' in request.lower():
                            event_type = 'web_admin_access'
                        
                        event = TimelineEvent(
                            timestamp=timestamp,
                            source='apache_logs',
                            event_type=event_type,
                            description=f'HTTP {status}: {request} from {ip}',
                            artifact=log_file,
                            user=user if user != '-' else 'anonymous',
                            size=int(size) if size != '-' else 0
                        )
                        
                        if self.add_event(event):
                            event_count += 1
        
        except Exception as e:
            self.logger.error(f"Error parsing Apache logs: {e}")
        
        self._update_source_count(source_id, event_count)
        self.logger.info(f"Processed {event_count} Apache log events")
        return event_count
    
    def parse_windows_prefetch(self, prefetch_dir: str = "/Windows/Prefetch") -> int:
        """Parse Windows Prefetch files"""
        self.logger.info(f"Processing Windows Prefetch files from: {prefetch_dir}")
        
        if not os.path.exists(prefetch_dir):
            self.logger.error(f"Prefetch directory not found: {prefetch_dir}")
            return 0
        
        source_id = self._record_source('windows_prefetch', prefetch_dir)
        event_count = 0
        
        try:
            for file_path in Path(prefetch_dir).glob('*.pf'):
                try:
                    # In real implementation, use specialized prefetch parsing library
                    stat = file_path.stat()
                    
                    # Prefetch files contain last execution time in metadata
                    event = TimelineEvent(
                        timestamp=datetime.fromtimestamp(stat.st_mtime),
                        source='windows_prefetch',
                        event_type='program_execution',
                        description=f'Program executed: {file_path.stem}',
                        artifact=str(file_path),
                        size=stat.st_size
                    )
                    
                    if self.add_event(event):
                        event_count += 1
                        
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Could not process prefetch file {file_path}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error processing prefetch files: {e}")
        
        self._update_source_count(source_id, event_count)
        self.logger.info(f"Processed {event_count} Prefetch events")
        return event_count
    
    def parse_registry_hives(self, registry_files: List[str]) -> int:
        """Parse Windows Registry hives"""
        self.logger.info("Processing Windows Registry hives")
        
        event_count = 0
        
        for reg_file in registry_files:
            if not os.path.exists(reg_file):
                self.logger.warning(f"Registry file not found: {reg_file}")
                continue
            
            source_id = self._record_source('windows_registry', reg_file)
            
            # Simulate registry parsing - in real implementation use python-registry
            simulated_events = [
                (datetime(2024, 1, 15, 8, 0, 0), 'registry', 'system_boot', 'System boot time', 'SYSTEM\\CurrentControlSet\\Control\\Windows'),
                (datetime(2024, 1, 15, 10, 30, 0), 'registry', 'user_login', 'User login time', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI'),
                (datetime(2024, 1, 15, 10, 31, 0), 'registry', 'program_execution', 'Program executed via Run key', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'),
            ]
            
            for timestamp, source, event_type, description, key_path in simulated_events:
                event = TimelineEvent(
                    timestamp=timestamp,
                    source=source,
                    event_type=event_type,
                    description=description,
                    artifact=f"{reg_file}:{key_path}"
                )
                
                if self.add_event(event):
                    event_count += 1
            
            self._update_source_count(source_id, len(simulated_events))
        
        self.logger.info(f"Processed {event_count} Registry events")
        return event_count
    
    def _record_source(self, source_type: str, source_path: str) -> int:
        """Record an artifact source"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO artifact_sources (source_type, source_path)
            VALUES (?, ?)
        ''', (source_type, source_path))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def _update_source_count(self, source_id: int, event_count: int):
        """Update event count for a source"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE artifact_sources SET event_count = ? WHERE id = ?
        ''', (event_count, source_id))
        self.conn.commit()
    
    def build_timeline(self, start_time: datetime = None, end_time: datetime = None, 
                      event_types: List[str] = None, sources: List[str] = None) -> List[TimelineEvent]:
        """Build timeline with optional filters"""
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM timeline_events WHERE 1=1"
        params = []
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        if event_types:
            placeholders = ','.join('?' * len(event_types))
            query += f" AND event_type IN ({placeholders})"
            params.extend(event_types)
        
        if sources:
            placeholders = ','.join('?' * len(sources))
            query += f" AND source IN ({placeholders})"
            params.extend(sources)
        
        query += " ORDER BY timestamp"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        events = []
        for row in results:
            event = TimelineEvent(
                timestamp=datetime.fromisoformat(row[1]),
                source=row[2],
                event_type=row[3],
                description=row[4],
                artifact=row[5],
                user=row[6],
                host=row[7],
                hash=row[8],
                size=row[9],
                confidence=row[10],
                tags=json.loads(row[11]) if row[11] else []
            )
            events.append(event)
        
        return events
    
    def correlate_events(self, time_window: timedelta = timedelta(minutes=5)) -> List[List[TimelineEvent]]:
        """Correlate events that occur within a specified time window"""
        all_events = self.build_timeline()
        correlated_groups = []
        current_group = []
        
        for i, event in enumerate(all_events):
            if not current_group:
                current_group.append(event)
                continue
            
            # Check if event is within time window of previous event
            time_diff = event.timestamp - current_group[-1].timestamp
            if time_diff <= time_window:
                current_group.append(event)
            else:
                if len(current_group) > 1:
                    correlated_groups.append(current_group)
                current_group = [event]
        
        # Don't forget the last group
        if len(current_group) > 1:
            correlated_groups.append(current_group)
        
        return correlated_groups
    
    def generate_report(self, output_format: str = "html", output_file: str = None) -> str:
        """Generate timeline report"""
        events = self.build_timeline()
        
        if output_format == "html":
            report = self._generate_html_report(events)
        elif output_format == "csv":
            report = self._generate_csv_report(events)
        elif output_format == "json":
            report = self._generate_json_report(events)
        else:
            report = self._generate_text_report(events)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            self.logger.info(f"Report saved to: {output_file}")
        
        return report
    
    def _generate_html_report(self, events: List[TimelineEvent]) -> str:
        """Generate HTML timeline report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensic Timeline - {self.case_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .timeline {{ border-left: 3px solid #007cba; margin: 20px 0; }}
                .event {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
                .timestamp {{ font-weight: bold; color: #007cba; }}
                .source {{ color: #666; font-size: 0.9em; }}
                .description {{ margin: 5px 0; }}
                .metadata {{ font-size: 0.8em; color: #888; }}
            </style>
        </head>
        <body>
            <h1>Forensic Timeline Report</h1>
            <p><strong>Case:</strong> {self.case_name}</p>
            <p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
            <p><strong>Total Events:</strong> {len(events)}</p>
            
            <div class="timeline">
        """
        
        for event in events:
            html += f"""
                <div class="event">
                    <div class="timestamp">{event.timestamp.isoformat()}</div>
                    <div class="source">{event.source} - {event.event_type}</div>
                    <div class="description">{event.description}</div>
                    <div class="metadata">
                        Artifact: {event.artifact} | 
                        User: {event.user} | 
                        Confidence: {event.confidence}
                    </div>
                </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_csv_report(self, events: List[TimelineEvent]) -> str:
        """Generate CSV timeline report"""
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Timestamp', 'Source', 'Event Type', 'Description', 'Artifact', 'User', 'Host', 'File Hash', 'Size', 'Confidence', 'Tags'])
        
        # Write events
        for event in events:
            writer.writerow([
                event.timestamp.isoformat(),
                event.source,
                event.event_type,
                event.description,
                event.artifact,
                event.user,
                event.host,
                event.hash,
                event.size,
                event.confidence,
                ';'.join(event.tags) if event.tags else ''
            ])
        
        return output.getvalue()
    
    def _generate_json_report(self, events: List[TimelineEvent]) -> str:
        """Generate JSON timeline report"""
        report_data = {
            'case_name': self.case_name,
            'generated_at': datetime.now().isoformat(),
            'total_events': len(events),
            'events': [event.to_dict() for event in events]
        }
        
        return json.dumps(report_data, indent=2)
    
    def _generate_text_report(self, events: List[TimelineEvent]) -> str:
        """Generate text timeline report"""
        report = f"""
Forensic Timeline Report
========================

Case: {self.case_name}
Generated: {datetime.now().isoformat()}
Total Events: {len(events)}

Timeline:
---------
"""
        
        for event in events:
            report += f"""
{event.timestamp.isoformat()} [{event.source}/{event.event_type}]
  {event.description}
  Artifact: {event.artifact}
  User: {event.user} | Host: {event.host}
  Confidence: {event.confidence} | Tags: {', '.join(event.tags) if event.tags else 'None'}
"""
        
        return report
    
    def analyze_timeline(self) -> Dict[str, Any]:
        """Analyze timeline for patterns and statistics"""
        events = self.build_timeline()
        
        analysis = {
            'total_events': len(events),
            'time_range': {},
            'events_by_source': defaultdict(int),
            'events_by_type': defaultdict(int),
            'events_by_hour': defaultdict(int),
            'top_artifacts': defaultdict(int),
            'suspicious_activity': []
        }
        
        if events:
            timestamps = [event.timestamp for event in events]
            analysis['time_range']['start'] = min(timestamps).isoformat()
            analysis['time_range']['end'] = max(timestamps).isoformat()
            analysis['time_range']['duration'] = str(max(timestamps) - min(timestamps))
        
        for event in events:
            analysis['events_by_source'][event.source] += 1
            analysis['events_by_type'][event.event_type] += 1
            analysis['events_by_hour'][event.timestamp.hour] += 1
            analysis['top_artifacts'][event.artifact] += 1
            
            # Detect suspicious patterns
            if any(keyword in event.description.lower() for keyword in ['malware', 'virus', 'exploit', 'inject', 'shell']):
                analysis['suspicious_activity'].append({
                    'timestamp': event.timestamp.isoformat(),
                    'description': event.description,
                    'reason': 'Suspicious keywords detected'
                })
        
        return analysis

class SuperTimelineBuilder(TimelineBuilder):
    """Extended timeline builder with advanced correlation features"""
    
    def __init__(self, case_name: str = "forensic_case"):
        super().__init__(case_name)
        self.entity_resolution = {}  # User/entity resolution mapping
    
    def build_super_timeline(self) -> List[TimelineEvent]:
        """Build enhanced timeline with correlated entities"""
        events = self.build_timeline()
        
        # Enhance events with entity resolution
        enhanced_events = []
        for event in events:
            enhanced_event = self._enhance_event(event)
            enhanced_events.append(enhanced_event)
        
        return enhanced_events
    
    def _enhance_event(self, event: TimelineEvent) -> TimelineEvent:
        """Enhance event with additional context and entity resolution"""
        # Resolve user entities
        if event.user and event.user not in self.entity_resolution:
            self.entity_resolution[event.user] = self._resolve_entity(event.user)
        
        # Add contextual tags
        if not event.tags:
            event.tags = []
        
        # Tag suspicious activities
        suspicious_keywords = ['passwd', 'shadow', 'sudo', 'su ', 'chmod 777', 'wget', 'curl', 'base64', 'eval']
        if any(keyword in event.description.lower() for keyword in suspicious_keywords):
            event.tags.append('suspicious')
            event.confidence = min(event.confidence + 0.2, 1.0)
        
        # Tag system changes
        system_keywords = ['/etc/', '/bin/', '/usr/bin/', 'registry', 'prefetch']
        if any(keyword in event.artifact.lower() for keyword in system_keywords):
            event.tags.append('system_change')
        
        return event
    
    def _resolve_entity(self, entity: str) -> Dict[str, Any]:
        """Resolve entity (user/host) information"""
        # In real implementation, this would query AD, LDAP, etc.
        return {
            'type': 'user',
            'name': entity,
            'department': 'unknown',
            'role': 'unknown'
        }
    
    def detect_attack_patterns(self) -> List[Dict[str, Any]]:
        """Detect common attack patterns in timeline"""
        patterns = []
        events = self.build_timeline()
        
        # Pattern 1: Rapid succession of file accesses
        file_access_events = [e for e in events if 'file_accessed' in e.event_type]
        for i in range(len(file_access_events) - 5):
            window = file_access_events[i:i+5]
            time_diff = window[-1].timestamp - window[0].timestamp
            if time_diff.total_seconds() < 10:  # 5 file accesses in 10 seconds
                patterns.append({
                    'pattern': 'rapid_file_access',
                    'description': 'Multiple files accessed in quick succession',
                    'events': [e.to_dict() for e in window],
                    'confidence': 0.7
                })
        
        # Pattern 2: Privilege escalation sequence
        priv_events = []
        for event in events:
            if any(keyword in event.description.lower() for keyword in ['sudo', 'su', 'runas']):
                priv_events.append(event)
        
        if len(priv_events) >= 3:
            patterns.append({
                'pattern': 'privilege_escalation_attempt',
                'description': 'Multiple privilege escalation attempts detected',
                'events': [e.to_dict() for e in priv_events[:3]],
                'confidence': 0.8
            })
        
        return patterns

def main():
    parser = argparse.ArgumentParser(description='Forensic Timeline Builder')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Build timeline command
    build_parser = subparsers.add_parser('build', help='Build forensic timeline')
    build_parser.add_argument('--case', required=True, help='Case name')
    build_parser.add_argument('--filesystem', help='Process filesystem timestamps from directory')
    build_parser.add_argument('--recursive', action='store_true', help='Recursive filesystem processing')
    build_parser.add_argument('--evtx', help='Process Windows Event Log file')
    build_parser.add_argument('--bash-history', help='Process bash history file')
    build_parser.add_argument('--apache-logs', help='Process Apache access logs')
    build_parser.add_argument('--prefetch', help='Process Windows Prefetch files')
    build_parser.add_argument('--registry', nargs='+', help='Process Windows Registry hives')
    
    # Query timeline command
    query_parser = subparsers.add_parser('query', help='Query timeline')
    query_parser.add_argument('--case', required=True, help='Case name')
    query_parser.add_argument('--start', help='Start time (YYYY-MM-DD HH:MM:SS)')
    query_parser.add_argument('--end', help='End time (YYYY-MM-DD HH:MM:SS)')
    query_parser.add_argument('--event-types', nargs='+', help='Filter by event types')
    query_parser.add_argument('--sources', nargs='+', help='Filter by sources')
    
    # Report generation command
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_parser.add_argument('--case', required=True, help='Case name')
    report_parser.add_argument('--format', choices=['html', 'csv', 'json', 'text'], default='html', help='Report format')
    report_parser.add_argument('--output', help='Output file')
    
    # Analysis command
    analysis_parser = subparsers.add_parser('analyze', help='Analyze timeline')
    analysis_parser.add_argument('--case', required=True, help='Case name')
    analysis_parser.add_argument('--correlate', action='store_true', help='Correlate events')
    analysis_parser.add_argument('--patterns', action='store_true', help='Detect attack patterns')
    
    args = parser.parse_args()
    
    if args.command == 'build':
        timeline = TimelineBuilder(args.case)
        
        if args.filesystem:
            timeline.process_filesystem_timestamps(args.filesystem, args.recursive)
        
        if args.evtx:
            timeline.parse_windows_event_logs(args.evtx)
        
        if args.bash_history:
            timeline.parse_bash_history(args.bash_history)
        
        if args.apache_logs:
            timeline.parse_apache_logs(args.apache_logs)
        
        if args.prefetch:
            timeline.parse_windows_prefetch(args.prefetch)
        
        if args.registry:
            timeline.parse_registry_hives(args.registry)
        
        print(f"Timeline building completed for case: {args.case}")
    
    elif args.command == 'query':
        timeline = TimelineBuilder(args.case)
        
        start_time = None
        end_time = None
        
        if args.start:
            start_time = datetime.strptime(args.start, '%Y-%m-%d %H:%M:%S')
        if args.end:
            end_time = datetime.strptime(args.end, '%Y-%m-%d %H:%M:%S')
        
        events = timeline.build_timeline(start_time, end_time, args.event_types, args.sources)
        
        print(f"Found {len(events)} events:")
        for event in events[:10]:  # Show first 10 events
            print(f"  {event.timestamp.isoformat()} [{event.source}] {event.description}")
        
        if len(events) > 10:
            print(f"  ... and {len(events) - 10} more events")
    
    elif args.command == 'report':
        timeline = TimelineBuilder(args.case)
        report = timeline.generate_report(args.format, args.output)
        
        if not args.output:
            print(report)
    
    elif args.command == 'analyze':
        timeline = SuperTimelineBuilder(args.case)
        
        if args.correlate:
            correlated = timeline.correlate_events()
            print(f"Found {len(correlated)} correlated event groups")
            for i, group in enumerate(correlated[:5]):  # Show first 5 groups
                print(f"Group {i+1}: {len(group)} events around {group[0].timestamp}")
        
        if args.patterns:
            patterns = timeline.detect_attack_patterns()
            print(f"Detected {len(patterns)} attack patterns:")
            for pattern in patterns:
                print(f"  {pattern['pattern']}: {pattern['description']} (confidence: {pattern['confidence']})")
        
        analysis = timeline.analyze_timeline()
        print(f"\nTimeline Analysis:")
        print(f"  Total events: {analysis['total_events']}")
        print(f"  Time range: {analysis['time_range'].get('start', 'N/A')} to {analysis['time_range'].get('end', 'N/A')}")
        print(f"  Top sources: {dict(analysis['events_by_source'])}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
