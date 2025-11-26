#!/usr/bin/env python3
"""
Host-Based Monitoring Scripts - Python Implementation
File integrity, process, and system activity monitoring
"""

import os
import sys
import hashlib
import time
import json
import psutil
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import argparse
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import grp
import pwd

class FileIntegrityMonitor:
    """File Integrity Monitoring (FIM) with real-time change detection"""
    
    def __init__(self, watch_dirs: List[str], db_path: str = "fim.db"):
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.db_path = db_path
        self.baseline_hashes = {}
        self.ignore_patterns = ['.log', '.tmp', '.swp', '.cache']
        self.init_database()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('fim_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize SQLite database for FIM data"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER,
                file_permissions TEXT,
                file_owner TEXT,
                file_group TEXT,
                last_modified REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS integrity_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                violation_type TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                old_size INTEGER,
                new_size INTEGER,
                old_permissions TEXT,
                new_permissions TEXT,
                process_name TEXT,
                user_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                severity TEXT DEFAULT 'medium'
            )
        ''')
        
        self.conn.commit()
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.error(f"Error hashing {file_path}: {e}")
            return "ERROR"
    
    def get_file_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Get comprehensive file metadata"""
        try:
            stat = file_path.stat()
            
            # Get owner and group names
            try:
                owner = pwd.getpwuid(stat.st_uid).pw_name
            except KeyError:
                owner = str(stat.st_uid)
            
            try:
                group = grp.getgrgid(stat.st_gid).gr_name
            except KeyError:
                group = str(stat.st_gid)
            
            return {
                'size': stat.st_size,
                'permissions': oct(stat.st_mode)[-3:],
                'owner': owner,
                'group': group,
                'last_modified': stat.st_mtime,
                'inode': stat.st_ino
            }
        except Exception as e:
            self.logger.error(f"Error getting metadata for {file_path}: {e}")
            return {}
    
    def should_ignore_file(self, file_path: Path) -> bool:
        """Check if file should be ignored"""
        filename = file_path.name
        
        # Check ignore patterns
        for pattern in self.ignore_patterns:
            if filename.endswith(pattern):
                return True
        
        # Ignore hidden files
        if filename.startswith('.'):
            return True
        
        return False
    
    def create_baseline(self) -> Dict[str, Any]:
        """Create initial file integrity baseline"""
        self.logger.info("Creating file integrity baseline...")
        
        baseline_stats = {
            'total_files': 0,
            'total_size': 0,
            'start_time': datetime.now().isoformat(),
            'directories': []
        }
        
        cursor = self.conn.cursor()
        
        for watch_dir in self.watch_dirs:
            if not watch_dir.exists():
                self.logger.warning(f"Watch directory does not exist: {watch_dir}")
                continue
            
            dir_stats = {
                'path': str(watch_dir),
                'files': 0,
                'size': 0
            }
            
            for file_path in watch_dir.rglob('*'):
                if file_path.is_file() and not self.should_ignore_file(file_path):
                    try:
                        file_hash = self.calculate_file_hash(file_path)
                        metadata = self.get_file_metadata(file_path)
                        
                        # Store in database
                        cursor.execute('''
                            INSERT OR REPLACE INTO file_baseline 
                            (file_path, file_hash, file_size, file_permissions, file_owner, file_group, last_modified)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            str(file_path), file_hash, metadata.get('size'),
                            metadata.get('permissions'), metadata.get('owner'),
                            metadata.get('group'), metadata.get('last_modified')
                        ))
                        
                        # Store in memory
                        self.baseline_hashes[str(file_path)] = {
                            'hash': file_hash,
                            'metadata': metadata
                        }
                        
                        baseline_stats['total_files'] += 1
                        baseline_stats['total_size'] += metadata.get('size', 0)
                        dir_stats['files'] += 1
                        dir_stats['size'] += metadata.get('size', 0)
                        
                    except Exception as e:
                        self.logger.error(f"Error processing {file_path}: {e}")
            
            baseline_stats['directories'].append(dir_stats)
        
        self.conn.commit()
        baseline_stats['end_time'] = datetime.now().isoformat()
        
        self.logger.info(f"Baseline created: {baseline_stats['total_files']} files")
        return baseline_stats
    
    def check_integrity(self) -> List[Dict[str, Any]]:
        """Check current file state against baseline"""
        violations = []
        
        self.logger.info("Running integrity check...")
        
        # Check existing files
        for file_path_str, baseline_data in self.baseline_hashes.items():
            file_path = Path(file_path_str)
            
            if not file_path.exists():
                # File deleted
                violation = {
                    'file_path': file_path_str,
                    'violation_type': 'file_deleted',
                    'old_hash': baseline_data['hash'],
                    'old_size': baseline_data['metadata'].get('size'),
                    'old_permissions': baseline_data['metadata'].get('permissions'),
                    'severity': 'high'
                }
                violations.append(violation)
                self._record_violation(violation)
                continue
            
            try:
                current_hash = self.calculate_file_hash(file_path)
                current_metadata = self.get_file_metadata(file_path)
                
                # Check hash
                if current_hash != baseline_data['hash']:
                    violation = {
                        'file_path': file_path_str,
                        'violation_type': 'content_modified',
                        'old_hash': baseline_data['hash'],
                        'new_hash': current_hash,
                        'old_size': baseline_data['metadata'].get('size'),
                        'new_size': current_metadata.get('size'),
                        'severity': 'high'
                    }
                    violations.append(violation)
                    self._record_violation(violation)
                
                # Check permissions
                if current_metadata.get('permissions') != baseline_data['metadata'].get('permissions'):
                    violation = {
                        'file_path': file_path_str,
                        'violation_type': 'permissions_changed',
                        'old_permissions': baseline_data['metadata'].get('permissions'),
                        'new_permissions': current_metadata.get('permissions'),
                        'severity': 'medium'
                    }
                    violations.append(violation)
                    self._record_violation(violation)
                
                # Check ownership
                if (current_metadata.get('owner') != baseline_data['metadata'].get('owner') or
                    current_metadata.get('group') != baseline_data['metadata'].get('group')):
                    violation = {
                        'file_path': file_path_str,
                        'violation_type': 'ownership_changed',
                        'old_owner': baseline_data['metadata'].get('owner'),
                        'new_owner': current_metadata.get('owner'),
                        'old_group': baseline_data['metadata'].get('group'),
                        'new_group': current_metadata.get('group'),
                        'severity': 'high'
                    }
                    violations.append(violation)
                    self._record_violation(violation)
            
            except Exception as e:
                self.logger.error(f"Error checking {file_path}: {e}")
        
        # Check for new files
        for watch_dir in self.watch_dirs:
            for file_path in watch_dir.rglob('*'):
                if (file_path.is_file() and not self.should_ignore_file(file_path) and
                    str(file_path) not in self.baseline_hashes):
                    
                    violation = {
                        'file_path': str(file_path),
                        'violation_type': 'new_file',
                        'severity': 'low'
                    }
                    violations.append(violation)
                    self._record_violation(violation)
        
        self.logger.info(f"Integrity check completed: {len(violations)} violations found")
        return violations
    
    def _record_violation(self, violation: Dict[str, Any]):
        """Record violation in database"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT INTO integrity_violations 
            (file_path, violation_type, old_hash, new_hash, old_size, new_size, 
             old_permissions, new_permissions, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            violation['file_path'],
            violation['violation_type'],
            violation.get('old_hash'),
            violation.get('new_hash'),
            violation.get('old_size'),
            violation.get('new_size'),
            violation.get('old_permissions'),
            violation.get('new_permissions'),
            violation.get('severity', 'medium')
        ))
        
        self.conn.commit()
        
        # Log the violation
        self.logger.warning(
            f"FIM Violation: {violation['violation_type']} - {violation['file_path']} "
            f"(Severity: {violation.get('severity', 'medium')})"
        )
    
    def real_time_monitor(self):
        """Start real-time file monitoring"""
        self.logger.info("Starting real-time file monitoring...")
        
        event_handler = FIMEventHandler(self)
        observer = Observer()
        
        for watch_dir in self.watch_dirs:
            if watch_dir.exists():
                observer.schedule(event_handler, str(watch_dir), recursive=True)
        
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        
        observer.join()

class FIMEventHandler(FileSystemEventHandler):
    """Watchdog event handler for real-time FIM"""
    
    def __init__(self, fim_monitor: FileIntegrityMonitor):
        self.fim_monitor = fim_monitor
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if self.fim_monitor.should_ignore_file(file_path):
            return
        
        # Check if file is in baseline
        if str(file_path) in self.fim_monitor.baseline_hashes:
            self.fim_monitor.logger.info(f"File modified: {file_path}")
            # Trigger integrity check for this file
            threading.Thread(target=self._check_single_file, args=(file_path,)).start()
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if self.fim_monitor.should_ignore_file(file_path):
            return
        
        self.fim_monitor.logger.info(f"New file created: {file_path}")
        
        violation = {
            'file_path': str(file_path),
            'violation_type': 'new_file',
            'severity': 'low'
        }
        self.fim_monitor._record_violation(violation)
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if str(file_path) in self.fim_monitor.baseline_hashes:
            self.fim_monitor.logger.warning(f"File deleted: {file_path}")
            
            baseline_data = self.fim_monitor.baseline_hashes[str(file_path)]
            violation = {
                'file_path': str(file_path),
                'violation_type': 'file_deleted',
                'old_hash': baseline_data['hash'],
                'old_size': baseline_data['metadata'].get('size'),
                'severity': 'high'
            }
            self.fim_monitor._record_violation(violation)
    
    def _check_single_file(self, file_path: Path):
        """Check integrity of a single file"""
        try:
            baseline_data = self.fim_monitor.baseline_hashes.get(str(file_path))
            if not baseline_data:
                return
            
            current_hash = self.fim_monitor.calculate_file_hash(file_path)
            current_metadata = self.fim_monitor.get_file_metadata(file_path)
            
            if current_hash != baseline_data['hash']:
                violation = {
                    'file_path': str(file_path),
                    'violation_type': 'content_modified',
                    'old_hash': baseline_data['hash'],
                    'new_hash': current_hash,
                    'old_size': baseline_data['metadata'].get('size'),
                    'new_size': current_metadata.get('size'),
                    'severity': 'high'
                }
                self.fim_monitor._record_violation(violation)
        
        except Exception as e:
            self.fim_monitor.logger.error(f"Error checking single file {file_path}: {e}")

class ProcessMonitor:
    """Monitor process creation and termination"""
    
    def __init__(self, db_path: str = "process_monitor.db"):
        self.db_path = db_path
        self.known_processes = set()
        self.suspicious_processes = [
            'nc', 'netcat', 'socat', 'ncat', 'wget', 'curl',
            'sh', 'bash', 'dash', 'zsh', 'ksh', 'python', 'perl',
            'php', 'ruby', 'lua', 'nc.traditional'
        ]
        self.init_database()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler('process_monitor.log')]
        )
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize process monitoring database"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                parent_pid INTEGER,
                command_line TEXT,
                username TEXT,
                event_type TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                severity TEXT DEFAULT 'low'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                command_line TEXT,
                username TEXT,
                reason TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def get_current_processes(self) -> Dict[int, Dict[str, Any]]:
        """Get current running processes"""
        processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'username', 'cmdline']):
            try:
                info = proc.info
                processes[info['pid']] = {
                    'name': info['name'],
                    'ppid': info['ppid'],
                    'username': info['username'],
                    'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else info['name']
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def monitor_processes(self, interval: int = 5):
        """Monitor process changes"""
        self.logger.info("Starting process monitoring...")
        
        # Get initial process list
        current_processes = self.get_current_processes()
        self.known_processes = set(current_processes.keys())
        
        # Record initial processes
        for pid, info in current_processes.items():
            self._record_process_event(pid, info, 'startup')
        
        while True:
            try:
                time.sleep(interval)
                
                new_processes = self.get_current_processes()
                current_pids = set(new_processes.keys())
                
                # Find new processes
                new_pids = current_pids - self.known_processes
                for pid in new_pids:
                    info = new_processes[pid]
                    self._record_process_event(pid, info, 'started')
                    
                    # Check for suspicious processes
                    self._check_suspicious_process(pid, info)
                
                # Find terminated processes
                terminated_pids = self.known_processes - current_pids
                for pid in terminated_pids:
                    # We don't have current info for terminated processes
                    self._record_process_event(pid, {}, 'terminated')
                
                self.known_processes = current_pids
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error in process monitoring: {e}")
    
    def _record_process_event(self, pid: int, info: Dict[str, Any], event_type: str):
        """Record process event in database"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT INTO process_events 
            (pid, process_name, parent_pid, command_line, username, event_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            pid,
            info.get('name', 'unknown'),
            info.get('ppid'),
            info.get('cmdline', ''),
            info.get('username', 'unknown'),
            event_type
        ))
        
        self.conn.commit()
        
        self.logger.info(f"Process {event_type}: {info.get('name', 'unknown')} (PID: {pid})")
    
    def _check_suspicious_process(self, pid: int, info: Dict[str, Any]):
        """Check if process is suspicious"""
        process_name = info.get('name', '').lower()
        cmdline = info.get('cmdline', '').lower()
        
        suspicious_reasons = []
        
        # Check process name
        for suspicious in self.suspicious_processes:
            if suspicious in process_name or suspicious in cmdline:
                suspicious_reasons.append(f"Suspicious process name: {suspicious}")
        
        # Check for network tools with suspicious patterns
        if any(tool in cmdline for tool in ['/dev/tcp/', '/dev/udp/', 'bash -i']):
            suspicious_reasons.append("Potential reverse shell detected")
        
        # Check for encoded commands
        if any(indicator in cmdline for indicator in ['base64', 'eval', 'exec', 'decode']):
            suspicious_reasons.append("Encoded or evaled command detected")
        
        if suspicious_reasons:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT INTO suspicious_processes 
                (pid, process_name, command_line, username, reason)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                pid,
                info.get('name', 'unknown'),
                info.get('cmdline', ''),
                info.get('username', 'unknown'),
                '; '.join(suspicious_reasons)
            ))
            
            self.conn.commit()
            
            self.logger.warning(
                f"SUSPICIOUS PROCESS: {info.get('name')} (PID: {pid}) - "
                f"Reasons: {suspicious_reasons}"
            )

class SystemActivityMonitor:
    """Monitor system activities and changes"""
    
    def __init__(self, db_path: str = "system_monitor.db"):
        self.db_path = db_path
        self.init_database()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler('system_monitor.log')]
        )
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize system activity database"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                session_type TEXT,
                source_ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                change_type TEXT NOT NULL,
                target TEXT,
                old_value TEXT,
                new_value TEXT,
                username TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT,
                local_address TEXT,
                remote_address TEXT,
                status TEXT,
                pid INTEGER,
                process_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def monitor_user_logins(self, interval: int = 30):
        """Monitor user login activity"""
        self.logger.info("Starting user login monitoring...")
        
        last_check = datetime.now()
        
        while True:
            try:
                time.sleep(interval)
                
                # Check current logged in users (simplified)
                try:
                    # This would use 'who' command or similar in real implementation
                    current_users = self._get_logged_in_users()
                    
                    for user in current_users:
                        cursor = self.conn.cursor()
                        cursor.execute('''
                            INSERT INTO user_sessions (username, session_type, source_ip)
                            VALUES (?, ?, ?)
                        ''', (user['username'], user['session_type'], user.get('source_ip')))
                        self.conn.commit()
                        
                        self.logger.info(f"User session: {user['username']} from {user.get('source_ip', 'local')}")
                
                except Exception as e:
                    self.logger.error(f"Error monitoring user logins: {e}")
                
                # Monitor network connections periodically
                self._monitor_network_connections()
                
            except KeyboardInterrupt:
                break
    
    def _get_logged_in_users(self) -> List[Dict[str, Any]]:
        """Get currently logged in users (simplified implementation)"""
        users = []
        
        try:
            # Use 'who' command to get logged in users
            import subprocess
            result = subprocess.run(['who'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        users.append({
                            'username': parts[0],
                            'session_type': 'terminal',
                            'source_ip': parts[2] if '@' in parts[2] else 'local'
                        })
        
        except Exception as e:
            self.logger.error(f"Error getting logged in users: {e}")
        
        return users
    
    def _monitor_network_connections(self):
        """Monitor network connections"""
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    cursor = self.conn.cursor()
                    
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    
                    process_name = "unknown"
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except psutil.NoSuchProcess:
                            process_name = "terminated"
                    
                    cursor.execute('''
                        INSERT INTO network_connections 
                        (protocol, local_address, remote_address, status, pid, process_name)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        conn.type,
                        local_addr,
                        remote_addr,
                        conn.status,
                        conn.pid,
                        process_name
                    ))
            
            self.conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error monitoring network connections: {e}")
    
    def monitor_system_changes(self, interval: int = 60):
        """Monitor system configuration changes"""
        self.logger.info("Starting system change monitoring...")
        
        # Track initial state of important files
        important_files = [
            '/etc/passwd',
            '/etc/group',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/hosts.allow',
            '/etc/hosts.deny',
            '/etc/crontab',
            '/etc/sudoers'
        ]
        
        file_hashes = {}
        for file_path in important_files:
            if os.path.exists(file_path):
                file_hashes[file_path] = self._calculate_file_hash(Path(file_path))
        
        while True:
            try:
                time.sleep(interval)
                
                # Check for changes in important files
                for file_path in important_files:
                    if os.path.exists(file_path):
                        current_hash = self._calculate_file_hash(Path(file_path))
                        old_hash = file_hashes.get(file_path)
                        
                        if old_hash and current_hash != old_hash:
                            self.logger.warning(f"Important file changed: {file_path}")
                            
                            cursor = self.conn.cursor()
                            cursor.execute('''
                                INSERT INTO system_changes 
                                (change_type, target, old_value, new_value)
                                VALUES (?, ?, ?, ?)
                            ''', (
                                'file_modified',
                                file_path,
                                f"Hash: {old_hash}",
                                f"Hash: {current_hash}"
                            ))
                            self.conn.commit()
                            
                            file_hashes[file_path] = current_hash
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error monitoring system changes: {e}")
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate file hash"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "ERROR"

def main():
    parser = argparse.ArgumentParser(description='Host-Based Monitoring Scripts')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # FIM commands
    fim_parser = subparsers.add_parser('fim', help='File Integrity Monitoring')
    fim_parser.add_argument('--create-baseline', action='store_true', help='Create FIM baseline')
    fim_parser.add_argument('--check-integrity', action='store_true', help='Check file integrity')
    fim_parser.add_argument('--real-time', action='store_true', help='Start real-time monitoring')
    fim_parser.add_argument('--watch-dirs', nargs='+', default=['/etc', '/bin', '/usr/bin'], 
                           help='Directories to monitor')
    fim_parser.add_argument('--db-path', default='fim.db', help='FIM database path')
    
    # Process monitoring commands
    process_parser = subparsers.add_parser('process', help='Process Monitoring')
    process_parser.add_argument('--monitor', action='store_true', help='Start process monitoring')
    process_parser.add_argument('--interval', type=int, default=5, help='Monitoring interval in seconds')
    process_parser.add_argument('--db-path', default='process_monitor.db', help='Process database path')
    
    # System monitoring commands
    system_parser = subparsers.add_parser('system', help='System Activity Monitoring')
    system_parser.add_argument('--monitor-logins', action='store_true', help='Monitor user logins')
    system_parser.add_argument('--monitor-changes', action='store_true', help='Monitor system changes')
    system_parser.add_argument('--interval', type=int, default=30, help='Monitoring interval in seconds')
    system_parser.add_argument('--db-path', default='system_monitor.db', help='System database path')
    
    args = parser.parse_args()
    
    if args.command == 'fim':
        fim = FileIntegrityMonitor(args.watch_dirs, args.db_path)
        
        if args.create_baseline:
            baseline = fim.create_baseline()
            print(f"Baseline created: {baseline['total_files']} files")
        
        if args.check_integrity:
            violations = fim.check_integrity()
            print(f"Integrity check completed: {len(violations)} violations")
            for violation in violations[:10]:  # Show first 10
                print(f"  - {violation['violation_type']}: {violation['file_path']}")
        
        if args.real_time:
            fim.real_time_monitor()
    
    elif args.command == 'process':
        process_monitor = ProcessMonitor(args.db_path)
        
        if args.monitor:
            process_monitor.monitor_processes(args.interval)
    
    elif args.command == 'system':
        system_monitor = SystemActivityMonitor(args.db_path)
        
        if args.monitor_logins:
            system_monitor.monitor_user_logins(args.interval)
        
        if args.monitor_changes:
            system_monitor.monitor_system_changes(args.interval)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
