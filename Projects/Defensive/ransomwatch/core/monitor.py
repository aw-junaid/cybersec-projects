"""
File System Monitor
Monitors file system for suspicious activity patterns
"""

import os
import time
import logging
from threading import Thread, Lock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.entropy import calculate_entropy, calculate_entropy_fast

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, rules_engine, alert_manager, honeyfile_manager):
        self.rules_engine = rules_engine
        self.alert_manager = alert_manager
        self.honeyfile_manager = honeyfile_manager
        self.logger = logging.getLogger("FileMonitor")
        self.file_operations = {}
        self.lock = Lock()
        
        # Track recent operations for rate analysis
        self.operation_window = 10  # seconds
        self.operations = []
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self._analyze_file_event(event.src_path, "MODIFIED")
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._analyze_file_event(event.src_path, "CREATED")
    
    def on_deleted(self, event):
        """Handle file deletion events"""
        if not event.is_directory:
            self._analyze_file_event(event.src_path, "DELETED")
    
    def on_moved(self, event):
        """Handle file move/rename events"""
        if not event.is_directory:
            self._analyze_file_event(event.dest_path, "MOVED")
            # Check if this looks like encryption pattern (.txt -> .encrypted)
            if self._is_encryption_pattern(event.src_path, event.dest_path):
                self.logger.warning(f"Possible encryption pattern: {event.src_path} -> {event.dest_path}")
    
    def _is_encryption_pattern(self, src_path, dest_path):
        """Detect file extension changes that suggest encryption"""
        src_ext = os.path.splitext(src_path)[1].lower()
        dest_ext = os.path.splitext(dest_path)[1].lower()
        
        encryption_patterns = [
            ('.txt', '.encrypted'), ('.doc', '.locked'), 
            ('.pdf', '.crypted'), ('.jpg', '.encrypt')
        ]
        
        return (src_ext, dest_ext) in encryption_patterns
    
    def _analyze_file_event(self, file_path, operation):
        """Analyze file event for suspicious patterns"""
        try:
            # Skip system files and temporary files
            if self._should_skip_file(file_path):
                return
            
            # Check honeyfile modification
            if self.honeyfile_manager.is_honeyfile(file_path):
                self.alert_manager.alert(
                    "CRITICAL", 
                    f"Honeyfile modified: {file_path}",
                    {"file_path": file_path, "operation": operation}
                )
                return
            
            # Track operation rate
            self._track_operation_rate(operation, file_path)
            
            # Analyze file if it exists and is modified
            if operation == "MODIFIED" and os.path.exists(file_path):
                self._analyze_file_content(file_path)
            
            # Check for rapid file operations
            if self._is_high_frequency_operation():
                self.alert_manager.alert(
                    "HIGH",
                    "High frequency file operations detected",
                    {"operations": self.operations[-10:], "count": len(self.operations)}
                )
        
        except Exception as e:
            self.logger.error(f"Error analyzing file event: {e}")
    
    def _should_skip_file(self, file_path):
        """Skip certain file types/paths"""
        skip_patterns = ['.log', '.tmp', '/proc/', '/sys/']
        return any(pattern in file_path for pattern in skip_patterns)
    
    def _track_operation_rate(self, operation, file_path):
        """Track operation rate for anomaly detection"""
        current_time = time.time()
        self.operations.append((current_time, operation, file_path))
        
        # Remove operations outside our time window
        cutoff_time = current_time - self.operation_window
        self.operations = [op for op in self.operations if op[0] > cutoff_time]
    
    def _is_high_frequency_operation(self):
        """Check if operation frequency is suspiciously high"""
        if len(self.operations) > 50:  # More than 5 ops/sec average
            return True
        return False
    
    def _analyze_file_content(self, file_path):
        """Analyze file content for encryption patterns"""
        try:
            # Check file size - skip very large files
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB
                return
            
            # Calculate entropy (use fast C version if available)
            try:
                entropy = calculate_entropy_fast(file_path)
            except:
                entropy = calculate_entropy(file_path)
            
            # Check for high entropy (encrypted content)
            if entropy > 7.5:  # High entropy threshold
                self.rules_engine.evaluate_file_entropy(
                    file_path, entropy, os.path.getpid()
                )
        
        except (OSError, IOError) as e:
            # File might be deleted or inaccessible
            pass

class FileMonitor:
    def __init__(self, watch_paths, rules_engine, alert_manager, honeyfile_manager):
        self.watch_paths = watch_paths
        self.rules_engine = rules_engine
        self.alert_manager = alert_manager
        self.honeyfile_manager = honeyfile_manager
        self.observer = Observer()
        self.logger = logging.getLogger("FileMonitor")
        
        self.handler = FileMonitorHandler(
            rules_engine, alert_manager, honeyfile_manager
        )
    
    def start(self):
        """Start file system monitoring"""
        try:
            for path in self.watch_paths:
                if os.path.exists(path):
                    self.observer.schedule(self.handler, path, recursive=True)
                    self.logger.info(f"Monitoring path: {path}")
                else:
                    self.logger.warning(f"Watch path does not exist: {path}")
            
            self.observer.start()
            self.logger.info("File system monitoring started")
        except Exception as e:
            self.logger.error(f"Failed to start file monitor: {e}")
    
    def stop(self):
        """Stop file system monitoring"""
        self.observer.stop()
        self.observer.join()
        self.logger.info("File system monitoring stopped")
