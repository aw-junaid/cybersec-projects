import os
import time
import threading
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Callable, List, Dict, Any
import hashlib

logger = logging.getLogger(__name__)

class FileCollector:
    """Collect logs from files and directories"""
    
    def __init__(self, config: Dict[str, Any], callback: Callable):
        self.config = config
        self.callback = callback
        self.observer = Observer()
        self.watched_paths = {}
        self.file_positions = {}
        self.running = False
        
    def start(self):
        """Start file collection"""
        logger.info("Starting file collector...")
        self.running = True
        
        # Start watching configured paths
        watch_paths = self.config.get("watch_paths", [])
        for watch_config in watch_paths:
            self._add_watch_path(watch_config)
        
        # Start observer
        self.observer.start()
        
        # Start tailing existing files
        self._tail_existing_files()
        
        logger.info("File collector started")
    
    def stop(self):
        """Stop file collection"""
        logger.info("Stopping file collector...")
        self.running = False
        self.observer.stop()
        self.observer.join()
        logger.info("File collector stopped")
    
    def _add_watch_path(self, watch_config: Dict[str, Any]):
        """Add a path to watch for file changes"""
        path = Path(watch_config["path"])
        if not path.exists():
            logger.warning(f"Watch path does not exist: {path}")
            return
        
        patterns = watch_config.get("patterns", ["*.log"])
        recursive = watch_config.get("recursive", True)
        
        event_handler = LogFileHandler(
            patterns=patterns,
            callback=self._handle_file_event,
            config=watch_config
        )
        
        self.observer.schedule(event_handler, str(path), recursive=recursive)
        self.watched_paths[str(path)] = watch_config
        
        logger.info(f"Watching path: {path} (patterns: {patterns}, recursive: {recursive})")
    
    def _tail_existing_files(self):
        """Tail existing files in watched paths"""
        for watch_path, config in self.watched_paths.items():
            path = Path(watch_path)
            patterns = config.get("patterns", ["*.log"])
            
            for pattern in patterns:
                if path.is_dir():
                    files = path.rglob(pattern) if config.get("recursive", True) else path.glob(pattern)
                else:
                    files = [path] if path.match(pattern) else []
                
                for file_path in files:
                    if file_path.is_file():
                        self._tail_file(file_path, config)
    
    def _tail_file(self, file_path: Path, config: Dict[str, Any]):
        """Tail a specific file"""
        try:
            file_key = str(file_path)
            
            # Get current file size
            current_size = file_path.stat().st_size
            
            # Check if we need to read from beginning or continue from last position
            if file_key in self.file_positions:
                last_position = self.file_positions[file_key]
                if current_size < last_position:
                    # File was rotated, start from beginning
                    last_position = 0
            else:
                # New file, start from beginning or end based on configuration
                if config.get("read_from_beginning", False):
                    last_position = 0
                else:
                    last_position = current_size
            
            # Read new content
            if current_size > last_position:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_position)
                    content = f.read()
                    
                    if content:
                        lines = content.splitlines()
                        for line in lines:
                            if line.strip():
                                self._process_log_line(line, file_path, config)
                    
                    # Update position
                    self.file_positions[file_key] = f.tell()
            
        except Exception as e:
            logger.error(f"Error tailing file {file_path}: {e}")
    
    def _handle_file_event(self, event):
        """Handle file system events"""
        if not self.running:
            return
        
        try:
            file_path = Path(event.src_path)
            
            if event.event_type == 'created' or event.event_type == 'modified':
                # Find matching watch configuration
                watch_config = None
                for watch_path, config in self.watched_paths.items():
                    if str(file_path).startswith(watch_path):
                        patterns = config.get("patterns", [])
                        if any(file_path.match(pattern) for pattern in patterns):
                            watch_config = config
                            break
                
                if watch_config:
                    self._tail_file(file_path, watch_config)
            
            elif event.event_type == 'deleted':
                # Remove from tracked files
                file_key = str(file_path)
                if file_key in self.file_positions:
                    del self.file_positions[file_key]
                    
        except Exception as e:
            logger.error(f"Error handling file event: {e}")
    
    def _process_log_line(self, line: str, file_path: Path, config: Dict[str, Any]):
        """Process a single log line"""
        try:
            log_entry = {
                "raw_message": line,
                "file_path": str(file_path),
                "source_type": "file",
                "collector_config": config.get("name", "file_collector"),
                "timestamp": time.time()
            }
            
            # Add file-specific metadata
            log_entry.update(self._get_file_metadata(file_path, config))
            
            # Call callback with log entry
            self.callback(log_entry)
            
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
    
    def _get_file_metadata(self, file_path: Path, config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from file path"""
        metadata = {
            "file_name": file_path.name,
            "file_directory": str(file_path.parent),
            "log_type": config.get("log_type", "unknown")
        }
        
        # Extract additional metadata from file path patterns
        path_patterns = config.get("path_patterns", {})
        for field, pattern in path_patterns.items():
            match = pattern.match(str(file_path))
            if match:
                metadata.update(match.groupdict())
        
        return metadata

class LogFileHandler(FileSystemEventHandler):
    """Watchdog event handler for log files"""
    
    def __init__(self, patterns: List[str], callback: Callable, config: Dict[str, Any]):
        self.patterns = patterns
        self.callback = callback
        self.config = config
    
    def on_created(self, event):
        if not event.is_directory:
            self.callback(event)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.callback(event)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.callback(event)
    
    def on_moved(self, event):
        if not event.is_directory:
            # Treat move as delete + create
            delete_event = type('Event', (), {'src_path': event.src_path, 'event_type': 'deleted'})()
            create_event = type('Event', (), {'src_path': event.dest_path, 'event_type': 'created'})()
            
            self.callback(delete_event)
            self.callback(create_event)
