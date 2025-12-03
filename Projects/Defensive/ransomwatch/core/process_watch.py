"""
Process Monitoring Component
Detect suspicious processes and behavior patterns
"""

import os
import psutil
import time
import logging
from threading import Thread, Event

class ProcessWatcher:
    def __init__(self, rules_engine, alert_manager, scan_interval=5):
        self.rules_engine = rules_engine
        self.alert_manager = alert_manager
        self.scan_interval = scan_interval
        self.shutdown_event = Event()
        self.logger = logging.getLogger("ProcessWatcher")
        self.known_suspicious_processes = set()
        
    def start(self):
        """Start process monitoring"""
        self.monitor_thread = Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.logger.info("Process monitoring started")
    
    def stop(self):
        """Stop process monitoring"""
        self.shutdown_event.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Process monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while not self.shutdown_event.is_set():
            try:
                self._scan_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Error in process monitor: {e}")
                time.sleep(self.scan_interval)
    
    def _scan_processes(self):
        """Scan running processes for suspicious activity"""
        suspicious_patterns = [
            'vssadmin', 'wbadmin', 'bcedit', 'shadowcopy',
            'wscript', 'cscript', 'powershell', 'certutil',
            'bitsadmin', 'mshta', 'rundll32'
        ]
        
        encryption_keywords = [
            'aes', 'des', 'rsa', 'crypto', 'encrypt', 'decrypt',
            'ransom', 'locker', 'cryptolocker'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                process_info = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'create_time': proc.info['create_time']
                }
                
                # Check for suspicious process names
                proc_name = process_info['name'].lower()
                cmdline = process_info['cmdline'].lower()
                
                # Pattern 1: Known suspicious processes
                for pattern in suspicious_patterns:
                    if pattern in proc_name or pattern in cmdline:
                        if proc.info['pid'] not in self.known_suspicious_processes:
                            self.known_suspicious_processes.add(proc.info['pid'])
                            self.alert_manager.alert(
                                "MEDIUM",
                                f"Suspicious process detected: {proc_name}",
                                process_info
                            )
                
                # Pattern 2: Encryption-related commands
                for keyword in encryption_keywords:
                    if keyword in cmdline:
                        self.alert_manager.alert(
                            "HIGH",
                            f"Encryption-related process detected: {proc_name}",
                            {"keyword": keyword, **process_info}
                        )
                
                # Pattern 3: Process spawning unusual children
                self._check_process_children(proc)
                
                # Send to rules engine for comprehensive evaluation
                self.rules_engine.evaluate_process(process_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def _check_process_children(self, parent_proc):
        """Check for suspicious process hierarchies"""
        try:
            children = parent_proc.children()
            if len(children) > 5:  # Unusually high number of children
                child_names = [child.name() for child in children]
                self.alert_manager.alert(
                    "LOW",
                    f"Process spawning many children: {parent_proc.name()}",
                    {"parent": parent_proc.name(), "children": child_names}
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def kill_suspicious_process(self, pid):
        """Kill a suspicious process (safe mode only)"""
        if os.environ.get('SAFE_MODE') != 'true':
            self.logger.warning("Safe mode not enabled, cannot kill process")
            return False
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            self.logger.info(f"Terminated suspicious process: {pid}")
            return True
        except psutil.NoSuchProcess:
            self.logger.warning(f"Process {pid} no longer exists")
            return False
        except psutil.AccessDenied:
            self.logger.error(f"Access denied killing process {pid}")
            return False
