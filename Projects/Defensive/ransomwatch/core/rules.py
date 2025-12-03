"""
Rules Engine
Evaluate detection rules and trigger alerts
"""

import yaml
import time
import logging
from collections import defaultdict, deque

class RulesEngine:
    def __init__(self, rules_file, alert_manager):
        self.rules_file = rules_file
        self.alert_manager = alert_manager
        self.logger = logging.getLogger("RulesEngine")
        self.rules = self.load_rules()
        
        # State tracking for correlation
        self.recent_events = deque(maxlen=1000)
        self.entropy_events = defaultdict(list)
        self.process_events = defaultdict(list)
    
    def load_rules(self):
        """Load detection rules from YAML file"""
        default_rules = {
            'high_entropy_surge': {
                'enabled': True,
                'threshold': 10,
                'time_window': 60,
                'severity': 'HIGH'
            },
            'rapid_file_operations': {
                'enabled': True,
                'threshold': 100,
                'time_window': 10,
                'severity': 'MEDIUM'
            },
            'suspicious_process_chain': {
                'enabled': True,
                'patterns': ['powershell', 'certutil', 'bitsadmin'],
                'severity': 'HIGH'
            },
            'honeyfile_modification': {
                'enabled': True,
                'severity': 'CRITICAL'
            }
        }
        
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    return yaml.safe_load(f)
            else:
                self._create_default_rules()
                return default_rules
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            return default_rules
    
    def _create_default_rules(self):
        """Create default rules file"""
        os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
        default_rules = {
            'rules': {
                'high_entropy_surge': {
                    'enabled': True,
                    'threshold': 10,
                    'time_window': 60,
                    'severity': 'HIGH',
                    'description': 'Multiple high entropy files created in short time'
                },
                'rapid_file_operations': {
                    'enabled': True,
                    'threshold': 100,
                    'time_window': 10,
                    'severity': 'MEDIUM',
                    'description': 'Rapid file modifications suggesting encryption'
                },
                'suspicious_process_chain': {
                    'enabled': True,
                    'patterns': ['powershell', 'certutil', 'bitsadmin'],
                    'severity': 'HIGH',
                    'description': 'Suspicious process execution patterns'
                },
                'honeyfile_modification': {
                    'enabled': True,
                    'severity': 'CRITICAL',
                    'description': 'Honeyfile modification or deletion'
                }
            }
        }
        
        with open(self.rules_file, 'w') as f:
            yaml.dump(default_rules, f, default_flow_style=False)
    
    def evaluate_file_entropy(self, file_path, entropy, pid):
        """Evaluate file entropy against rules"""
        current_time = time.time()
        
        # Store entropy event
        self.entropy_events[pid].append((current_time, file_path, entropy))
        
        # Clean old events
        cutoff_time = current_time - 300  # 5 minutes
        for pid in list(self.entropy_events.keys()):
            self.entropy_events[pid] = [
                event for event in self.entropy_events[pid] 
                if event[0] > cutoff_time
            ]
            if not self.entropy_events[pid]:
                del self.entropy_events[pid]
        
        # Check for high entropy surge
        if self.rules['high_entropy_surge']['enabled']:
            self._check_entropy_surge(pid)
        
        # Individual high entropy file
        if entropy > 7.8:
            self.alert_manager.alert(
                "MEDIUM",
                f"High entropy file detected: {file_path}",
                {
                    "file_path": file_path,
                    "entropy": entropy,
                    "pid": pid,
                    "rule": "high_entropy_file"
                }
            )
    
    def _check_entropy_surge(self, pid):
        """Check for surge in high entropy files"""
        if pid not in self.entropy_events:
            return
        
        events = self.entropy_events[pid]
        time_window = self.rules['high_entropy_surge']['time_window']
        threshold = self.rules['high_entropy_surge']['threshold']
        
        current_time = time.time()
        recent_high_entropy = [
            event for event in events
            if event[0] > current_time - time_window and event[2] > 7.0
        ]
        
        if len(recent_high_entropy) >= threshold:
            self.alert_manager.alert(
                self.rules['high_entropy_surge']['severity'],
                f"High entropy surge detected from process {pid}",
                {
                    "pid": pid,
                    "high_entropy_files": len(recent_high_entropy),
                    "time_window": time_window,
                    "rule": "high_entropy_surge"
                }
            )
    
    def evaluate_process(self, process_info):
        """Evaluate process against detection rules"""
        current_time = time.time()
        
        # Store process event
        self.process_events[process_info['pid']].append((current_time, process_info))
        
        # Check for suspicious process chains
        if self.rules['suspicious_process_chain']['enabled']:
            self._check_suspicious_process_chain(process_info)
    
    def _check_suspicious_process_chain(self, process_info):
        """Check for suspicious process execution patterns"""
        cmdline = process_info['cmdline'].lower()
        
        suspicious_patterns = self.rules['suspicious_process_chain']['patterns']
        detected_patterns = []
        
        for pattern in suspicious_patterns:
            if pattern in cmdline:
                detected_patterns.append(pattern)
        
        if detected_patterns:
            self.alert_manager.alert(
                self.rules['suspicious_process_chain']['severity'],
                f"Suspicious process pattern detected: {process_info['name']}",
                {
                    "pid": process_info['pid'],
                    "process_name": process_info['name'],
                    "cmdline": process_info['cmdline'],
                    "detected_patterns": detected_patterns,
                    "rule": "suspicious_process_chain"
                }
            )
    
    def evaluate_rapid_operations(self, operations):
        """Evaluate rapid file operations"""
        if self.rules['rapid_file_operations']['enabled']:
            threshold = self.rules['rapid_file_operations']['threshold']
            time_window = self.rules['rapid_file_operations']['time_window']
            
            if len(operations) >= threshold:
                self.alert_manager.alert(
                    self.rules['rapid_file_operations']['severity'],
                    f"Rapid file operations detected: {len(operations)} in {time_window}s",
                    {
                        "operation_count": len(operations),
                        "time_window": time_window,
                        "rule": "rapid_file_operations"
                    }
                )
