#!/usr/bin/env python3
"""
RansomWatch Main Entry Point
Complete ransomware detection and prevention system
"""

import os
import sys
import time
import signal
import logging
import argparse
from threading import Event
from core.monitor import FileMonitor
from core.process_watch import ProcessWatcher
from core.honeyfile import HoneyfileManager
from core.rules import RulesEngine
from core.alert import AlertManager

class RansomWatch:
    def __init__(self, config_path="config/config.json"):
        self.shutdown_event = Event()
        self.setup_logging()
        self.load_config(config_path)
        self.setup_signal_handlers()
        
        # Initialize components
        self.alert_manager = AlertManager(
            webhook_url=self.config.get('slack_webhook'),
            log_file=self.config.get('log_file', 'ransomwatch.log')
        )
        
        self.rules_engine = RulesEngine(
            rules_file="config/rules.yml",
            alert_manager=self.alert_manager
        )
        
        self.honeyfile_manager = HoneyfileManager(
            honeyfiles_file="config/honeyfiles.txt",
            alert_manager=self.alert_manager
        )
        
        self.process_watcher = ProcessWatcher(
            rules_engine=self.rules_engine,
            alert_manager=self.alert_manager
        )
        
        self.file_monitor = FileMonitor(
            watch_paths=self.config.get('watch_paths', ['/home', '/tmp']),
            rules_engine=self.rules_engine,
            alert_manager=self.alert_manager,
            honeyfile_manager=self.honeyfile_manager
        )
    
    def setup_logging(self):
        """Configure logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ransomwatch.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("RansomWatch")
    
    def load_config(self, config_path):
        """Load configuration from JSON file"""
        import json
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file {config_path} not found, using defaults")
            self.config = {
                'watch_paths': ['/home', '/tmp', '/var/tmp'],
                'log_file': 'ransomwatch.log',
                'safe_mode': False
            }
    
    def setup_signal_handlers(self):
        """Handle graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info("Shutdown signal received")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def start(self):
        """Start all monitoring components"""
        self.logger.info("Starting RansomWatch monitoring system")
        
        try:
            # Create honeyfiles first
            self.honeyfile_manager.create_honeyfiles()
            
            # Start monitoring components
            self.file_monitor.start()
            self.process_watcher.start()
            
            self.logger.info("All monitoring components started")
            
            # Main loop
            while not self.shutdown_event.is_set():
                time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop all monitoring components"""
        self.logger.info("Stopping RansomWatch")
        self.file_monitor.stop()
        self.process_watcher.stop()
        self.honeyfile_manager.cleanup()

def main():
    parser = argparse.ArgumentParser(description='RansomWatch Detection System')
    parser.add_argument('--config', default='config/config.json', help='Config file path')
    parser.add_argument('--safe-mode', action='store_true', help='Enable prevention actions')
    
    args = parser.parse_args()
    
    # Set safe mode in environment for components to read
    if args.safe_mode:
        os.environ['SAFE_MODE'] = 'true'
        print("WARNING: Safe mode enabled - prevention actions will be taken")
    
    app = RansomWatch(args.config)
    app.start()

if __name__ == "__main__":
    main()
