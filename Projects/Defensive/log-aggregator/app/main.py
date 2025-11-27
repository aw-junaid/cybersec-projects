import logging
import time
import signal
import sys
from threading import Event
from typing import Dict, Any

from app.collectors.file_collector import FileCollector
from app.collectors.syslog_collector import SyslogCollector
from app.parsers.base_parser import ParserManager
from app.processors.normalizer import LogNormalizer
from app.storage.elasticsearch_store import ElasticsearchStorage
from app.search.query_engine import QueryEngine
from app.api.rest_api import RESTAPI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('log_aggregator.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class LogAggregator:
    """Main log aggregation system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.shutdown_event = Event()
        
        # Initialize components
        self.parser_manager = ParserManager(config.get("parsers", {}))
        self.normalizer = LogNormalizer(config.get("normalization", {}))
        self.storage = ElasticsearchStorage(config.get("storage", {}).get("elasticsearch", {}))
        self.query_engine = QueryEngine(self.storage)
        
        self.collectors = []
        self.api = None
    
    def start(self):
        """Start the log aggregation system"""
        logger.info("Starting log aggregator...")
        self.running = True
        
        try:
            # Initialize storage
            self.storage.initialize()
            
            # Start collectors
            self._start_collectors()
            
            # Start API
            self._start_api()
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            logger.info("Log aggregator started successfully")
            
            # Main loop
            self._main_loop()
            
        except Exception as e:
            logger.error(f"Error starting log aggregator: {e}")
            self.stop()
    
    def stop(self):
        """Stop the log aggregation system"""
        logger.info("Stopping log aggregator...")
        self.running = False
        self.shutdown_event.set()
        
        # Stop collectors
        for collector in self.collectors:
            try:
                collector.stop()
            except Exception as e:
                logger.error(f"Error stopping collector: {e}")
        
        # Stop API
        if self.api:
            try:
                self.api.stop()
            except Exception as e:
                logger.error(f"Error stopping API: {e}")
        
        logger.info("Log aggregator stopped")
    
    def _start_collectors(self):
        """Start all configured collectors"""
        collector_configs = self.config.get("collectors", {})
        
        # File collector
        if collector_configs.get("file", {}).get("enabled", False):
            file_collector = FileCollector(
                collector_configs["file"],
                self._process_log_entry
            )
            file_collector.start()
            self.collectors.append(file_collector)
        
        # Syslog collector
        if collector_configs.get("syslog", {}).get("enabled", False):
            syslog_collector = SyslogCollector(
                collector_configs["syslog"], 
                self._process_log_entry
            )
            syslog_collector.start()
            self.collectors.append(syslog_collector)
        
        logger.info(f"Started {len(self.collectors)} collectors")
    
    def _start_api(self):
        """Start REST API"""
        api_config = self.config.get("api", {})
        if api_config.get("enabled", True):
            self.api = RESTAPI(self.query_engine, api_config)
            self.api.start()
            logger.info(f"REST API started on {api_config.get('host', '0.0.0.0')}:{api_config.get('port', 8000)}")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            self.stop()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _process_log_entry(self, raw_entry: Dict[str, Any]):
        """Process a single log entry through the pipeline"""
        try:
            # Parse
            parsed_entry = self.parser_manager.parse(raw_entry)
            
            # Normalize
            normalized_entry = self.normalizer.normalize(parsed_entry)
            
            # Store
            self.storage.store(normalized_entry)
            
            # Log processing stats
            if hasattr(self, 'processed_count'):
                self.processed_count += 1
                if self.processed_count % 1000 == 0:
                    logger.info(f"Processed {self.processed_count} log entries")
            else:
                self.processed_count = 1
            
        except Exception as e:
            logger.error(f"Error processing log entry: {e}")
    
    def _main_loop(self):
        """Main system loop"""
        try:
            while not self.shutdown_event.is_set():
                # Check system health
                self._check_health()
                
                # Sleep briefly
                self.shutdown_event.wait(5)
                
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()
    
    def _check_health(self):
        """Check system health and log statistics"""
        # This could be expanded to monitor system health,
        # storage usage, performance metrics, etc.
        pass

def main():
    """Main entry point"""
    from config.settings import settings
    
    # Create aggregator instance
    aggregator = LogAggregator({
        "collectors": settings.COLLECTORS,
        "parsers": settings.PARSERS, 
        "normalization": settings.NORMALIZATION,
        "storage": settings.STORAGE,
        "api": settings.API
    })
    
    try:
        aggregator.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
