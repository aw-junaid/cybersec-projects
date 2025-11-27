from app.ingest.collectors import LogCollector
from app.ingest.parsers import LogParser
from app.analyze.correlator import EventCorrelator
from app.analyze.rules_engine import RulesEngine
from app.visualize.dashboard import SIEMDashboard
from app.database.models import Base
from app.config.settings import settings
import logging
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('siem.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class SIEMSystem:
    """Main SIEM system class"""
    
    def __init__(self):
        self.storage_handler = self._setup_storage()
        self.log_collector = LogCollector(self.storage_handler)
        self.rules_engine = RulesEngine(self.storage_handler)
        self.event_correlator = EventCorrelator(self.storage_handler, self.rules_engine)
        self.dashboard = SIEMDashboard(self.storage_handler)
        
    def _setup_storage(self):
        """Setup database storage"""
        # In a real implementation, this would setup database connections
        # For this demo, we'll use a simple in-memory storage
        class StorageHandler:
            def __init__(self):
                self.settings = settings
                self.events = []
                self.alerts = []
            
            def store_event(self, event):
                self.events.append(event)
            
            def create_alert(self, alert_data):
                alert_id = len(self.alerts) + 1
                alert_data['id'] = alert_id
                self.alerts.append(alert_data)
                return alert_id
            
            def get_events_by_time_range(self, start_time, end_time):
                return [e for e in self.events 
                       if start_time <= e.get('timestamp', start_time) <= end_time]
            
            def get_alerts_by_time_range(self, start_time, end_time):
                return [a for a in self.alerts 
                       if start_time <= a.get('timestamp', start_time) <= end_time]
        
        return StorageHandler()
    
    def start(self):
        """Start the SIEM system"""
        logger.info("Starting SIEM System...")
        
        try:
            # Start log collectors
            self.log_collector.start_collectors()
            
            # Start correlation engine
            self.event_correlator.start_correlation()
            
            logger.info("SIEM System started successfully")
            
        except Exception as e:
            logger.error(f"Error starting SIEM system: {e}")
            raise
    
    def stop(self):
        """Stop the SIEM system"""
        logger.info("Stopping SIEM System...")
        
        self.log_collector.stop_collectors()
        self.event_correlator.stop_correlation()
        
        logger.info("SIEM System stopped")
    
    def run_dashboard(self):
        """Run the web dashboard"""
        logger.info("Starting SIEM Dashboard...")
        self.dashboard.run(debug=settings.DEBUG)

def main():
    """Main function"""
    siem = SIEMSystem()
    
    try:
        # Start SIEM in background thread
        siem_thread = threading.Thread(target=siem.start)
        siem_thread.daemon = True
        siem_thread.start()
        
        # Run dashboard in main thread
        siem.run_dashboard()
        
    except KeyboardInterrupt:
        logger.info("Shutting down SIEM system...")
        siem.stop()
    except Exception as e:
        logger.error(f"SIEM system error: {e}")
        siem.stop()

if __name__ == "__main__":
    main()
