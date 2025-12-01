#!/usr/bin/env python3
"""
HoneyNet Sensor Agent
Safety Notice: This agent requires HONEY_LAB_MODE=1 and network isolation checks.
Do not deploy in production environments without proper approvals.
"""

import os
import sys
import json
import time
import logging
import asyncio
import hashlib
import socket
import ssl
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

import aiofiles
import aiohttp
from kafka import KafkaProducer
from kafka.errors import KafkaError
import maxminddb
import psutil
from prometheus_client import start_http_server, Counter, Gauge, Histogram

# Safety checks
if os.getenv('HONEY_LAB_MODE') != '1':
    print("ERROR: HONEY_LAB_MODE environment variable not set to 1")
    print("This agent can only run in approved lab environments")
    sys.exit(1)

# Constants
CONFIG = {
    'kafka_brokers': os.getenv('KAFKA_BROKERS', 'localhost:9092').split(','),
    'node_token': os.getenv('NODE_TOKEN'),
    'ca_cert': os.getenv('CA_CERT_PATH', '/certs/ca.crt'),
    'node_cert': os.getenv('NODE_CERT_PATH', '/certs/node.crt'),
    'node_key': os.getenv('NODE_KEY_PATH', '/certs/node.key'),
    'maxmind_db': os.getenv('MAXMIND_DB', '/data/GeoLite2-City.mmdb'),
    'artifact_dir': os.getenv('ARTIFACT_DIR', '/data/artifacts'),
    'metrics_port': int(os.getenv('METRICS_PORT', '8080')),
    'queue_max_size': int(os.getenv('QUEUE_MAX_SIZE', '10000')),
}

# Prometheus metrics
EVENTS_PROCESSED = Counter('hn_events_processed_total', 'Total events processed')
EVENTS_FAILED = Counter('hn_events_failed_total', 'Total events failed to process')
ARTIFACTS_CAPTURED = Counter('hn_artifacts_captured_total', 'Total artifacts captured')
QUEUE_SIZE = Gauge('hn_queue_size', 'Current event queue size')
PROCESSING_TIME = Histogram('hn_processing_seconds', 'Event processing time')

@dataclass
class EnrichedEvent:
    timestamp: str
    sensor_id: str
    event_type: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    raw_data: str
    geoip: Optional[Dict]
    asn: Optional[Dict]
    reverse_dns: Optional[str]
    artifacts: List[str]
    signatures: List[str]

class SafetyCheckError(Exception):
    """Raised when safety checks fail"""

class HoneynetAgent:
    def __init__(self):
        self.logger = self._setup_logging()
        self._verify_safety()
        self._verify_config()
        
        self.geoip_reader = None
        self.kafka_producer = None
        self.event_queue = asyncio.Queue(maxsize=CONFIG['queue_max_size'])
        
    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('honeynet-agent')
    
    def _verify_safety(self):
        """Verify the agent is running in safe conditions"""
        # Check network isolation
        try:
            # Ensure we're not on a public network
            gateways = psutil.net_if_addrs()
            for interface, addrs in gateways.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address:
                        if not addr.address.startswith(('10.', '172.', '192.168.', '127.')):
                            self.logger.warning(f"Interface {interface} has public IP: {addr.address}")
        except Exception as e:
            self.logger.error(f"Safety check failed: {e}")
            raise SafetyCheckError(f"Network safety check failed: {e}")
    
    def _verify_config(self):
        """Verify required configuration"""
        if not CONFIG['node_token']:
            raise SafetyCheckError("NODE_TOKEN environment variable required")
        
        required_files = [CONFIG['ca_cert'], CONFIG['node_cert'], CONFIG['node_key']]
        for file_path in required_files:
            if not Path(file_path).exists():
                raise SafetyCheckError(f"Required file missing: {file_path}")
    
    async def initialize(self):
        """Initialize the agent"""
        self.logger.info("Initializing Honeynet Agent")
        
        # Initialize GeoIP
        if Path(CONFIG['maxmind_db']).exists():
            self.geoip_reader = maxminddb.open_database(CONFIG['maxmind_db'])
        
        # Initialize Kafka producer with TLS
        ssl_context = ssl.create_default_context(
            cafile=CONFIG['ca_cert']
        )
        ssl_context.load_cert_chain(
            certfile=CONFIG['node_cert'],
            keyfile=CONFIG['node_key']
        )
        
        try:
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=CONFIG['kafka_brokers'],
                security_protocol='SSL',
                ssl_context=ssl_context,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                acks='all',
                retries=3
            )
        except KafkaError as e:
            self.logger.error(f"Failed to connect to Kafka: {e}")
            raise
        
        # Start metrics server
        start_http_server(CONFIG['metrics_port'])
        self.logger.info(f"Metrics server started on port {CONFIG['metrics_port']}")
    
    async def enrich_event(self, raw_event: Dict) -> EnrichedEvent:
        """Enrich raw event with GeoIP, reverse DNS, etc."""
        start_time = time.time()
        
        try:
            # Basic event structure
            event = EnrichedEvent(
                timestamp=datetime.utcnow().isoformat(),
                sensor_id=CONFIG['node_token'][:8],  # Use first 8 chars of token as ID
                event_type=raw_event.get('event_type', 'unknown'),
                source_ip=raw_event.get('src_ip', ''),
                source_port=raw_event.get('src_port', 0),
                dest_ip=raw_event.get('dest_ip', ''),
                dest_port=raw_event.get('dest_port', 0),
                protocol=raw_event.get('protocol', ''),
                raw_data=json.dumps(raw_event),
                geoip=None,
                asn=None,
                reverse_dns=None,
                artifacts=[],
                signatures=[]
            )
            
            # GeoIP enrichment
            if self.geoip_reader and event.source_ip:
                try:
                    geo_data = self.geoip_reader.get(event.source_ip)
                    if geo_data:
                        event.geoip = {
                            'country': geo_data.get('country', {}).get('names', {}).get('en'),
                            'city': geo_data.get('city', {}).get('names', {}).get('en'),
                            'latitude': geo_data.get('location', {}).get('latitude'),
                            'longitude': geo_data.get('location', {}).get('longitude'),
                        }
                except Exception as e:
                    self.logger.warning(f"GeoIP lookup failed for {event.source_ip}: {e}")
            
            # Reverse DNS lookup (async)
            if event.source_ip:
                try:
                    loop = asyncio.get_event_loop()
                    event.reverse_dns = await loop.run_in_executor(
                        None, socket.getfqdn, event.source_ip
                    )
                except Exception as e:
                    self.logger.debug(f"Reverse DNS failed for {event.source_ip}: {e}")
            
            # Extract artifacts if present
            if 'artifacts' in raw_event:
                for artifact in raw_event['artifacts']:
                    artifact_path = await self._store_artifact(artifact)
                    if artifact_path:
                        event.artifacts.append(artifact_path)
            
            PROCESSING_TIME.observe(time.time() - start_time)
            EVENTS_PROCESSED.inc()
            return event
            
        except Exception as e:
            EVENTS_FAILED.inc()
            self.logger.error(f"Event enrichment failed: {e}")
            raise
    
    async def _store_artifact(self, artifact_data: Dict) -> Optional[str]:
        """Store artifact to encrypted disk and prepare for upload"""
        try:
            artifact_dir = Path(CONFIG['artifact_dir'])
            artifact_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename
            content_hash = hashlib.sha256(artifact_data['content']).hexdigest()
            filename = f"{content_hash}_{int(time.time())}.bin"
            filepath = artifact_dir / filename
            
            # Write artifact
            async with aiofiles.open(filepath, 'wb') as f:
                await f.write(artifact_data['content'])
            
            ARTIFACTS_CAPTURED.inc()
            self.logger.info(f"Artifact stored: {filename}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Artifact storage failed: {e}")
            return None
    
    async def send_to_broker(self, event: EnrichedEvent):
        """Send enriched event to message broker"""
        try:
            event_dict = asdict(event)
            future = self.kafka_producer.send('honeynet-events', event_dict)
            # Wait for send to complete
            future.get(timeout=10)
            self.logger.debug(f"Event sent to broker: {event.event_type}")
        except Exception as e:
            self.logger.error(f"Failed to send event to broker: {e}")
            raise
    
    async def process_event(self, raw_event: Dict):
        """Process a single event through the pipeline"""
        try:
            QUEUE_SIZE.set(self.event_queue.qsize())
            
            enriched_event = await self.enrich_event(raw_event)
            await self.send_to_broker(enriched_event)
            
        except Exception as e:
            self.logger.error(f"Event processing failed: {e}")
    
    async def watch_log_files(self, log_patterns: List[str]):
        """Watch log files for new events"""
        # Implementation for file watching would go here
        # Using watchdog or similar library
        pass
    
    async def health_check(self) -> bool:
        """Perform health check"""
        try:
            # Check Kafka connectivity
            if self.kafka_producer:
                self.kafka_producer.flush(timeout=5)
            
            # Check disk space
            disk_usage = psutil.disk_usage(CONFIG['artifact_dir'])
            if disk_usage.percent > 90:
                self.logger.warning("Disk usage above 90%")
            
            return True
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
    
    async def run(self):
        """Main agent loop"""
        await self.initialize()
        self.logger.info("Honeynet Agent started successfully")
        
        # Example: Simulate receiving events (replace with actual source)
        while True:
            try:
                # Health check every 30 seconds
                await asyncio.sleep(30)
                if not await self.health_check():
                    self.logger.error("Health check failed, restarting may be needed")
                    
            except Exception as e:
                self.logger.error(f"Agent main loop error: {e}")
                await asyncio.sleep(5)

async def main():
    """Main entry point"""
    agent = HoneynetAgent()
    try:
        await agent.run()
    except KeyboardInterrupt:
        agent.logger.info("Agent shutdown requested")
    except Exception as e:
        agent.logger.error(f"Agent failed: {e}")
        sys.exit(1)
    finally:
        if agent.geoip_reader:
            agent.geoip_reader.close()

if __name__ == "__main__":
    asyncio.run(main())
