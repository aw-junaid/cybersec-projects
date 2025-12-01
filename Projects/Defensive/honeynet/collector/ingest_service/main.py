#!/usr/bin/env python3
"""
Honeynet Ingest Service
Safety Notice: This service requires HONEY_LAB_MODE=1
"""

import os
import json
import logging
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
from minio import Minio
import yara
import clamd

class IngestService:
    def __init__(self):
        self._verify_safety()
        self.logger = self._setup_logging()
        
        # Initialize clients
        self.es = Elasticsearch([os.getenv('ELASTICSEARCH_HOST', 'localhost:9200')])
        self.minio = Minio(
            os.getenv('MINIO_ENDPOINT', 'localhost:9000'),
            access_key=os.getenv('MINIO_ACCESS_KEY', 'honeynet'),
            secret_key=os.getenv('MINIO_SECRET_KEY', 'change-this-password'),
            secure=False
        )
        
        # Initialize analysis tools
        self.yara_rules = self._load_yara_rules()
        self.clamav = clamd.ClamdUnixSocket()
        
    def _verify_safety(self):
        if os.getenv('HONEY_LAB_MODE') != '1':
            raise RuntimeError("HONEY_LAB_MODE environment variable not set to 1")
    
    def _setup_logging(self):
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger('ingest-service')
    
    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            rules = yara.compile(filepath='/rules/index.yar')
            return rules
        except Exception as e:
            self.logger.warning(f"Failed to load YARA rules: {e}")
            return None
    
    def process_event(self, event):
        """Process a single event from Kafka"""
        try:
            # Store in Elasticsearch
            self.es.index(
                index='honeynet-events',
                body=event
            )
            
            # Analyze artifacts
            if 'artifacts' in event:
                for artifact_path in event['artifacts']:
                    self._analyze_artifact(artifact_path, event)
            
            self.logger.info(f"Processed event from {event.get('source_ip', 'unknown')}")
            
        except Exception as e:
            self.logger.error(f"Event processing failed: {e}")
    
    def _analyze_artifact(self, artifact_path, event):
        """Analyze captured artifact"""
        try:
            # YARA scanning
            if self.yara_rules:
                matches = self.yara_rules.match(artifact_path)
                if matches:
                    self.logger.warning(f"YARA match: {matches}")
                    # Trigger alert
            
            # ClamAV scanning
            scan_result = self.clamav.scan(artifact_path)
            if scan_result and 'FOUND' in scan_result[artifact_path][1]:
                self.logger.warning(f"ClamAV detection: {scan_result}")
            
            # Store in MinIO
            object_name = f"artifacts/{os.path.basename(artifact_path)}"
            self.minio.fput_object(
                "honeynet", object_name, artifact_path
            )
            
        except Exception as e:
            self.logger.error(f"Artifact analysis failed: {e}")
    
    def run(self):
        """Main ingestion loop"""
        consumer = KafkaConsumer(
            'honeynet-events',
            bootstrap_servers=os.getenv('KAFKA_BROKERS', 'localhost:9092').split(','),
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        
        self.logger.info("Ingest service started")
        
        for message in consumer:
            self.process_event(message.value)

if __name__ == "__main__":
    service = IngestService()
    service.run()
