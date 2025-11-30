#!/usr/bin/env python3
"""
Main DLP Engine for Lab Demo
Analyzes network events for data exfiltration patterns
LAB USE ONLY - NEVER RUN AGAINST PRODUCTION SYSTEMS
"""

import json
import sys
import argparse
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass

from dlptools.safety import SafetyChecker
from dlptools.logger import DlpLogger
from file_analyzer import FileAnalyzer
from enrich import EnrichmentEngine
from ml_detector import MLAnomalyDetector

@dataclass
class DlpAlert:
    alert_id: str
    timestamp: str
    source: Dict
    destination: Dict
    protocol: str
    rule_id: str
    risk_score: int
    reason: str
    evidence: Dict
    recommendation: str

class DlpEngine:
    def __init__(self, config_path: str = None):
        SafetyChecker.verify_lab_mode()
        
        self.logger = DlpLogger("dlp-engine")
        self.enricher = EnrichmentEngine()
        
        # Initialize analyzers
        self.file_analyzer = FileAnalyzer("yara/exfil_signatures.yar")
        self.ml_detector = MLAnomalyDetector()
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "files_analyzed": 0
        }
        
        self.logger.log_event("engine_start", {"config": self.config})
    
    def _load_config(self, config_path: str) -> Dict:
        """Load engine configuration"""
        default_config = {
            "risk_threshold": 70,
            "max_file_size": 10485760,  # 10MB
            "allowed_domains": ["google.com", "microsoft.com", "apple.com"],
            "suspicious_ports": [21, 25, 587, 4444, 8080, 8443],
            "enable_ml": True,
            "output_elasticsearch": False,
            "elasticsearch_host": "localhost:9200"
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                self.logger.log_event("config_error", {"error": str(e)})
        
        return default_config
    
    def process_zeek_log(self, log_data: Dict) -> Optional[DlpAlert]:
        """Process Zeek log entry"""
        self.stats["events_processed"] += 1
        
        alert = None
        
        try:
            log_type = log_data.get('_path', '')
            
            if log_type == 'http':
                alert = self._analyze_http(log_data)
            elif log_type == 'dns':
                alert = self._analyze_dns(log_data)
            elif log_type == 'ssl':
                alert = self._analyze_tls(log_data)
            elif log_type == 'smtp':
                alert = self._analyze_smtp(log_data)
            elif log_type == 'ftp':
                alert = self._analyze_ftp(log_data)
            
            if alert:
                self.stats["alerts_generated"] += 1
                self._output_alert(alert)
            
        except Exception as e:
            self.logger.log_event("processing_error", {
                "error": str(e),
                "log_data": log_data
            })
        
        return alert
    
    def _analyze_http(self, http_log: Dict) -> Optional[DlpAlert]:
        """Analyze HTTP traffic for exfiltration"""
        risk_factors = []
        evidence = {}
        
        # Check for large POST requests
        if http_log.get('method') == 'POST':
            post_size = http_log.get('request_body_len', 0)
            
            if post_size > 1000000:  # 1MB
                risk_factors.append(("large_post", 30))
                evidence["post_size"] = post_size
            
            # Check destination
            host = http_log.get('host', '')
            if host not in self.config['allowed_domains']:
                risk_factors.append(("unknown_domain", 25))
                evidence["domain"] = host
        
        # Check for suspicious user agents
        ua = http_log.get('user_agent', '')
        if any(suspicious in ua.lower() for suspicious in ['curl', 'wget', 'python']):
            risk_factors.append(("suspicious_ua", 15))
            evidence["user_agent"] = ua
        
        if risk_factors:
            risk_score = sum(score for _, score in risk_factors)
            
            return DlpAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source={
                    "ip": http_log.get('id.orig_h'),
                    "port": http_log.get('id.orig_p'),
                    "host": ""
                },
                destination={
                    "ip": http_log.get('id.resp_h'),
                    "port": http_log.get('id.resp_p'),
                    "host": http_log.get('host', '')
                },
                protocol="HTTP",
                rule_id="dlp-http-exfil-01",
                risk_score=min(risk_score, 100),
                reason="Suspicious HTTP activity detected",
                evidence=evidence,
                recommendation="Investigate host and review HTTP traffic"
            )
        
        return None
    
    def _analyze_dns(self, dns_log: Dict) -> Optional[DlpAlert]:
        """Analyze DNS for tunneling"""
        risk_factors = []
        evidence = {}
        
        query = dns_log.get('query', '')
        query_type = dns_log.get('qtype_name', '')
        
        # Check for long DNS queries (potential tunneling)
        if len(query) > 100:
            risk_factors.append(("long_dns_query", 40))
            evidence["query_length"] = len(query)
            evidence["query"] = query[:50] + "..."  # Truncate for evidence
        
        # Check for TXT record queries (common in tunneling)
        if query_type == 'TXT':
            risk_factors.append(("dns_txt_query", 35))
            evidence["query_type"] = query_type
        
        # Check for high entropy subdomains
        if '.' in query:
            subdomain = query.split('.')[0]
            if len(subdomain) > 50:
                entropy = self.file_analyzer.entropy(subdomain.encode())
                if entropy > 6.0:
                    risk_factors.append(("high_entropy_subdomain", 45))
                    evidence["entropy"] = entropy
        
        if risk_factors:
            risk_score = sum(score for _, score in risk_factors)
            
            return DlpAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source={
                    "ip": dns_log.get('id.orig_h'),
                    "port": dns_log.get('id.orig_p'),
                    "host": ""
                },
                destination={
                    "ip": dns_log.get('id.resp_h'), 
                    "port": dns_log.get('id.resp_p'),
                    "host": dns_log.get('query', '')
                },
                protocol="DNS",
                rule_id="dlp-dns-tunnel-01",
                risk_score=min(risk_score, 100),
                reason="Potential DNS tunneling activity",
                evidence=evidence,
                recommendation="Block DNS queries to external resolvers"
            )
        
        return None
    
    def _analyze_tls(self, tls_log: Dict) -> Optional[DlpAlert]:
        """Analyze TLS for suspicious connections"""
        risk_factors = []
        evidence = {}
        
        server_name = tls_log.get('server_name', '')
        
        # Check for suspicious SNI
        if server_name and server_name not in self.config['allowed_domains']:
            risk_factors.append(("unknown_sni", 30))
            evidence["server_name"] = server_name
        
        # Check for self-signed certificates
        if tls_log.get('validation_status') == 'self signed':
            risk_factors.append(("self_signed_cert", 25))
        
        if risk_factors:
            risk_score = sum(score for _, score in risk_factors)
            
            return DlpAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source={
                    "ip": tls_log.get('id.orig_h'),
                    "port": tls_log.get('id.orig_p'),
                    "host": ""
                },
                destination={
                    "ip": tls_log.get('id.resp_h'),
                    "port": tls_log.get('id.resp_p'),
                    "host": server_name
                },
                protocol="TLS",
                rule_id="dlp-tls-suspicious-01",
                risk_score=min(risk_score, 100),
                reason="Suspicious TLS connection",
                evidence=evidence,
                recommendation="Review TLS certificate and destination"
            )
        
        return None
    
    def _analyze_smtp(self, smtp_log: Dict) -> Optional[DlpAlert]:
        """Analyze SMTP for data exfiltration"""
        # Basic implementation - extend based on SMTP log fields
        risk_factors = []
        evidence = {}
        
        # Check for attachments to external domains
        if smtp_log.get('mailfrom', '') and '@' in smtp_log.get('mailfrom', ''):
            domain = smtp_log['mailfrom'].split('@')[-1]
            if domain not in self.config['allowed_domains']:
                risk_factors.append(("external_email", 35))
                evidence["from_domain"] = domain
        
        if risk_factors:
            risk_score = sum(score for _, score in risk_factors)
            
            return DlpAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source={
                    "ip": smtp_log.get('id.orig_h'),
                    "port": smtp_log.get('id.orig_p'),
                    "host": ""
                },
                destination={
                    "ip": smtp_log.get('id.resp_h'),
                    "port": smtp_log.get('id.resp_p'),
                    "host": smtp_log.get('helo', '')
                },
                protocol="SMTP",
                rule_id="dlp-smtp-exfil-01",
                risk_score=min(risk_score, 100),
                reason="Suspicious email activity",
                evidence=evidence,
                recommendation="Review email content and attachments"
            )
        
        return None
    
    def _analyze_ftp(self, ftp_log: Dict) -> Optional[DlpAlert]:
        """Analyze FTP for file transfers"""
        risk_factors = []
        evidence = {}
        
        command = ftp_log.get('command', '')
        
        # Check for file upload commands
        if command in ['STOR', 'STOU']:
            risk_factors.append(("ftp_upload", 40))
            evidence["command"] = command
            evidence["file"] = ftp_log.get('file', '')
        
        if risk_factors:
            risk_score = sum(score for _, score in risk_factors)
            
            return DlpAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source={
                    "ip": ftp_log.get('id.orig_h'),
                    "port": ftp_log.get('id.orig_p'),
                    "host": ""
                },
                destination={
                    "ip": ftp_log.get('id.resp_h'),
                    "port": ftp_log.get('id.resp_p'),
                    "host": ""
                },
                protocol="FTP",
                rule_id="dlp-ftp-upload-01",
                risk_score=min(risk_score, 100),
                reason="FTP file upload detected",
                evidence=evidence,
                recommendation="Block FTP transfers and investigate"
            )
        
        return None
    
    def _output_alert(self, alert: DlpAlert):
        """Output alert in JSON format"""
        alert_dict = {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp,
            "source": alert.source,
            "destination": alert.destination,
            "protocol": alert.protocol,
            "rule_id": alert.rule_id,
            "risk_score": alert.risk_score,
            "reason": alert.reason,
            "evidence": alert.evidence,
            "recommendation": alert.recommendation
        }
        
        # Output to stdout
        print(json.dumps(alert_dict, indent=2))
        
        # Log via structured logger
        self.logger.log_alert(alert_dict)
    
    def print_stats(self):
        """Print engine statistics"""
        stats_output = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "statistics": self.stats
        }
        print(json.dumps(stats_output, indent=2))

def main():
    parser = argparse.ArgumentParser(description='DLP Engine - Lab Use Only')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--dry-run', action='store_true', help='Process without alerts')
    parser.add_argument('--enable-exfil-tests', action='store_true', 
                       help='Enable exfiltration tests (requires confirmation)')
    
    args = parser.parse_args()
    
    # Safety checks
    SafetyChecker.verify_lab_mode()
    
    if args.enable_exfil_tests:
        SafetyChecker.confirm_destructive_action("EXFIL_TEST_ENABLE")
    
    # Initialize engine
    engine = DlpEngine(args.config)
    
    # Example: Process sample logs from stdin
    try:
        for line in sys.stdin:
            if line.strip():
                try:
                    log_data = json.loads(line)
                    engine.process_zeek_log(log_data)
                except json.JSONDecodeError:
                    continue
        
        # Print final statistics
        engine.print_stats()
        
    except KeyboardInterrupt:
        print("\nShutting down DLP engine...")
        engine.print_stats()
        sys.exit(0)

if __name__ == "__main__":
    main()
