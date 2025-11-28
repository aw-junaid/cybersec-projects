#!/usr/bin/env python3
"""
Cloud CSPM - Cloud Security Posture Management Tool
Main entry point for the CSPM scanner
"""

import asyncio
import json
import logging
import sys
from typing import Dict, List, Any
import click

from connectors.aws_connector import AWSConnector
from connectors.azure_connector import AzureConnector
from connectors.gcp_connector import GCPConnector
from scanners.iam_scanner import IAMScanner
from scanners.storage_scanner import StorageScanner
from scanners.network_scanner import NetworkScanner
from analysis.risk_scorer import RiskScorer
from reporting.json_reporter import JSONReporter
from reporting.cli_reporter import CLIReporter
from utils.config_loader import ConfigLoader
from utils.logger import setup_logging


class CloudCSPM:
    """Main CSPM application class"""
    
    def __init__(self, config_path: str = "config/rules"):
        self.config = ConfigLoader.load_config(config_path)
        self.setup_logging()
        self.connectors = {}
        self.scanners = {}
        self.findings = []
        
    def setup_logging(self):
        """Initialize logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cspm_scan.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def initialize_connectors(self, providers: List[str]):
        """Initialize cloud provider connectors"""
        for provider in providers:
            try:
                if provider.lower() == 'aws':
                    self.connectors['aws'] = AWSConnector()
                elif provider.lower() == 'azure':
                    self.connectors['azure'] = AzureConnector()
                elif provider.lower() == 'gcp':
                    self.connectors['gcp'] = GCPConnector()
                self.logger.info(f"Initialized {provider} connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize {provider}: {str(e)}")
                
    def initialize_scanners(self):
        """Initialize security scanners"""
        self.scanners = {
            'iam': IAMScanner(self.connectors),
            'storage': StorageScanner(self.connectors),
            'network': NetworkScanner(self.connectors)
        }
        
    def scan_all(self) -> List[Dict[str, Any]]:
        """Execute all security scans"""
        all_findings = []
        
        for scanner_name, scanner in self.scanners.items():
            self.logger.info(f"Running {scanner_name} scanner...")
            try:
                findings = scanner.scan()
                all_findings.extend(findings)
                self.logger.info(f"Found {len(findings)} issues with {scanner_name}")
            except Exception as e:
                self.logger.error(f"Scanner {scanner_name} failed: {str(e)}")
                
        return all_findings
    
    def analyze_risks(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze and score risks"""
        risk_scorer = RiskScorer()
        scored_findings = []
        
        for finding in findings:
            risk_score = risk_scorer.calculate_risk_score(finding)
            finding['risk_score'] = risk_score
            finding['severity'] = risk_scorer.score_to_severity(risk_score)
            scored_findings.append(finding)
            
        return sorted(scored_findings, key=lambda x: x['risk_score'], reverse=True)
    
    def generate_reports(self, findings: List[Dict[str, Any]], output_format: str = 'all'):
        """Generate security reports"""
        if output_format in ['json', 'all']:
            JSONReporter.generate_report(findings, 'security_report.json')
            
        if output_format in ['cli', 'all']:
            CLIReporter.generate_report(findings)


@click.command()
@click.option('--providers', '-p', multiple=True, 
              default=['aws'], 
              help='Cloud providers to scan (aws, azure, gcp)')
@click.option('--output', '-o', 
              default='all', 
              type=click.Choice(['json', 'cli', 'all']),
              help='Output format')
@click.option('--config', '-c', 
              default='config/rules',
              help='Configuration directory path')
def main(providers, output, config):
    """Cloud CSPM - Cloud Security Posture Management Tool"""
    try:
        # Initialize CSPM tool
        cspm = CloudCSPM(config)
        cspm.logger.info("Starting cloud security scan...")
        
        # Initialize connectors and scanners
        cspm.initialize_connectors(providers)
        cspm.initialize_scanners()
        
        # Run security scans
        findings = cspm.scan_all()
        cspm.logger.info(f"Total findings before risk analysis: {len(findings)}")
        
        # Analyze risks
        analyzed_findings = cspm.analyze_risks(findings)
        cspm.logger.info(f"Total findings after risk analysis: {len(analyzed_findings)}")
        
        # Generate reports
        cspm.generate_reports(analyzed_findings, output)
        cspm.logger.info("Security scan completed successfully")
        
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
