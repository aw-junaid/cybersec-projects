#!/usr/bin/env python3
"""
Enrichment module for DLP Demo
Provides context for network events (IP, DNS, TLS)
LAB USE ONLY
"""

import socket
import json
import requests
from typing import Dict, Optional
from dlptools.safety import SafetyChecker

class EnrichmentEngine:
    def __init__(self):
        SafetyChecker.verify_lab_mode()
        
        # Lab-only enrichment data
        self.known_malicious_domains = {
            "exfil-malicious.com", "data-stealer.net", "bad-actor.org"
        }
        
        self.cloud_provider_ranges = {
            "AWS": ["3.0.0.0/9", "52.0.0.0/10"],
            "Azure": ["13.0.0.0/9", "20.0.0.0/10"],
            "GCP": ["8.0.0.0/9", "34.0.0.0/10"]
        }
    
    def enrich_ip(self, ip_address: str) -> Dict:
        """Enrich IP address with context"""
        try:
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except (socket.herror, socket.gaierror):
                hostname = None
            
            # Simple ASN/Org simulation (lab-only)
            org = self._simulate_whois(ip_address)
            
            # Check if cloud provider
            is_cloud = self._is_cloud_ip(ip_address)
            
            return {
                "ip": ip_address,
                "hostname": hostname,
                "organization": org,
                "is_cloud_provider": is_cloud,
                "risk_factors": []
            }
            
        except Exception as e:
            return {
                "ip": ip_address,
                "error": str(e)
            }
    
    def enrich_dns(self, query: str, response: str) -> Dict:
        """Enrich DNS query/response"""
        risk_factors = []
        
        # Check for suspicious patterns
        if len(query) > 100:
            risk_factors.append("long_dns_query")
        
        if any(domain in query for domain in self.known_malicious_domains):
            risk_factors.append("known_malicious_domain")
        
        # Check for base64-like patterns
        import base64
        try:
            # Remove domain part and check if remainder is base64
            domain_parts = query.split('.')
            if len(domain_parts) > 2:
                potential_b64 = domain_parts[0]
                if len(potential_b64) % 4 == 0:
                    base64.b64decode(potential_b64 + '===')
                    risk_factors.append("potential_base64_encoding")
        except:
            pass
        
        return {
            "query": query,
            "response": response,
            "risk_factors": risk_factors,
            "suspicious": len(risk_factors) > 0
        }
    
    def enrich_tls(self, server_name: str, cert_info: Dict) -> Dict:
        """Enrich TLS connection details"""
        risk_factors = []
        
        # Check certificate validity
        if cert_info.get('self_signed', False):
            risk_factors.append("self_signed_cert")
        
        # Check for suspicious SNI
        if server_name in self.known_malicious_domains:
            risk_factors.append("known_malicious_sni")
        
        return {
            "server_name": server_name,
            "certificate": cert_info,
            "risk_factors": risk_factors,
            "suspicious": len(risk_factors) > 0
        }
    
    def _simulate_whois(self, ip: str) -> str:
        """Simulate WHOIS lookup (lab-only)"""
        # Simple mapping for demo
        ip_parts = list(map(int, ip.split('.')))
        
        if ip_parts[0] == 10:
            return "LAB-NETWORK-PRIVATE"
        elif ip_parts[0] == 192 and ip_parts[1] == 168:
            return "LAB-NETWORK-PRIVATE"
        elif ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
            return "LAB-NETWORK-PRIVATE"
        else:
            return f"ASN{ip_parts[0] * 1000 + ip_parts[1]} - DEMO-ISP"
    
    def _is_cloud_ip(self, ip: str) -> bool:
        """Check if IP is in cloud provider range (simplified)"""
        ip_parts = list(map(int, ip.split('.')))
        
        # Simple check for demo
        if ip_parts[0] in [3, 8, 13, 20, 34, 52]:
            return True
        return False

if __name__ == "__main__":
    SafetyChecker.verify_lab_mode()
    
    enricher = EnrichmentEngine()
    
    # Test enrichment
    test_ip = "8.8.8.8"
    result = enricher.enrich_ip(test_ip)
    print(json.dumps(result, indent=2))
