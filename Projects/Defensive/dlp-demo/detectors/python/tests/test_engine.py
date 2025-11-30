#!/usr/bin/env python3
"""
Unit tests for DLP Engine
"""

import pytest
import json
import os
import sys
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dlp_engine import DlpEngine, DlpAlert

# Set lab mode for testing
os.environ['DLP_LAB_MODE'] = '1'

class TestDlpEngine:
    def setup_method(self):
        """Set up test fixtures"""
        self.engine = DlpEngine()
    
    def test_http_large_post(self):
        """Test detection of large HTTP POST"""
        http_log = {
            "_path": "http",
            "method": "POST",
            "request_body_len": 2000000,  # 2MB
            "host": "unknown-exfil.com",
            "id.orig_h": "10.1.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "192.168.1.200",
            "id.resp_p": 80,
            "user_agent": "curl/7.68.0"
        }
        
        alert = self.engine.process_zeek_log(http_log)
        assert alert is not None
        assert alert.protocol == "HTTP"
        assert alert.risk_score >= 55  # large_post + unknown_domain
        assert "large_post" in str(alert.evidence)
    
    def test_dns_tunneling(self):
        """Test DNS tunneling detection"""
        dns_log = {
            "_path": "dns",
            "query": "very-long-subdomain-with-potential-tunneling-data-encoded-in-base64-format.example.com",
            "qtype_name": "TXT",
            "id.orig_h": "10.1.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53
        }
        
        alert = self.engine.process_zeek_log(dns_log)
        assert alert is not None
        assert alert.protocol == "DNS"
        assert alert.risk_score >= 75  # long_query + txt_query
        assert "dns_txt_query" in str(alert.evidence)
    
    def test_ftp_upload(self):
        """Test FTP upload detection"""
        ftp_log = {
            "_path": "ftp",
            "command": "STOR",
            "file": "secret_data.txt",
            "id.orig_h": "10.1.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "192.168.1.200",
            "id.resp_p": 21
        }
        
        alert = self.engine.process_zeek_log(ftp_log)
        assert alert is not None
        assert alert.protocol == "FTP"
        assert alert.risk_score == 40
        assert alert.evidence["command"] == "STOR"
    
    def test_benign_traffic(self):
        """Test that benign traffic doesn't trigger alerts"""
        http_log = {
            "_path": "http",
            "method": "GET",
            "host": "google.com",
            "id.orig_h": "10.1.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "142.250.189.174",
            "id.resp_p": 80
        }
        
        alert = self.engine.process_zeek_log(http_log)
        assert alert is None
    
    def test_alert_structure(self):
        """Test alert structure and fields"""
        ftp_log = {
            "_path": "ftp",
            "command": "STOR",
            "file": "test.txt",
            "id.orig_h": "10.1.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "192.168.1.200",
            "id.resp_p": 21
        }
        
        alert = self.engine.process_zeek_log(ftp_log)
        
        assert hasattr(alert, 'alert_id')
        assert hasattr(alert, 'timestamp')
        assert hasattr(alert, 'source')
        assert hasattr(alert, 'destination')
        assert hasattr(alert, 'protocol')
        assert hasattr(alert, 'rule_id')
        assert hasattr(alert, 'risk_score')
        assert hasattr(alert, 'reason')
        assert hasattr(alert, 'evidence')
        assert hasattr(alert, 'recommendation')

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
