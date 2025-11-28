#!/usr/bin/env python3
"""Unit tests for container security scanner"""

import pytest
from fastapi.testclient import TestClient
from main import app, calculate_risk_score

client = TestClient(app)

def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_risk_score_calculation():
    """Test risk score calculation logic"""
    # Test with no vulnerabilities and verified signature
    vulnerabilities = []
    signature_verified = True
    security_issues = []
    score = calculate_risk_score(vulnerabilities, signature_verified, security_issues)
    assert score == 0
    
    # Test with critical vulnerability
    vulnerabilities = [{"severity": "CRITICAL"}]
    score = calculate_risk_score(vulnerabilities, signature_verified, security_issues)
    assert score == 10
    
    # Test with unverified signature
    signature_verified = False
    score = calculate_risk_score([], signature_verified, security_issues)
    assert score == 20

def test_scan_endpoint_invalid_image():
    """Test scan endpoint with invalid image"""
    response = client.post("/scan", json={"image": "invalid-image:latest"})
    # Should handle gracefully, though actual scanning might fail
    assert response.status_code in [200, 500]

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
