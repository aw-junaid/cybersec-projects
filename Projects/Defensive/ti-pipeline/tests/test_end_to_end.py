import pytest
import asyncio
import aiohttp
import json
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

API_BASE = "http://localhost:8000"
API_KEY = "test-key"

@pytest.fixture
async def session():
    async with aiohttp.ClientSession() as session:
        yield session

@pytest.mark.asyncio
async def test_api_health(session):
    """Test API health endpoint"""
    async with session.get(f"{API_BASE}/stats", headers={"Authorization": f"Bearer {API_KEY}"}) as response:
        assert response.status == 200
        data = await response.json()
        assert "ioc_statistics" in data
        assert "enrichment_statistics" in data

@pytest.mark.asyncio
async def test_ioc_ingestion(session):
    """Test IOC ingestion"""
    test_iocs = [
        {
            "value": "test-malicious-domain.com",
            "type": "domain",
            "source": "test_feed",
            "confidence": 85,
            "first_seen": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "tags": ["malicious", "test"],
            "description": "Test malicious domain"
        },
        {
            "value": "192.168.1.100",
            "type": "ipv4", 
            "source": "test_feed",
            "confidence": 75,
            "first_seen": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "tags": ["suspicious", "test"],
            "description": "Test suspicious IP"
        }
    ]
    
    payload = {
        "iocs": test_iocs,
        "feed_name": "pytest_feed",
        "feed_version": "1.0"
    }
    
    async with session.post(
        f"{API_BASE}/ingest", 
        json=payload,
        headers={"Authorization": f"Bearer {API_KEY}"}
    ) as response:
        assert response.status == 202
        data = await response.json()
        assert "ioc_ids" in data
        assert len(data["ioc_ids"]) == 2
        assert data["enrichment_queued"] is True

@pytest.mark.asyncio
async def test_ioc_search(session):
    """Test IOC search functionality"""
    async with session.get(
        f"{API_BASE}/search?q=test-malicious-domain.com",
        headers={"Authorization": f"Bearer {API_KEY}"}
    ) as response:
        assert response.status == 200
        data = await response.json()
        assert "iocs" in data
        assert "total" in data
        assert len(data["iocs"]) >= 1
        
        # Verify the IOC we just ingested is found
        found_ioc = None
        for ioc in data["iocs"]:
            if ioc["value"] == "test-malicious-domain.com":
                found_ioc = ioc
                break
        
        assert found_ioc is not None
        assert found_ioc["type"] == "domain"
        assert found_ioc["source"] == "pytest_feed"

@pytest.mark.asyncio
async def test_enrichment_worker_mock():
    """Test enrichment worker with mock providers"""
    from workers.tasks.vt_enrich import enrich as vt_enrich
    from workers.tasks.whois_enrich import enrich as whois_enrich
    
    # Test VirusTotal mock enrichment
    vt_result = await vt_enrich("test-domain.com", "domain")
    assert vt_result is not None
    assert vt_result["source"] == "virustotal"
    assert "confidence" in vt_result
    assert "timestamp" in vt_result
    assert "raw_data" in vt_result
    
    # Test WHOIS mock enrichment  
    whois_result = await whois_enrich("test-domain.com", "domain")
    assert whois_result is not None
    assert whois_result["source"] == "whois"
    assert "normalized_data" in whois_result

@pytest.mark.asyncio
async def test_cache_functionality():
    """Test Redis cache functionality"""
    from cache.cache import Cache
    
    cache = Cache("redis://localhost:6379/0")
    await cache.connect()
    
    # Test set and get
    test_data = {"test": "value", "number": 42}
    await cache.set("test_key", test_data, ttl_hours=1)
    
    retrieved = await cache.get("test_key")
    assert retrieved == test_data
    
    # Test cache miss
    missing = await cache.get("non_existent_key")
    assert missing is None
    
    await cache.disconnect()

def test_ioc_normalization():
    """Test IOC normalization logic"""
    from api.app import normalize_ioc
    
    # Test domain normalization
    normalized = normalize_ioc("EXAMPLE.COM", "domain")
    assert normalized == "example.com"
    
    # Test IP normalization
    normalized = normalize_ioc(" 192.168.1.1 ", "ipv4")
    assert normalized == "192.168.1.1"
    
    # Test hash normalization
    normalized = normalize_ioc("ABCD1234", "md5")
    assert normalized == "abcd1234"

@pytest.mark.asyncio
async def test_error_handling(session):
    """Test error handling for invalid requests"""
    # Test invalid API key
    async with session.get(f"{API_BASE}/search?q=test", headers={"Authorization": "Bearer invalid-key"}) as response:
        assert response.status == 401
    
    # Test malformed ingestion payload
    malformed_payload = {"invalid": "data"}
    async with session.post(
        f"{API_BASE}/ingest",
        json=malformed_payload,
        headers={"Authorization": f"Bearer {API_KEY}"}
    ) as response:
        # Should be 422 Unprocessable Entity for validation errors
        assert response.status in [400, 422]

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
