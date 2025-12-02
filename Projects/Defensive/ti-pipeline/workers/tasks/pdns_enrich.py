import os
import hashlib
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, Any, List

MOCK_ENRICH = os.getenv("MOCK_ENRICH", "true").lower() == "true"
ENABLE_REAL_ENRICH = os.getenv("ENABLE_REAL_ENRICH", "false").lower() == "true"

async def enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Enrich with Passive DNS data
    """
    if ioc_type not in ['domain', 'ipv4']:
        return None
        
    if MOCK_ENRICH or not ENABLE_REAL_ENRICH:
        return await mock_enrich(value, ioc_type)
    
    return await real_enrich(value, ioc_type)

async def real_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Real Passive DNS API call
    """
    # This would integrate with services like PassiveTotal, SecurityTrails, etc.
    # For now, return mock data in real mode as well
    return await mock_enrich(value, ioc_type)

async def mock_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Mock Passive DNS response
    """
    import asyncio
    await asyncio.sleep(0.05)
    
    now = datetime.utcnow()
    
    if ioc_type == 'domain':
        data = {
            "results": [
                {
                    "first_seen": (now - timedelta(days=30)).isoformat(),
                    "last_seen": (now - timedelta(days=1)).isoformat(),
                    "record_type": "A",
                    "value": "1.2.3.4"
                },
                {
                    "first_seen": (now - timedelta(days=15)).isoformat(),
                    "last_seen": now.isoformat(),
                    "record_type": "A",
                    "value": "5.6.7.8"
                },
                {
                    "first_seen": (now - timedelta(days=5)).isoformat(),
                    "last_seen": now.isoformat(),
                    "record_type": "A",
                    "value": "9.10.11.12"
                }
            ],
            "total_count": 3
        }
    else:
        data = {
            "results": [
                {
                    "first_seen": (now - timedelta(days=45)).isoformat(),
                    "last_seen": (now - timedelta(days=10)).isoformat(),
                    "record_type": "A",
                    "value": "malicious-domain.com"
                },
                {
                    "first_seen": (now - timedelta(days=20)).isoformat(),
                    "last_seen": now.isoformat(),
                    "record_type": "A",
                    "value": "suspicious-site.net"
                }
            ],
            "total_count": 2
        }
    
    return normalize_pdns_response(data, ioc_type)

def normalize_pdns_response(data: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
    """
    Normalize Passive DNS response
    """
    results = data.get('results', [])
    
    # Calculate DNS churn and other metrics
    unique_records = len(results)
    date_range = calculate_date_range(results)
    
    normalized = {
        "total_records": unique_records,
        "date_range_days": date_range,
        "records": results[:10],  # Limit to first 10 records
        "recent_activity": has_recent_activity(results),
        "fast_flux": detect_fast_flux(results)
    }
    
    confidence = calculate_pdns_confidence(normalized)
    
    return {
        "source": "pdns",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": data,
        "normalized_data": normalized,
        "confidence": confidence,
        "request_hash": hashlib.sha256(str(data).encode()).hexdigest()[:16],
        "response_hash": hashlib.sha256(str(normalized).encode()).hexdigest()[:16]
    }

def calculate_date_range(records: List[Dict]) -> int:
    """
    Calculate date range of DNS records in days
    """
    if not records:
        return 0
    
    first_seen = min(datetime.fromisoformat(r['first_seen'].replace('Z', '+00:00')) for r in records)
    last_seen = max(datetime.fromisoformat(r['last_seen'].replace('Z', '+00:00')) for r in records)
    
    return (last_seen - first_seen).days

def has_recent_activity(records: List[Dict]) -> bool:
    """
    Check if there's recent DNS activity (last 7 days)
    """
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    for record in records:
        last_seen = datetime.fromisoformat(record['last_seen'].replace('Z', '+00:00'))
        if last_seen > week_ago:
            return True
    return False

def detect_fast_flux(records: List[Dict]) -> bool:
    """
    Detect potential fast-flux DNS patterns
    """
    if len(records) < 3:
        return False
    
    # Check for multiple IP changes in short time
    ip_changes = len(set(r['value'] for r in records))
    date_range = calculate_date_range(records)
    
    # High IP churn in short time suggests fast-flux
    return ip_changes >= 3 and date_range < 30

def calculate_pdns_confidence(pdns_data: Dict[str, Any]) -> int:
    """
    Calculate confidence based on Passive DNS patterns
    """
    confidence = 50
    
    # Fast flux increases suspicion
    if pdns_data.get('fast_flux'):
        confidence += 30
    
    # Many records in short time
    if pdns_data['total_records'] >= 5 and pdns_data['date_range_days'] < 30:
        confidence += 20
    
    # Recent activity
    if pdns_data.get('recent_activity'):
        confidence += 10
    
    return min(100, confidence)
