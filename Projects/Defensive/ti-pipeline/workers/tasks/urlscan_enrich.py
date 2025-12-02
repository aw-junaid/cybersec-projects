import os
import hashlib
import aiohttp
from datetime import datetime
from typing import Dict, Any

MOCK_ENRICH = os.getenv("MOCK_ENRICH", "true").lower() == "true"
ENABLE_REAL_ENRICH = os.getenv("ENABLE_REAL_ENRICH", "false").lower() == "true"
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

async def enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Enrich with URLScan.io
    """
    if ioc_type not in ['domain', 'url']:
        return None
        
    if MOCK_ENRICH or not ENABLE_REAL_ENRICH or not URLSCAN_API_KEY:
        return await mock_enrich(value, ioc_type)
    
    return await real_enrich(value, ioc_type)

async def real_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Real URLScan API call
    """
    headers = {"API-Key": URLSCAN_API_KEY}
    
    if ioc_type == 'domain':
        url = f"https://urlscan.io/api/v1/search/?q=domain:{value}"
    else:
        url = f"https://urlscan.io/api/v1/search/?q={value}"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return normalize_urlscan_response(data)
            elif response.status == 429:
                raise Exception("URLScan rate limit exceeded")
            else:
                raise Exception(f"URLScan API error: {response.status}")

async def mock_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Mock URLScan response
    """
    import asyncio
    await asyncio.sleep(0.1)
    
    data = {
        "results": [
            {
                "page": {
                    "url": f"https://{value}/" if ioc_type == 'domain' else value,
                    "domain": value if ioc_type == 'domain' else value.split('/')[2],
                    "ip": "1.2.3.4",
                    "country": "US",
                    "server": "nginx",
                    "asnname": "Mock ISP Inc."
                },
                "stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "unknown": 0
                },
                "verdicts": {
                    "overall": {
                        "malicious": True,
                        "score": 65
                    }
                },
                "task": {
                    "time": datetime.utcnow().isoformat()
                }
            }
        ],
        "total": 1
    }
    
    return normalize_urlscan_response(data)

def normalize_urlscan_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize URLScan response
    """
    if not data.get('results'):
        return {
            "source": "urlscan",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_data": data,
            "normalized_data": {},
            "confidence": 0,
            "request_hash": hashlib.sha256(str(data).encode()).hexdigest()[:16],
            "response_hash": hashlib.sha256(str({}).encode()).hexdigest()[:16]
        }
    
    result = data['results'][0]
    stats = result.get('stats', {})
    verdicts = result.get('verdicts', {})
    
    malicious_count = stats.get('malicious', 0)
    suspicious_count = stats.get('suspicious', 0)
    overall_score = verdicts.get('overall', {}).get('score', 0)
    
    confidence = max(overall_score, (malicious_count * 30 + suspicious_count * 15))
    
    normalized = {
        "url": result['page']['url'],
        "domain": result['page']['domain'],
        "ip": result['page']['ip'],
        "country": result['page']['country'],
        "server": result['page']['server'],
        "asn": result['page']['asnname'],
        "malicious_flags": malicious_count,
        "suspicious_flags": suspicious_count,
        "overall_score": overall_score,
        "last_scanned": result['task']['time']
    }
    
    return {
        "source": "urlscan",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": data,
        "normalized_data": normalized,
        "confidence": min(100, confidence),
        "request_hash": hashlib.sha256(str(data).encode()).hexdigest()[:16],
        "response_hash": hashlib.sha256(str(normalized).encode()).hexdigest()[:16]
    }
