import os
import hashlib
import aiohttp
from datetime import datetime
from typing import Dict, Any

MOCK_ENRICH = os.getenv("MOCK_ENRICH", "true").lower() == "true"
ENABLE_REAL_ENRICH = os.getenv("ENABLE_REAL_ENRICH", "false").lower() == "true"
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

async def enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Enrich IP with Shodan
    """
    if ioc_type not in ['ipv4', 'ipv6']:
        return None
        
    if MOCK_ENRICH or not ENABLE_REAL_ENRICH or not SHODAN_API_KEY:
        return await mock_enrich(value, ioc_type)
    
    return await real_enrich(value, ioc_type)

async def real_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Real Shodan API call
    """
    url = f"https://api.shodan.io/shodan/host/{value}"
    params = {"key": SHODAN_API_KEY}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return normalize_shodan_response(data)
            elif response.status == 429:
                raise Exception("Shodan rate limit exceeded")
            else:
                raise Exception(f"Shodan API error: {response.status}")

async def mock_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Mock Shodan response
    """
    import asyncio
    await asyncio.sleep(0.1)
    
    data = {
        "ip_str": value,
        "country_code": "US",
        "org": "Mock ISP",
        "os": "Linux 4.15",
        "ports": [80, 443, 22, 3389],
        "vulns": ["CVE-2021-44228", "CVE-2022-22965"],
        "tags": ["web", "https"],
        "data": [
            {
                "port": 80,
                "product": "nginx",
                "version": "1.18.0"
            },
            {
                "port": 443,
                "product": "OpenSSL",
                "version": "1.1.1"
            }
        ]
    }
    
    return normalize_shodan_response(data)

def normalize_shodan_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Shodan response
    """
    open_ports = data.get('ports', [])
    vulnerabilities = data.get('vulns', [])
    
    risk_score = min(100, len(open_ports) * 5 + len(vulnerabilities) * 20)
    
    normalized = {
        "country": data.get('country_code'),
        "organization": data.get('org'),
        "operating_system": data.get('os'),
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
        "services": [],
        "risk_score": risk_score
    }
    
    # Extract service information
    for service in data.get('data', []):
        normalized["services"].append({
            "port": service.get('port'),
            "product": service.get('product'),
            "version": service.get('version'),
            "banner": service.get('data', '')[:100]
        })
    
    return {
        "source": "shodan",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": data,
        "normalized_data": normalized,
        "confidence": risk_score,
        "request_hash": hashlib.sha256(str(data).encode()).hexdigest()[:16],
        "response_hash": hashlib.sha256(str(normalized).encode()).hexdigest()[:16]
    }
