import os
import hashlib
import aiohttp
from datetime import datetime
from typing import Dict, Any

MOCK_ENRICH = os.getenv("MOCK_ENRICH", "true").lower() == "true"
ENABLE_REAL_ENRICH = os.getenv("ENABLE_REAL_ENRICH", "false").lower() == "true"
VT_API_KEY = os.getenv("VT_API_KEY")

async def enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Enrich IOC with VirusTotal
    """
    if MOCK_ENRICH or not ENABLE_REAL_ENRICH or not VT_API_KEY:
        return await mock_enrich(value, ioc_type)
    
    return await real_enrich(value, ioc_type)

async def real_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Real VirusTotal API call
    """
    url = get_vt_url(value, ioc_type)
    headers = {"x-apikey": VT_API_KEY}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return normalize_vt_response(data, ioc_type)
            elif response.status == 429:
                raise Exception("VirusTotal rate limit exceeded")
            else:
                raise Exception(f"VirusTotal API error: {response.status}")

async def mock_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Mock VirusTotal response
    """
    # Simulate API delay
    import asyncio
    await asyncio.sleep(0.1)
    
    request_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
    
    if ioc_type in ['ipv4', 'ipv6']:
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 45,
                        "harmless": 12
                    },
                    "country": "US",
                    "as_owner": "Mock AS Owner",
                    "reputation": -5,
                    "last_modification_date": int(datetime.utcnow().timestamp())
                }
            }
        }
    elif ioc_type == 'domain':
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 1,
                        "undetected": 40,
                        "harmless": 15
                    },
                    "last_dns_records": [
                        {"type": "A", "value": "1.2.3.4"},
                        {"type": "NS", "value": "ns1.mock.com"}
                    ],
                    "creation_date": 1609459200,
                    "last_modification_date": int(datetime.utcnow().timestamp())
                }
            }
        }
    elif ioc_type in ['md5', 'sha1', 'sha256']:
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 3,
                        "undetected": 10,
                        "harmless": 2
                    },
                    "meaningful_name": "malware.exe",
                    "type_description": "Win32 Trojan",
                    "size": 1024000,
                    "last_modification_date": int(datetime.utcnow().timestamp())
                }
            }
        }
    else:
        data = {"data": {"attributes": {}}}
    
    return normalize_vt_response(data, ioc_type)

def get_vt_url(value: str, ioc_type: str) -> str:
    """
    Get appropriate VirusTotal API URL
    """
    base_url = "https://www.virustotal.com/api/v3"
    
    endpoints = {
        'ipv4': f"/ip_addresses/{value}",
        'ipv6': f"/ip_addresses/{value}",
        'domain': f"/domains/{value}",
        'url': f"/urls/{hashlib.sha256(value.encode()).hexdigest()}",
        'md5': f"/files/{value}",
        'sha1': f"/files/{value}",
        'sha256': f"/files/{value}",
    }
    
    return base_url + endpoints.get(ioc_type, "")

def normalize_vt_response(data: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
    """
    Normalize VirusTotal response
    """
    attributes = data.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    total = sum(stats.values())
    
    confidence = 0
    if total > 0:
        confidence = min(100, int((malicious + suspicious * 0.5) / total * 100))
    
    normalized = {
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total,
        "reputation": attributes.get('reputation', 0),
        "confidence": confidence
    }
    
    if ioc_type in ['ipv4', 'ipv6']:
        normalized.update({
            "country": attributes.get('country'),
            "asn": attributes.get('asn'),
            "as_owner": attributes.get('as_owner')
        })
    elif ioc_type == 'domain':
        normalized.update({
            "creation_date": attributes.get('creation_date'),
            "dns_records": attributes.get('last_dns_records', [])
        })
    elif ioc_type in ['md5', 'sha1', 'sha256']:
        normalized.update({
            "file_type": attributes.get('type_description'),
            "file_size": attributes.get('size'),
            "file_name": attributes.get('meaningful_name')
        })
    
    return {
        "source": "virustotal",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": data,
        "normalized_data": normalized,
        "confidence": confidence,
        "request_hash": hashlib.sha256(str(data).encode()).hexdigest()[:16],
        "response_hash": hashlib.sha256(str(normalized).encode()).hexdigest()[:16]
    }
