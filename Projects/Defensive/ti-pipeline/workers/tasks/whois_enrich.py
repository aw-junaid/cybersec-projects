import os
import hashlib
import aiohttp
from datetime import datetime
from typing import Dict, Any

MOCK_ENRICH = os.getenv("MOCK_ENRICH", "true").lower() == "true"
ENABLE_REAL_ENRICH = os.getenv("ENABLE_REAL_ENRICH", "false").lower() == "true"
WHOIS_API_KEY = os.getenv("WHOISXML_API_KEY")

async def enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Enrich with WHOIS data
    """
    if ioc_type not in ['domain', 'ipv4']:
        return None
        
    if MOCK_ENRICH or not ENABLE_REAL_ENRICH or not WHOIS_API_KEY:
        return await mock_enrich(value, ioc_type)
    
    return await real_enrich(value, ioc_type)

async def real_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Real WHOIS API call
    """
    if ioc_type == 'domain':
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    else:
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    
    params = {
        "apiKey": WHOIS_API_KEY,
        "domainName" if ioc_type == 'domain' else "ip": value,
        "outputFormat": "JSON"
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return normalize_whois_response(data, ioc_type)
            else:
                raise Exception(f"WHOIS API error: {response.status}")

async def mock_enrich(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Mock WHOIS response
    """
    import asyncio
    await asyncio.sleep(0.05)
    
    if ioc_type == 'domain':
        data = {
            "WhoisRecord": {
                "domainName": value,
                "registryData": {
                    "createdDate": "2020-01-01T00:00:00Z",
                    "updatedDate": "2023-01-01T00:00:00Z",
                    "expiresDate": "2024-01-01T00:00:00Z",
                    "registrant": {
                        "organization": "Mock Organization Inc.",
                        "country": "US",
                        "state": "CA"
                    },
                    "registrar": {
                        "name": "Mock Registrar LLC"
                    }
                }
            }
        }
    else:
        data = {
            "WhoisRecord": {
                "registryData": {
                    "netRange": "1.2.3.0 - 1.2.3.255",
                    "orgName": "Mock Internet Provider",
                    "country": "US",
                    "createdDate": "2020-01-01T00:00:00Z"
                }
            }
        }
    
    return normalize_whois_response(data, ioc_type)

def normalize_whois_response(data: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
    """
    Normalize WHOIS response
    """
    registry_data = data.get('WhoisRecord', {}).get('registryData', {})
    
    normalized = {
        "created_date": registry_data.get('createdDate'),
        "updated_date": registry_data.get('updatedDate'),
        "expires_date": registry_data.get('expiresDate'),
    }
    
    if ioc_type == 'domain':
        normalized.update({
            "registrant_organization": registry_data.get('registrant', {}).get('organization'),
            "registrant_country": registry_data.get('registrant', {}).get('country'),
            "registrar": registry_data.get('registrar', {}).get('name'),
            "domain_name": data.get('WhoisRecord', {}).get('domainName')
        })
    else:
        normalized.update({
            "network_range": registry_data.get('netRange'),
            "organization": registry_data.get('orgName'),
            "country": registry_data.get('country')
        })
    
    # Calculate domain age confidence
    confidence = calculate_whois_confidence(normalized)
    
    return {
        "source": "whois",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": data,
        "normalized_data": normalized,
        "confidence": confidence,
        "request_hash": hashlib.sha256(str(data).encode()).hexdigest()[:16],
        "response_hash": hashlib.sha256(str(normalized).encode()).hexdigest()[:16]
    }

def calculate_whois_confidence(whois_data: Dict[str, Any]) -> int:
    """
    Calculate confidence based on WHOIS data
    """
    confidence = 50  # Base confidence
    
    # New domains are more suspicious
    created_date = whois_data.get('created_date')
    if created_date:
        from datetime import datetime, timezone
        try:
            created = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 30:
                confidence += 30
            elif age_days > 365:
                confidence -= 10
        except:
            pass
    
    # Privacy protection services reduce confidence
    org = whois_data.get('registrant_organization') or whois_data.get('organization')
    if org and any(privacy in org.lower() for privacy in ['privacy', 'proxy', 'redacted']):
        confidence += 20
    
    return min(100, confidence)
