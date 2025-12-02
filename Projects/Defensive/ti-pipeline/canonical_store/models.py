from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Any

@dataclass
class IOC:
    id: str
    value: str
    normalized_value: str
    type: str  # ipv4, ipv6, domain, url, md5, sha1, sha256, email
    source: str
    confidence: Optional[int]
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    description: Optional[str]
    analyst_verdict: Optional[str]  # malicious, suspicious, benign, false_positive
    analyst_confidence: Optional[int]
    analyst_notes: Optional[str]
    analyst_updated_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

@dataclass
class EnrichmentRecord:
    id: str
    ioc_id: str
    source: str  # virustotal, shodan, whois, etc.
    data: Dict[str, Any]  # Raw enrichment data
    normalized_data: Dict[str, Any]  # Normalized fields
    confidence: Optional[int]
    timestamp: datetime
    ttl_hours: int
    created_at: datetime

@dataclass
class Feed:
    id: str
    name: str
    version: str
    description: Optional[str]
    last_ingestion: Optional[datetime]
    enabled: bool
    created_at: datetime
