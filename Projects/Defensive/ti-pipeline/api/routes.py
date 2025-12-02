from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from datetime import datetime

from .app import verify_api_key
from canonical_store.db import get_db

router = APIRouter()

@router.post("/ioc/{ioc_id}/verdict")
async def add_verdict(
    ioc_id: str,
    verdict: str,
    confidence: int,
    analyst_notes: Optional[str] = None,
    api_key: str = Depends(verify_api_key)
):
    """
    Add analyst verdict to IOC
    """
    db = await get_db()
    
    if verdict not in ['malicious', 'suspicious', 'benign', 'false_positive']:
        raise HTTPException(status_code=400, detail="Invalid verdict")
    
    await db.execute("""
        UPDATE iocs 
        SET analyst_verdict = $1, analyst_confidence = $2, analyst_notes = $3,
            analyst_updated_at = $4
        WHERE id = $5
    """, verdict, confidence, analyst_notes, datetime.utcnow(), ioc_id)
    
    return {"message": "Verdict updated", "ioc_id": ioc_id}

@router.get("/exports/stix")
async def export_stix(
    since: Optional[datetime] = None,
    types: Optional[List[str]] = None,
    api_key: str = Depends(verify_api_key)
):
    """
    Export IOCs as STIX bundle
    """
    db = await get_db()
    
    query = "SELECT * FROM iocs WHERE 1=1"
    params = []
    
    if since:
        query += " AND last_seen >= $1"
        params.append(since)
    
    if types:
        placeholders = ",".join([f"${i+len(params)+1}" for i in range(len(types))])
        query += f" AND type IN ({placeholders})"
        params.extend(types)
    
    iocs = await db.fetch(query, *params)
    
    # Basic STIX 2.1 output
    stix_objects = []
    for ioc in iocs:
        stix_obj = {
            "type": "indicator",
            "id": f"indicator--{ioc['id']}",
            "created": ioc['created_at'].isoformat() + "Z",
            "modified": ioc['last_seen'].isoformat() + "Z",
            "pattern": f"[{get_stix_pattern(ioc['type'], ioc['value'])}]",
            "pattern_type": "stix",
            "valid_from": ioc['first_seen'].isoformat() + "Z",
            "labels": ["malicious-activity"]
        }
        stix_objects.append(stix_obj)
    
    bundle = {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "objects": stix_objects
    }
    
    return bundle

def get_stix_pattern(ioc_type: str, value: str) -> str:
    """
    Convert IOC to STIX pattern
    """
    patterns = {
        'ipv4': f"ipv4-addr:value = '{value}'",
        'domain': f"domain-name:value = '{value}'",
        'url': f"url:value = '{value}'",
        'md5': f"file:hashes.md5 = '{value}'",
        'sha1': f"file:hashes.sha1 = '{value}'",
        'sha256': f"file:hashes.sha256 = '{value}'"
    }
    return patterns.get(ioc_type, f"generic:value = '{value}'")
