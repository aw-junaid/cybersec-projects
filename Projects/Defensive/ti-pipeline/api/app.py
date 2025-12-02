import os
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
import asyncpg
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Counter, Histogram, Gauge

from canonical_store.db import get_db
from canonical_store.models import IOC, EnrichmentRecord
from workers.enrich_worker import enqueue_enrichment_tasks

# Metrics
INGESTION_REQUESTS = Counter('ingestion_requests_total', 'Total ingestion requests')
ENRICHMENT_QUEUED = Counter('enrichment_tasks_queued', 'Enrichment tasks queued')
API_REQUESTS = Counter('api_requests_total', 'Total API requests', ['endpoint', 'method'])
REQUEST_DURATION = Histogram('request_duration_seconds', 'Request duration')
ACTIVE_IOCS = Gauge('active_iocs_total', 'Number of active IOCs')

app = FastAPI(
    title="Threat Intelligence Pipeline API",
    description="Production-grade IOC collection and enrichment platform",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication
security = HTTPBearer()
API_KEY = os.getenv("API_KEY", "test-key")

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    return credentials.credentials

# Pydantic Models
class IOCInput(BaseModel):
    value: str
    type: str
    source: str
    confidence: Optional[int] = Field(None, ge=0, le=100)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Optional[List[str]] = []
    description: Optional[str] = None

    @validator('type')
    def validate_type(cls, v):
        allowed_types = {'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'}
        if v not in allowed_types:
            raise ValueError(f'Type must be one of {allowed_types}')
        return v

class BatchIngestRequest(BaseModel):
    iocs: List[IOCInput]
    feed_name: str
    feed_version: Optional[str] = None

class SearchResponse(BaseModel):
    iocs: List[Dict[str, Any]]
    total: int
    page: int
    size: int

# Routes
@app.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_iocs(
    request: BatchIngestRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Ingest batch IOCs for enrichment
    """
    INGESTION_REQUESTS.inc()
    API_REQUESTS.labels(endpoint='/ingest', method='POST').inc()

    ioc_ids = []
    db = await get_db()
    
    try:
        for ioc_input in request.iocs:
            # Normalize IOC value
            normalized_value = normalize_ioc(ioc_input.value, ioc_input.type)
            
            # Check for existing IOC
            existing_ioc = await db.fetchrow(
                "SELECT id FROM iocs WHERE normalized_value = $1 AND type = $2",
                normalized_value, ioc_input.type
            )
            
            if existing_ioc:
                ioc_id = existing_ioc['id']
                # Update last_seen if newer
                await db.execute(
                    "UPDATE iocs SET last_seen = $1 WHERE id = $2",
                    ioc_input.last_seen or datetime.utcnow(), ioc_id
                )
            else:
                ioc_id = str(uuid.uuid4())
                await db.execute("""
                    INSERT INTO iocs (id, value, normalized_value, type, source, confidence, 
                                    first_seen, last_seen, tags, description, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                """, ioc_id, ioc_input.value, normalized_value, ioc_input.type, 
                   request.feed_name, ioc_input.confidence, ioc_input.first_seen or datetime.utcnow(),
                   ioc_input.last_seen or datetime.utcnow(), ioc_input.tags, 
                   ioc_input.description, datetime.utcnow())
            
            ioc_ids.append(ioc_id)
        
        # Queue enrichment tasks
        background_tasks.add_task(enqueue_enrichment_tasks, ioc_ids)
        ENRICHMENT_QUEUED.inc(len(ioc_ids))
        
        return {
            "message": f"Accepted {len(ioc_ids)} IOCs for processing",
            "ioc_ids": ioc_ids,
            "enrichment_queued": True
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")

@app.get("/ioc/{ioc_id}")
async def get_ioc(
    ioc_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Get IOC with enrichment timeline
    """
    API_REQUESTS.labels(endpoint='/ioc/{ioc_id}', method='GET').inc()
    
    db = await get_db()
    
    ioc = await db.fetchrow("""
        SELECT * FROM iocs WHERE id = $1
    """, ioc_id)
    
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    enrichments = await db.fetch("""
        SELECT * FROM enrichment_records 
        WHERE ioc_id = $1 
        ORDER BY created_at DESC
    """, ioc_id)
    
    return {
        "ioc": dict(ioc),
        "enrichments": [dict(enrich) for enrich in enrichments],
        "enrichment_count": len(enrichments)
    }

@app.get("/search")
async def search_iocs(
    q: str,
    type: Optional[str] = None,
    source: Optional[str] = None,
    page: int = 1,
    size: int = 50,
    api_key: str = Depends(verify_api_key)
):
    """
    Search IOCs with filters
    """
    API_REQUESTS.labels(endpoint='/search', method='GET').inc()
    
    db = await get_db()
    offset = (page - 1) * size
    
    query = "SELECT * FROM iocs WHERE normalized_value ILIKE $1"
    params = [f"%{q}%"]
    param_count = 1
    
    if type:
        param_count += 1
        query += f" AND type = ${param_count}"
        params.append(type)
    
    if source:
        param_count += 1
        query += f" AND source = ${param_count}"
        params.append(source)
    
    query += f" ORDER BY last_seen DESC LIMIT ${param_count + 1} OFFSET ${param_count + 2}"
    params.extend([size, offset])
    
    iocs = await db.fetch(query, *params)
    total = await db.fetchval(
        "SELECT COUNT(*) FROM iocs WHERE normalized_value ILIKE $1" + 
        (f" AND type = $2" if type else "") +
        (f" AND source = ${3 if type else 2}" if source else ""),
        *([f"%{q}%"] + ([type] if type else []) + ([source] if source else []))
    )
    
    return SearchResponse(
        iocs=[dict(ioc) for ioc in iocs],
        total=total,
        page=page,
        size=size
    )

@app.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint
    """
    return generate_latest()

@app.get("/stats")
async def get_stats(api_key: str = Depends(verify_api_key)):
    """
    Get pipeline statistics
    """
    API_REQUESTS.labels(endpoint='/stats', method='GET').inc()
    
    db = await get_db()
    
    stats = await db.fetchrow("""
        SELECT 
            COUNT(*) as total_iocs,
            COUNT(DISTINCT source) as unique_sources,
            AVG(confidence) as avg_confidence,
            MAX(last_seen) as latest_ioc
        FROM iocs
    """)
    
    enrichment_stats = await db.fetchrow("""
        SELECT 
            COUNT(*) as total_enrichments,
            COUNT(DISTINCT source) as unique_enrichment_sources
        FROM enrichment_records
    """)
    
    return {
        "ioc_statistics": dict(stats),
        "enrichment_statistics": dict(enrichment_stats)
    }

def normalize_ioc(value: str, ioc_type: str) -> str:
    """
    Normalize IOC values to canonical form
    """
    if ioc_type == 'domain':
        return value.lower().strip()
    elif ioc_type == 'ipv4':
        return value.strip()
    elif ioc_type in ['md5', 'sha1', 'sha256']:
        return value.lower().strip()
    elif ioc_type == 'url':
        # Basic URL normalization
        return value.lower().strip()
    else:
        return value.strip()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
