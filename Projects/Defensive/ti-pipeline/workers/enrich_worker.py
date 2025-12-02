import os
import asyncio
import uuid
from datetime import datetime
from typing import List, Dict, Any
import aiohttp
import asyncpg
from prometheus_client import Counter, Histogram, Gauge

from cache.cache import get_cache, Cache
from canonical_store.db import get_db

# Metrics
ENRICHMENT_REQUESTS = Counter('enrichment_requests_total', 'Total enrichment requests', ['provider'])
ENRICHMENT_ERRORS = Counter('enrichment_errors_total', 'Enrichment errors', ['provider'])
ENRICHMENT_DURATION = Histogram('enrichment_duration_seconds', 'Enrichment duration', ['provider'])
CACHE_HITS = Counter('cache_hits_total', 'Cache hits', ['provider'])
ACTIVE_ENRICHMENTS = Gauge('active_enrichments', 'Active enrichment tasks')

# Rate limiting
RATE_LIMITS = {
    'virustotal': (4, 60),  # 4 requests per minute
    'shodan': (1, 1),       # 1 request per second
    'whois': (10, 60),      # 10 requests per minute
    'pdns': (5, 60),        # 5 requests per minute
    'urlscan': (10, 60),    # 10 requests per minute
}

class RateLimiter:
    def __init__(self):
        self.queues = {}
        self.locks = {}
    
    async def acquire(self, provider: str):
        if provider not in self.queues:
            self.queues[provider] = asyncio.Queue()
            self.locks[provider] = asyncio.Lock()
        
        await self.queues[provider].put(1)
        async with self.locks[provider]:
            max_requests, time_window = RATE_LIMITS.get(provider, (10, 60))
            if self.queues[provider].qsize() > max_requests:
                await asyncio.sleep(time_window)
            await self.queues[provider].get()

rate_limiter = RateLimiter()

async def enqueue_enrichment_tasks(ioc_ids: List[str]):
    """
    Enqueue IOCs for enrichment processing
    """
    db = await get_db()
    cache = await get_cache()
    
    for ioc_id in ioc_ids:
        ioc = await db.fetchrow("SELECT * FROM iocs WHERE id = $1", ioc_id)
        if not ioc:
            continue
            
        # Determine which enrichments to run based on IOC type
        enrichment_tasks = get_enrichment_tasks_for_type(ioc['type'])
        
        # Run enrichments in parallel with rate limiting
        tasks = []
        for provider in enrichment_tasks:
            task = asyncio.create_task(
                enrich_ioc(ioc, provider, cache, db)
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)

def get_enrichment_tasks_for_type(ioc_type: str) -> List[str]:
    """
    Get appropriate enrichment providers for IOC type
    """
    base_providers = ['whois', 'pdns']
    
    type_specific = {
        'ipv4': ['virustotal', 'shodan', 'urlscan'],
        'ipv6': ['virustotal', 'shodan'],
        'domain': ['virustotal', 'urlscan'],
        'url': ['virustotal', 'urlscan'],
        'md5': ['virustotal'],
        'sha1': ['virustotal'],
        'sha256': ['virustotal'],
    }
    
    return base_providers + type_specific.get(ioc_type, [])

async def enrich_ioc(ioc: Dict, provider: str, cache: Cache, db: asyncpg.Connection):
    """
    Enrich a single IOC with a specific provider
    """
    ACTIVE_ENRICHMENTS.inc()
    ENRICHMENT_REQUESTS.labels(provider=provider).inc()
    
    cache_key = f"enrich:{provider}:{ioc['normalized_value']}"
    
    try:
        # Check cache first
        cached_result = await cache.get(cache_key)
        if cached_result:
            CACHE_HITS.labels(provider=provider).inc()
            await save_enrichment_result(
                ioc['id'], provider, cached_result, db, from_cache=True
            )
            return cached_result
        
        # Apply rate limiting
        await rate_limiter.acquire(provider)
        
        # Run enrichment
        start_time = datetime.utcnow()
        
        enrichment_module = get_enrichment_module(provider)
        result = await enrichment_module.enrich(ioc['value'], ioc['type'])
        
        ENRICHMENT_DURATION.labels(provider=provider).observe(
            (datetime.utcnow() - start_time).total_seconds()
        )
        
        if result:
            # Cache result
            await cache.set(cache_key, result, ttl_hours=24)
            
            # Save to database
            await save_enrichment_result(ioc['id'], provider, result, db)
            
            return result
            
    except Exception as e:
        ENRICHMENT_ERRORS.labels(provider=provider).inc()
        print(f"Enrichment error for {provider} on {ioc['value']}: {str(e)}")
    finally:
        ACTIVE_ENRICHMENTS.dec()

async def save_enrichment_result(
    ioc_id: str, 
    provider: str, 
    result: Dict[str, Any], 
    db: asyncpg.Connection,
    from_cache: bool = False
):
    """
    Save enrichment result to database
    """
    enrichment_id = str(uuid.uuid4())
    
    await db.execute("""
        INSERT INTO enrichment_records 
        (id, ioc_id, source, data, normalized_data, confidence, timestamp, ttl_hours)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    """, enrichment_id, ioc_id, provider, result.get('raw_data', {}),
       result.get('normalized_data', {}), result.get('confidence'),
       datetime.utcnow(), 24)
    
    # Log audit entry
    await db.execute("""
        INSERT INTO audit_log (action, provider, request_hash, response_hash, metadata)
        VALUES ($1, $2, $3, $4, $5)
    """, "enrichment", provider, result.get('request_hash', ''),
       result.get('response_hash', ''), {"from_cache": from_cache})

def get_enrichment_module(provider: str):
    """
    Dynamically import enrichment module
    """
    module_map = {
        'virustotal': 'workers.tasks.vt_enrich',
        'shodan': 'workers.tasks.shodan_enrich',
        'whois': 'workers.tasks.whois_enrich',
        'pdns': 'workers.tasks.pdns_enrich',
        'urlscan': 'workers.tasks.urlscan_enrich',
    }
    
    module_name = module_map.get(provider)
    if not module_name:
        raise ValueError(f"Unknown provider: {provider}")
    
    # Dynamic import
    module = __import__(module_name, fromlist=['enrich'])
    return module
