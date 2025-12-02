import os
import json
from typing import Any, Optional, Dict
import redis.asyncio as redis
from datetime import timedelta

class Cache:
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.client: Optional[redis.Redis] = None
        self.default_ttl = int(os.getenv("CACHE_TTL_HOURS", "24")) * 3600
    
    async def connect(self):
        """Connect to Redis"""
        if not self.client:
            self.client = redis.from_url(self.redis_url, decode_responses=True)
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.client:
            await self.client.close()
            self.client = None
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        await self.connect()
        try:
            value = await self.client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            print(f"Cache get error: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl_hours: int = None) -> bool:
        """Set value in cache with TTL"""
        await self.connect()
        try:
            ttl = ttl_hours * 3600 if ttl_hours else self.default_ttl
            serialized = json.dumps(value)
            await self.client.setex(key, timedelta(seconds=ttl), serialized)
            return True
        except Exception as e:
            print(f"Cache set error: {e}")
            return False
    
    async def get_many(self, keys: list) -> Dict[str, Any]:
        """Get multiple values from cache"""
        await self.connect()
        try:
            values = await self.client.mget(keys)
            result = {}
            for key, value in zip(keys, values):
                if value:
                    result[key] = json.loads(value)
            return result
        except Exception as e:
            print(f"Cache get_many error: {e}")
            return {}
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        await self.connect()
        try:
            await self.client.delete(key)
            return True
        except Exception as e:
            print(f"Cache delete error: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        await self.connect()
        try:
            return await self.client.exists(key) > 0
        except Exception as e:
            print(f"Cache exists error: {e}")
            return False
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        await self.connect()
        try:
            info = await self.client.info()
            return {
                "connected_clients": info.get('connected_clients', 0),
                "used_memory": info.get('used_memory', 0),
                "keyspace_hits": info.get('keyspace_hits', 0),
                "keyspace_misses": info.get('keyspace_misses', 0),
                "hit_ratio": self._calculate_hit_ratio(info),
                "db_size": info.get('db0', {}).get('keys', 0)
            }
        except Exception as e:
            print(f"Cache stats error: {e}")
            return {}
    
    def _calculate_hit_ratio(self, info: Dict) -> float:
        """Calculate cache hit ratio"""
        hits = info.get('keyspace_hits', 0)
        misses = info.get('keyspace_misses', 0)
        total = hits + misses
        return hits / total if total > 0 else 0.0

# Global cache instance
_cache: Optional[Cache] = None

async def get_cache() -> Cache:
    """Get global cache instance"""
    global _cache
    if _cache is None:
        _cache = Cache()
        await _cache.connect()
    return _cache

async def close_cache():
    """Close global cache connection"""
    global _cache
    if _cache:
        await _cache.disconnect()
        _cache = None
