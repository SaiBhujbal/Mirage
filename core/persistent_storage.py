"""
MIRAGE Persistent Session Storage
Redis backend for session persistence across restarts

Addresses: "In-Memory Session Storage" vulnerability
- Sessions persist across WAF restarts
- Attacker cannot reset reputation by forcing restart
- High-availability support with Redis Cluster
"""
import time
import json
import logging
from typing import Dict, Optional, List, Set
from dataclasses import dataclass, field, asdict
from abc import ABC, abstractmethod
import threading

logger = logging.getLogger("mirage.storage")


class SessionStorageBackend(ABC):
    """Abstract session storage backend"""
    
    @abstractmethod
    def get(self, session_id: str) -> Optional[Dict]:
        pass
    
    @abstractmethod
    def set(self, session_id: str, data: Dict, ttl: int = 86400):
        pass
    
    @abstractmethod
    def delete(self, session_id: str):
        pass
    
    @abstractmethod
    def exists(self, session_id: str) -> bool:
        pass
    
    @abstractmethod
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        pass

    @abstractmethod
    def mget(self, keys: List[str]) -> List[Optional[Dict]]:
        pass


class InMemoryStorage(SessionStorageBackend):
    """
    In-memory storage (default, not persistent)
    Use for development/testing only
    """
    
    def __init__(self):
        self.data: Dict[str, Dict] = {}
        self.expiry: Dict[str, float] = {}
        self.lock = threading.Lock()
    
    def get(self, session_id: str) -> Optional[Dict]:
        with self.lock:
            # Check expiry
            if session_id in self.expiry:
                if time.time() > self.expiry[session_id]:
                    del self.data[session_id]
                    del self.expiry[session_id]
                    return None
            
            return self.data.get(session_id)
    
    def set(self, session_id: str, data: Dict, ttl: int = 86400):
        with self.lock:
            self.data[session_id] = data
            if ttl > 0:
                self.expiry[session_id] = time.time() + ttl
            else:
                self.expiry.pop(session_id, None)
    
    def delete(self, session_id: str):
        with self.lock:
            self.data.pop(session_id, None)
            self.expiry.pop(session_id, None)
    
    def exists(self, session_id: str) -> bool:
        return self.get(session_id) is not None
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        with self.lock:
            if pattern == "*":
                return list(self.data.keys())
            
            import fnmatch
            return [k for k in self.data.keys() if fnmatch.fnmatch(k, pattern)]

    def mget(self, keys: List[str]) -> List[Optional[Dict]]:
        with self.lock:
            results = []
            for session_id in keys:
                # Check expiry
                if session_id in self.expiry:
                    if time.time() > self.expiry[session_id]:
                        del self.data[session_id]
                        del self.expiry[session_id]
                        results.append(None)
                        continue

                results.append(self.data.get(session_id))
            return results


class RedisStorage(SessionStorageBackend):
    """
    Redis storage backend for production
    
    Features:
    - Persistence across restarts
    - High availability with Redis Cluster
    - Automatic TTL management
    - Atomic operations
    """
    
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 6379,
                 db: int = 0,
                 password: str = None,
                 prefix: str = "mirage:session:",
                 cluster_mode: bool = False,
                 sentinel_hosts: List[tuple] = None,
                 sentinel_master: str = None):
        
        self.prefix = prefix
        self.cluster_mode = cluster_mode
        self.redis = None
        
        try:
            import redis
            
            if sentinel_hosts and sentinel_master:
                # Redis Sentinel for HA
                from redis.sentinel import Sentinel
                sentinel = Sentinel(sentinel_hosts, socket_timeout=0.5)
                self.redis = sentinel.master_for(sentinel_master, socket_timeout=0.5)
                logger.info(f"Connected to Redis Sentinel: {sentinel_master}")
                
            elif cluster_mode:
                # Redis Cluster
                from redis.cluster import RedisCluster
                self.redis = RedisCluster(host=host, port=port, password=password)
                logger.info(f"Connected to Redis Cluster: {host}:{port}")
                
            else:
                # Standalone Redis
                self.redis = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    password=password,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5,
                )
                # Test connection
                self.redis.ping()
                logger.info(f"Connected to Redis: {host}:{port}/{db}")
                
        except ImportError:
            logger.error("redis package not installed. Run: pip install redis")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def _key(self, session_id: str) -> str:
        """Generate Redis key with prefix"""
        return f"{self.prefix}{session_id}"
    
    def get(self, session_id: str) -> Optional[Dict]:
        try:
            data = self.redis.get(self._key(session_id))
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error(f"Redis GET error: {e}")
            return None
    
    def set(self, session_id: str, data: Dict, ttl: int = 86400):
        try:
            # Convert sets to lists for JSON serialization
            serializable = self._make_serializable(data)
            self.redis.setex(
                self._key(session_id),
                ttl,
                json.dumps(serializable)
            )
        except Exception as e:
            logger.error(f"Redis SET error: {e}")
    
    def delete(self, session_id: str):
        try:
            self.redis.delete(self._key(session_id))
        except Exception as e:
            logger.error(f"Redis DELETE error: {e}")
    
    def exists(self, session_id: str) -> bool:
        try:
            return self.redis.exists(self._key(session_id)) > 0
        except Exception as e:
            logger.error(f"Redis EXISTS error: {e}")
            return False
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        try:
            full_pattern = f"{self.prefix}{pattern}"
            keys = self.redis.keys(full_pattern)
            # Remove prefix from keys
            return [k.replace(self.prefix, "") for k in keys]
        except Exception as e:
            logger.error(f"Redis KEYS error: {e}")
            return []
    
    def mget(self, keys: List[str]) -> List[Optional[Dict]]:
        if not keys:
            return []
        try:
            prefixed_keys = [self._key(k) for k in keys]
            raw_data = self.redis.mget(prefixed_keys)

            results = []
            for item in raw_data:
                if item:
                    results.append(json.loads(item))
                else:
                    results.append(None)
            return results
        except Exception as e:
            logger.error(f"Redis MGET error: {e}")
            return [None] * len(keys)

    def _make_serializable(self, data: Dict) -> Dict:
        """Convert non-JSON-serializable types"""
        result = {}
        for key, value in data.items():
            if isinstance(value, set):
                result[key] = list(value)
            elif isinstance(value, dict):
                result[key] = self._make_serializable(value)
            else:
                result[key] = value
        return result
    
    # Additional Redis-specific operations
    
    def increment_field(self, session_id: str, field: str, amount: int = 1) -> int:
        """Atomically increment a field"""
        try:
            # Use hash for complex objects
            return self.redis.hincrby(f"{self.prefix}hash:{session_id}", field, amount)
        except Exception as e:
            logger.error(f"Redis HINCRBY error: {e}")
            return 0
    
    def add_to_set(self, session_id: str, field: str, value: str):
        """Add value to a set field"""
        try:
            self.redis.sadd(f"{self.prefix}set:{session_id}:{field}", value)
        except Exception as e:
            logger.error(f"Redis SADD error: {e}")
    
    def get_set(self, session_id: str, field: str) -> Set[str]:
        """Get all values from a set field"""
        try:
            return self.redis.smembers(f"{self.prefix}set:{session_id}:{field}")
        except Exception as e:
            logger.error(f"Redis SMEMBERS error: {e}")
            return set()


class ReputationStorage:
    """
    Persistent reputation storage
    
    Stores IP reputation scores that survive restarts
    """
    
    def __init__(self, backend: SessionStorageBackend):
        self.backend = backend
        self.prefix = "reputation:"
    
    def get_reputation(self, ip: str) -> float:
        """Get reputation score for IP (0-1, lower = worse)"""
        data = self.backend.get(f"{self.prefix}{ip}")
        if data:
            return data.get("score", 1.0)
        return 1.0
    
    def update_reputation(self, ip: str, score: float, reason: str):
        """Update reputation score"""
        data = self.backend.get(f"{self.prefix}{ip}") or {
            "score": 1.0,
            "history": [],
            "first_seen": time.time(),
        }
        
        data["score"] = max(0.0, min(1.0, score))
        data["last_updated"] = time.time()
        data["history"].append({
            "timestamp": time.time(),
            "score": score,
            "reason": reason,
        })
        
        # Keep last 100 history entries
        data["history"] = data["history"][-100:]
        
        # TTL of 7 days for reputation data
        self.backend.set(f"{self.prefix}{ip}", data, ttl=604800)
    
    def record_attack(self, ip: str, category: str, severity: float):
        """Record attack and decrease reputation"""
        current = self.get_reputation(ip)
        new_score = current * (1 - severity * 0.2)
        self.update_reputation(ip, new_score, f"Attack: {category}")
    
    def record_legitimate(self, ip: str):
        """Record legitimate request and slowly increase reputation"""
        current = self.get_reputation(ip)
        if current < 1.0:
            new_score = min(1.0, current + 0.01)
            self.update_reputation(ip, new_score, "Legitimate request")
    
    def get_all_bad_actors(self, threshold: float = 0.5) -> List[Dict]:
        """Get all IPs with reputation below threshold"""
        bad_actors = []
        keys = self.backend.get_all_keys(f"{self.prefix}*")
        
        all_data = self.backend.mget(keys)
        for key, data in zip(keys, all_data):
            if data and data.get("score", 1.0) < threshold:
                ip = key.replace(self.prefix, "")
                bad_actors.append({
                    "ip": ip,
                    "score": data["score"],
                    "first_seen": data.get("first_seen"),
                    "last_updated": data.get("last_updated"),
                })
        
        return sorted(bad_actors, key=lambda x: x["score"])


class RuleStorage:
    """
    Persistent storage for auto-generated rules
    
    Ensures rules survive WAF restarts
    """
    
    def __init__(self, backend: SessionStorageBackend):
        self.backend = backend
        self.prefix = "rule:"
    
    def save_rule(self, rule_id: str, rule_data: Dict):
        """Save rule to persistent storage"""
        rule_data["saved_at"] = time.time()
        self.backend.set(f"{self.prefix}{rule_id}", rule_data, ttl=0)  # No expiry
    
    def get_rule(self, rule_id: str) -> Optional[Dict]:
        """Get rule by ID"""
        return self.backend.get(f"{self.prefix}{rule_id}")
    
    def get_all_rules(self) -> List[Dict]:
        """Get all saved rules"""
        keys = self.backend.get_all_keys(f"{self.prefix}*")
        all_rules = self.backend.mget(keys)
        return [r for r in all_rules if r]
    
    def delete_rule(self, rule_id: str):
        """Delete a rule"""
        self.backend.delete(f"{self.prefix}{rule_id}")


# ============================================================================
# STORAGE FACTORY
# ============================================================================

def create_storage(config: Dict = None) -> SessionStorageBackend:
    """
    Create storage backend based on configuration
    
    Config options:
    - type: "memory" | "redis"
    - redis_host: str
    - redis_port: int
    - redis_password: str
    - redis_db: int
    - redis_cluster: bool
    - redis_sentinel_hosts: List[tuple]
    - redis_sentinel_master: str
    """
    config = config or {}
    storage_type = config.get("type", "memory")
    
    if storage_type == "redis":
        return RedisStorage(
            host=config.get("redis_host", "localhost"),
            port=config.get("redis_port", 6379),
            db=config.get("redis_db", 0),
            password=config.get("redis_password"),
            cluster_mode=config.get("redis_cluster", False),
            sentinel_hosts=config.get("redis_sentinel_hosts"),
            sentinel_master=config.get("redis_sentinel_master"),
        )
    else:
        logger.warning("Using in-memory storage. Sessions will not persist across restarts!")
        return InMemoryStorage()


# Default storage (can be overridden in settings)
_storage_backend = None

def get_storage() -> SessionStorageBackend:
    """Get the configured storage backend"""
    global _storage_backend
    if _storage_backend is None:
        _storage_backend = InMemoryStorage()
    return _storage_backend

def set_storage(backend: SessionStorageBackend):
    """Set the storage backend"""
    global _storage_backend
    _storage_backend = backend
