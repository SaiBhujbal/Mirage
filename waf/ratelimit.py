"""
Rate limiting with an optional SHARED (Redis) backend.

THE BUG THIS FIXES: the in-memory limiter counts per PROCESS. Run 4 gunicorn workers
behind a load balancer across 3 pods and one attacker gets 12x the intended budget,
because each worker keeps its own window. A rate limit that scales with your replica
count is not a rate limit.

Design:
  - RedisRateLimiter  : one shared sliding window per IP across every worker/pod.
                        Implemented as a single atomic Lua script (no read-then-write
                        race between workers) over a sorted set of request timestamps.
  - MemoryRateLimiter : the original per-process limiter; correct for single-instance.
  - build_rate_limiter(): picks Redis when REDIS_URL is set and reachable, else memory.

FAIL-OPEN vs FAIL-CLOSED: if Redis goes down mid-flight we fall back to the local
in-memory window rather than rejecting all traffic. A rate limiter outage must not become
an outage of the site it protects — the other WAF layers still enforce. This is a
deliberate availability choice and is logged loudly.
"""
from __future__ import annotations
import os, time, threading, logging
from collections import defaultdict, deque
from typing import Optional, Protocol

log = logging.getLogger("waf.ratelimit")


class RateLimiter(Protocol):
    def allow(self, ip: str) -> bool: ...


class MemoryRateLimiter:
    """Per-process sliding window. Correct only for a single instance."""
    backend = "memory"

    def __init__(self, capacity: int = 120, window_s: float = 10.0):
        self.capacity, self.window = capacity, window_s
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            dq = self.hits[ip]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.capacity:
                return False
            dq.append(now)
            return True


# Atomic sliding-window in one round trip. Returns 1 (allow) or 0 (deny).
# Must be atomic: two workers doing GET-then-SET would both see "under limit" and both
# admit, letting an attacker exceed the cap by the number of concurrent workers.
_LUA = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cap    = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local used = redis.call('ZCARD', key)
if used >= cap then
  redis.call('EXPIRE', key, math.ceil(window))
  return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window))
return 1
"""


class RedisRateLimiter:
    """Shared sliding window across every worker and pod."""
    backend = "redis"

    def __init__(self, url: str, capacity: int = 120, window_s: float = 10.0,
                 prefix: str = "waf:rl:", socket_timeout: float = 0.15):
        import redis  # imported lazily so redis is an optional dependency
        self.capacity, self.window, self.prefix = capacity, window_s, prefix
        # Short timeouts: the limiter sits in the hot path. A slow Redis must degrade,
        # never add 100s of ms to every request.
        self.r = redis.Redis.from_url(url, socket_timeout=socket_timeout,
                                      socket_connect_timeout=socket_timeout,
                                      health_check_interval=30, decode_responses=True)
        self.r.ping()
        self._script = self.r.register_script(_LUA)
        self._fallback = MemoryRateLimiter(capacity, window_s)
        self._degraded = False
        self._counter = 0
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            self._counter += 1
            member = f"{now:.6f}-{self._counter}"   # unique member per request
        try:
            ok = self._script(keys=[self.prefix + ip],
                              args=[now, self.window, self.capacity, member])
            if self._degraded:
                log.warning("rate limiter: Redis recovered, resuming shared window")
                self._degraded = False
            return bool(ok)
        except Exception as e:
            if not self._degraded:
                log.error("rate limiter: Redis unavailable (%s) — FAILING OPEN to "
                          "per-process window; limits are now per-worker", e)
                self._degraded = True
            return self._fallback.allow(ip)


def build_rate_limiter(capacity: int = 120, window_s: float = 10.0,
                       url: Optional[str] = None) -> RateLimiter:
    """Redis when REDIS_URL is set and reachable; otherwise per-process memory."""
    url = url if url is not None else os.environ.get("REDIS_URL", "")
    if url:
        try:
            rl = RedisRateLimiter(url, capacity, window_s)
            log.info("rate limiter: shared Redis window (%s req / %ss)", capacity, window_s)
            return rl
        except Exception as e:
            log.error("rate limiter: REDIS_URL set but unusable (%s) — falling back to "
                      "per-process memory. Limits will NOT be shared across replicas.", e)
    return MemoryRateLimiter(capacity, window_s)
